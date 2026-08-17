"""Crash-recoverable reference package lifecycle over signed staged artifacts."""

from __future__ import annotations

import hashlib
import re
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from packaging.version import Version
from pydantic import BaseModel, ConfigDict

from plaik_contracts import PackageManifest, PackageType

from .dependencies import (
    DependencyResolutionError,
    resolve_capabilities,
    resolve_install_order,
    version_matches,
)
from .operation_journal import OperationJournal, OperationStatus
from .package_artifacts import (
    INTEGRITY_MARKER_FILENAME,
    PackageArtifactVerifier,
    VerifiedPackageArtifact,
)
from .packages import PackageRecord, PackageStatus, RESERVED_PACKAGE_IDS
from .storage import exclusive_file_lock, read_json, write_json_atomic


_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class TransactionalPackageError(RuntimeError):
    """A package lifecycle transaction was rejected or could not be recovered."""


class TransactionPhase(StrEnum):
    PREPARED = "prepared"
    FILES_APPLIED = "files_applied"
    REGISTRY_APPLIED = "registry_applied"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"


PackageAction = Literal["install", "update", "enable", "disable", "uninstall"]
FailureInjector = Callable[[str], None]
SignerTransitionAuthorizer = Callable[[str, PackageType, str, str], bool]
PackageStageValidator = Callable[[Path, PackageManifest, Mapping[str, PackageRecord]], None]
PackageMigrationApplier = Callable[[Path, PackageManifest], None]
PackageStateValidator = Callable[
    [Literal["enable", "disable", "uninstall"], str, PackageRecord, Mapping[str, PackageRecord]],
    None,
]


class _TransactionIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    operation_id: str
    action: PackageAction
    package_id: str
    phase: TransactionPhase
    registry_before: dict[str, PackageRecord]
    registry_after: dict[str, PackageRecord]
    artifact_sha256: str | None = None
    signature_key_id: str | None = None
    stage_name: str | None = None
    backup_name: str | None = None


@dataclass(frozen=True, slots=True)
class PackageLifecycleResult:
    operation_id: str
    action: PackageAction
    package_id: str
    version: str | None
    status: PackageStatus | None
    idempotent_replay: bool = False


class TransactionalPackageManager:
    """Serialize lifecycle changes and recover incomplete filesystem/registry swaps.

    This reference coordinator is the sole supported writer for its registry and
    package root. It combines atomic directory renames, atomic registry replace,
    a durable transaction intent, and ``OperationJournal`` idempotency. A crash
    before the committed intent rolls back; a crash after it completes forward.
    """

    def __init__(
        self,
        *,
        registry_path: Path,
        packages_root: Path,
        transaction_root: Path,
        core_version: str,
        artifact_verifier: PackageArtifactVerifier,
        operation_journal: OperationJournal,
        protected_ids: set[str] | None = None,
        failure_injector: FailureInjector | None = None,
        signer_transition_authorizer: SignerTransitionAuthorizer | None = None,
        stage_validator: PackageStageValidator | None = None,
        migration_applier: PackageMigrationApplier | None = None,
        state_validator: PackageStateValidator | None = None,
        lock_target: Path | None = None,
    ) -> None:
        self.registry_path = Path(registry_path)
        self.packages_root = Path(packages_root)
        self.transaction_root = Path(transaction_root)
        self.intent_root = self.transaction_root / "intents"
        self.stage_root = self.transaction_root / "staging"
        self.backup_root = self.transaction_root / "backups"
        self.lock_target = Path(lock_target) if lock_target else self.transaction_root / "lifecycle"
        self.core_version = core_version
        self.artifact_verifier = artifact_verifier
        self.operation_journal = operation_journal
        self.protected_ids = frozenset({"default", *(protected_ids or set())})
        self.failure_injector = failure_injector
        self.signer_transition_authorizer = signer_transition_authorizer
        self.stage_validator = stage_validator
        self.migration_applier = migration_applier
        self.state_validator = state_validator

    def install(
        self,
        operation_id: str,
        artifact_path: Path,
        signature_path: Path,
    ) -> PackageLifecycleResult:
        artifact = self.artifact_verifier.verify(artifact_path, signature_path)
        return self._install_or_update(operation_id, artifact, action="install")

    def update(
        self,
        operation_id: str,
        artifact_path: Path,
        signature_path: Path,
    ) -> PackageLifecycleResult:
        artifact = self.artifact_verifier.verify(artifact_path, signature_path)
        return self._install_or_update(operation_id, artifact, action="update")

    def enable(self, operation_id: str, package_id: str) -> PackageLifecycleResult:
        return self._state_change(operation_id, package_id, action="enable")

    def disable(self, operation_id: str, package_id: str) -> PackageLifecycleResult:
        return self._state_change(operation_id, package_id, action="disable")

    def uninstall(self, operation_id: str, package_id: str) -> PackageLifecycleResult:
        operation_id = _validate_operation_id(operation_id)
        package_id = _validate_package_id(package_id)
        target = f"package/{package_id}"
        with exclusive_file_lock(self.lock_target):
            self._ensure_roots()
            self._recover_locked()
            replay = self._begin(operation_id, action="package.uninstall", target=target)
            if replay:
                if package_id in self._read_records():
                    raise TransactionalPackageError(
                        "succeeded uninstall journal conflicts with package registry"
                    )
                return PackageLifecycleResult(
                    operation_id, "uninstall", package_id, None, None, True
                )

            before = self._read_records()
            try:
                record = _require_record(before, package_id)
            except TransactionalPackageError:
                self._fail_without_intent(operation_id, "package.not_installed")
                raise
            if not self._installed_marker_is_valid(package_id, record):
                self._fail_without_intent(operation_id, "package.integrity_marker_invalid")
                raise TransactionalPackageError(
                    "installed package integrity marker is invalid"
                )
            if package_id in self.protected_ids:
                self._fail_without_intent(operation_id, "package.protected")
                raise TransactionalPackageError("protected package cannot be uninstalled")
            if record.status == PackageStatus.ENABLED:
                self._fail_without_intent(operation_id, "package.enabled")
                raise TransactionalPackageError("disable package before uninstall")
            if self.state_validator is not None:
                try:
                    self.state_validator("uninstall", package_id, record, before)
                except TransactionalPackageError:
                    self._fail_without_intent(operation_id, "package.state_rejected")
                    raise
            dependents = _required_dependents(before, package_id, enabled_only=False)
            if dependents:
                self._fail_without_intent(operation_id, "package.dependents")
                raise TransactionalPackageError("installed dependents block uninstall")
            package_path = self._package_path(package_id)
            if not package_path.is_dir() or package_path.is_symlink():
                self._fail_without_intent(operation_id, "package.files_missing")
                raise TransactionalPackageError("installed package files are missing")

            after = dict(before)
            del after[package_id]
            intent = self._new_intent(
                operation_id,
                "uninstall",
                package_id,
                before,
                after,
                backup=True,
            )
            self._execute(intent)
            return PackageLifecycleResult(
                operation_id, "uninstall", package_id, None, None
            )

    def recover(self) -> tuple[str, ...]:
        """Recover every durable intent and return the affected operation IDs."""

        with exclusive_file_lock(self.lock_target):
            self._ensure_roots()
            return self._recover_locked()

    def records(self) -> dict[str, PackageRecord]:
        with exclusive_file_lock(self.lock_target):
            self._ensure_roots()
            self._recover_locked()
            return self._read_records()

    def _install_or_update(
        self,
        operation_id: str,
        artifact: VerifiedPackageArtifact,
        *,
        action: Literal["install", "update"],
    ) -> PackageLifecycleResult:
        operation_id = _validate_operation_id(operation_id)
        package_id = artifact.manifest.id
        target = f"package/{package_id}/{artifact.artifact_sha256}"
        journal_action = f"package.{action}"
        with exclusive_file_lock(self.lock_target):
            self._ensure_roots()
            self._recover_locked()
            replay = self._begin(operation_id, action=journal_action, target=target)
            if replay:
                record = self._read_records().get(package_id)
                if (
                    record is None
                    or record.manifest.version != artifact.manifest.version
                    or not self._artifact_marker_matches(
                        self._package_path(package_id),
                        package_id=package_id,
                        version=artifact.manifest.version,
                        artifact_sha256=artifact.artifact_sha256,
                        signature_key_id=artifact.signature_key_id,
                    )
                ):
                    raise TransactionalPackageError(
                        f"succeeded {action} journal conflicts with package registry"
                    )
                return _result(operation_id, action, record, replay=True)

            before = self._read_records()
            existing = before.get(package_id)
            if package_id in RESERVED_PACKAGE_IDS:
                self._fail_without_intent(operation_id, "package.reserved")
                raise TransactionalPackageError("package id is reserved")
            if action == "install" and existing is not None:
                self._fail_without_intent(operation_id, "package.already_installed")
                raise TransactionalPackageError("package is already installed")
            if action == "update":
                if existing is None:
                    self._fail_without_intent(operation_id, "package.not_installed")
                    raise TransactionalPackageError("package is not installed")
                if existing.manifest.type != artifact.manifest.type:
                    self._fail_without_intent(operation_id, "package.type_changed")
                    raise TransactionalPackageError("package type cannot change during update")
                if Version(artifact.manifest.version) <= Version(existing.manifest.version):
                    self._fail_without_intent(operation_id, "package.version_not_newer")
                    raise TransactionalPackageError("package update version must be newer")
                if not self._installed_marker_is_valid(package_id, existing):
                    self._fail_without_intent(
                        operation_id, "package.integrity_marker_invalid"
                    )
                    raise TransactionalPackageError(
                        "installed package integrity marker is invalid"
                    )
                installed_signer = self._installed_signer(package_id)
                signer_transition_allowed = (
                    installed_signer == artifact.signature_key_id
                    or (
                        self.signer_transition_authorizer is not None
                        and self.signer_transition_authorizer(
                            package_id,
                            artifact.manifest.type,
                            installed_signer,
                            artifact.signature_key_id,
                        )
                    )
                )
                if not signer_transition_allowed:
                    self._fail_without_intent(
                        operation_id,
                        "package.signer_changed",
                    )
                    raise TransactionalPackageError(
                        "package update signer does not match the installed package"
                    )

            status = existing.status if existing else PackageStatus.INSTALLED
            after = dict(before)
            after[package_id] = PackageRecord(manifest=artifact.manifest, status=status)
            try:
                self._validate_graph(after)
                if status == PackageStatus.ENABLED:
                    _require_enabled_dependencies(after, package_id)
            except TransactionalPackageError:
                self._fail_without_intent(operation_id, "package.dependency_invalid")
                raise

            package_path = self._package_path(package_id)
            if action == "install" and package_path.exists():
                self._fail_without_intent(operation_id, "package.files_exist")
                raise TransactionalPackageError("package destination already exists")
            if action == "update" and (
                not package_path.is_dir() or package_path.is_symlink()
            ):
                self._fail_without_intent(operation_id, "package.files_missing")
                raise TransactionalPackageError("installed package files are missing")

            intent = self._new_intent(
                operation_id,
                action,
                package_id,
                before,
                after,
                artifact_sha256=artifact.artifact_sha256,
                signature_key_id=artifact.signature_key_id,
                stage=True,
                backup=action == "update",
            )
            try:
                self._write_intent(intent)
            except Exception:
                self._mark_failed(operation_id, "package.intent_write_failed")
                raise TransactionalPackageError(
                    "package transaction intent could not be persisted"
                ) from None
            try:
                self.artifact_verifier.extract(artifact, self._stage_path(intent))
                self._write_artifact_marker(self._stage_path(intent), artifact)
                if self.stage_validator is not None:
                    self.stage_validator(
                        self._stage_path(intent),
                        artifact.manifest,
                        before,
                    )
            except Exception:
                self._rollback_and_fail(intent, "package.artifact_stage_failed")
                raise TransactionalPackageError(
                    "package artifact staging failed and was rolled back"
                ) from None
            try:
                self._inject("after_stage")
            except Exception:
                self._rollback_and_fail(intent, "package.after_stage_failed")
                raise TransactionalPackageError(
                    "package staging failed and was rolled back"
                ) from None
            self._execute(intent)
            return _result(operation_id, action, after[package_id])

    def _state_change(
        self,
        operation_id: str,
        package_id: str,
        *,
        action: Literal["enable", "disable"],
    ) -> PackageLifecycleResult:
        operation_id = _validate_operation_id(operation_id)
        package_id = _validate_package_id(package_id)
        target = f"package/{package_id}"
        with exclusive_file_lock(self.lock_target):
            self._ensure_roots()
            self._recover_locked()
            replay = self._begin(
                operation_id,
                action=f"package.{action}",
                target=target,
            )
            if replay:
                record = _require_record(self._read_records(), package_id)
                expected = (
                    PackageStatus.ENABLED if action == "enable" else PackageStatus.DISABLED
                )
                if record.status != expected or not self._installed_marker_is_valid(
                    package_id, record
                ):
                    raise TransactionalPackageError(
                        f"succeeded {action} journal conflicts with package registry"
                    )
                return _result(operation_id, action, record, replay=True)

            before = self._read_records()
            try:
                record = _require_record(before, package_id)
            except TransactionalPackageError:
                self._fail_without_intent(operation_id, "package.not_installed")
                raise
            if not self._installed_marker_is_valid(package_id, record):
                self._fail_without_intent(operation_id, "package.integrity_marker_invalid")
                raise TransactionalPackageError(
                    "installed package integrity marker is invalid"
                )
            if action == "disable" and package_id in self.protected_ids:
                self._fail_without_intent(operation_id, "package.protected")
                raise TransactionalPackageError("protected package cannot be disabled")
            if self.state_validator is not None:
                try:
                    self.state_validator(action, package_id, record, before)
                except TransactionalPackageError:
                    self._fail_without_intent(operation_id, "package.state_rejected")
                    raise
            if action == "enable":
                try:
                    _require_enabled_dependencies(before, package_id)
                    _require_enabled_capabilities(before, enabling=package_id)
                except TransactionalPackageError:
                    self._fail_without_intent(
                        operation_id, "package.dependency_not_enabled"
                    )
                    raise
                status = PackageStatus.ENABLED
            else:
                dependents = _required_dependents(before, package_id, enabled_only=True)
                if dependents:
                    self._fail_without_intent(operation_id, "package.dependents")
                    raise TransactionalPackageError("enabled dependents block disable")
                try:
                    _require_enabled_capabilities(before, disabling=package_id)
                except TransactionalPackageError:
                    self._fail_without_intent(
                        operation_id, "package.capability_dependents"
                    )
                    raise
                status = PackageStatus.DISABLED
            after = dict(before)
            after[package_id] = record.model_copy(update={"status": status})
            intent = self._new_intent(
                operation_id,
                action,
                package_id,
                before,
                after,
            )
            self._execute(intent)
            return _result(operation_id, action, after[package_id])

    def _execute(self, intent: _TransactionIntent) -> None:
        if not self._intent_path(intent.operation_id).is_file():
            try:
                self._write_intent(intent)
            except Exception:
                self._mark_failed(intent.operation_id, "package.intent_write_failed")
                raise TransactionalPackageError(
                    "package transaction intent could not be persisted"
                ) from None
        current = intent
        try:
            if intent.action in {"install", "update", "uninstall"}:
                self._apply_files(intent)
            current = intent.model_copy(update={"phase": TransactionPhase.FILES_APPLIED})
            self._write_intent(current)
            self._inject("after_filesystem")
            if intent.action in {"install", "update"}:
                self._apply_migrations(intent)

            self._write_records(intent.registry_after)
            current = current.model_copy(update={"phase": TransactionPhase.REGISTRY_APPLIED})
            self._write_intent(current)
            self._inject("after_registry")
        except Exception:
            self._rollback_and_fail(current, f"package.{intent.action}_failed")
            raise TransactionalPackageError(
                f"package {intent.action} failed and was rolled back"
            ) from None

        try:
            current = current.model_copy(update={"phase": TransactionPhase.COMMITTED})
            self._write_intent(current)
        except Exception:
            self._rollback_and_fail(current, f"package.{intent.action}_failed")
            raise TransactionalPackageError(
                f"package {intent.action} failed and was rolled back"
            ) from None
        try:
            self._inject("after_commit_marker")
            self.operation_journal.succeed(intent.operation_id)
        except Exception:
            # The durable commit decision has been written. Recovery must finish
            # forward; rolling back now could contradict a succeeded journal.
            raise TransactionalPackageError(
                f"package {intent.action} committed; journal recovery is required"
            ) from None
        self._cleanup_intent(current)

    def _recover_locked(self) -> tuple[str, ...]:
        recovered: list[str] = []
        intents: dict[str, _TransactionIntent] = {}
        for path in sorted(self.intent_root.glob("*.json")):
            try:
                intent = _TransactionIntent.model_validate(read_json(path, {}))
            except Exception as error:
                raise TransactionalPackageError(
                    "package transaction intent cannot be validated"
                ) from error
            if path != self._intent_path(intent.operation_id):
                raise TransactionalPackageError("package transaction intent path is invalid")
            intents[intent.operation_id] = intent
            state = self.operation_journal.state(intent.operation_id)
            if state is None:
                raise TransactionalPackageError(
                    "package transaction intent has no operation journal"
                )
            if intent.phase == TransactionPhase.COMMITTED:
                if not self._postcondition(intent):
                    # COMMITTED is the durable transaction decision. Never turn
                    # corruption or lost postcondition evidence into a rollback;
                    # preserve the committed state/intent for explicit repair.
                    raise TransactionalPackageError(
                        "committed package postcondition is invalid; recovery is required"
                    )
                if state.status == OperationStatus.STARTED:
                    self.operation_journal.succeed(intent.operation_id)
                elif state.status != OperationStatus.SUCCEEDED:
                    raise TransactionalPackageError(
                        "committed package intent conflicts with operation journal"
                    )
                self._cleanup_intent(intent)
            else:
                if state.status == OperationStatus.SUCCEEDED:
                    raise TransactionalPackageError(
                        "pre-commit package intent conflicts with succeeded journal"
                    )
                self._rollback_intent(intent)
                self._mark_failed(intent.operation_id, "package.recovered_rollback")
                self._cleanup_intent(intent)
            recovered.append(intent.operation_id)

        for state in self.operation_journal.pending():
            if state.action.startswith("package.") and state.operation_id not in intents:
                self.operation_journal.fail(
                    state.operation_id,
                    error_code="package.interrupted_before_prepare",
                )
                recovered.append(state.operation_id)
        return tuple(sorted(set(recovered)))

    def _begin(self, operation_id: str, *, action: str, target: str) -> bool:
        state = self.operation_journal.begin(
            operation_id,
            action=action,
            target=target,
        )
        if state.status == OperationStatus.SUCCEEDED:
            return True
        if state.status == OperationStatus.FAILED:
            self.operation_journal.retry(operation_id)
            return False
        return False

    def _new_intent(
        self,
        operation_id: str,
        action: PackageAction,
        package_id: str,
        before: Mapping[str, PackageRecord],
        after: Mapping[str, PackageRecord],
        *,
        artifact_sha256: str | None = None,
        signature_key_id: str | None = None,
        stage: bool = False,
        backup: bool = False,
    ) -> _TransactionIntent:
        token = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:24]
        prefix = f"{package_id}-{token}"
        return _TransactionIntent(
            operation_id=operation_id,
            action=action,
            package_id=package_id,
            phase=TransactionPhase.PREPARED,
            registry_before=dict(before),
            registry_after=dict(after),
            artifact_sha256=artifact_sha256,
            signature_key_id=signature_key_id,
            stage_name=f"{prefix}.stage" if stage else None,
            backup_name=f"{prefix}.backup" if backup else None,
        )

    def _apply_files(self, intent: _TransactionIntent) -> None:
        package_path = self._package_path(intent.package_id)
        stage_path = self._stage_path(intent) if intent.stage_name else None
        backup_path = self._backup_path(intent) if intent.backup_name else None
        if intent.action == "install":
            if stage_path is None or not stage_path.is_dir() or package_path.exists():
                raise TransactionalPackageError("install staging postcondition failed")
            stage_path.replace(package_path)
        elif intent.action == "update":
            if (
                stage_path is None
                or backup_path is None
                or not stage_path.is_dir()
                or not package_path.is_dir()
                or backup_path.exists()
            ):
                raise TransactionalPackageError("update staging postcondition failed")
            package_path.replace(backup_path)
            stage_path.replace(package_path)
        elif intent.action == "uninstall":
            if backup_path is None or not package_path.is_dir() or backup_path.exists():
                raise TransactionalPackageError("uninstall staging postcondition failed")
            package_path.replace(backup_path)

    def _apply_migrations(self, intent: _TransactionIntent) -> None:
        record = intent.registry_after.get(intent.package_id)
        if record is None or not record.manifest.migrations:
            return
        if self.migration_applier is None:
            raise TransactionalPackageError(
                "package declares migrations but no migration applier is configured"
            )
        package_path = self._package_path(intent.package_id)
        try:
            self.migration_applier(package_path, record.manifest)
        except TransactionalPackageError:
            raise
        except Exception as error:
            raise TransactionalPackageError(
                "package migration application failed"
            ) from error

    def _rollback_and_fail(self, intent: _TransactionIntent, error_code: str) -> None:
        try:
            rolled_back = self._rollback_intent(intent)
            self._mark_failed(intent.operation_id, error_code)
            self._cleanup_intent(rolled_back)
        except Exception as error:
            raise TransactionalPackageError(
                "package rollback is incomplete and requires recovery"
            ) from error

    def _rollback_intent(self, intent: _TransactionIntent) -> _TransactionIntent:
        package_path = self._package_path(intent.package_id)
        stage_path = self._stage_path(intent) if intent.stage_name else None
        backup_path = self._backup_path(intent) if intent.backup_name else None

        if intent.action == "install":
            if intent.package_id not in intent.registry_before and package_path.exists():
                _remove_private_tree(package_path, self.packages_root)
        elif intent.action in {"update", "uninstall"} and backup_path is not None:
            if backup_path.exists():
                if package_path.exists():
                    _remove_private_tree(package_path, self.packages_root)
                backup_path.replace(package_path)
        if stage_path is not None and stage_path.exists():
            _remove_private_tree(stage_path, self.stage_root)
        self._write_records(intent.registry_before)
        rolled_back = intent.model_copy(update={"phase": TransactionPhase.ROLLED_BACK})
        self._write_intent(rolled_back)
        return rolled_back

    def _postcondition(self, intent: _TransactionIntent) -> bool:
        if self._read_records() != intent.registry_after:
            return False
        package_path = self._package_path(intent.package_id)
        if intent.action in {"install", "update"}:
            record = intent.registry_after.get(intent.package_id)
            return (
                record is not None
                and package_path.is_dir()
                and not package_path.is_symlink()
                and intent.artifact_sha256 is not None
                and intent.signature_key_id is not None
                and self._artifact_marker_matches(
                    package_path,
                    package_id=intent.package_id,
                    version=record.manifest.version,
                    artifact_sha256=intent.artifact_sha256,
                    signature_key_id=intent.signature_key_id,
                )
            )
        if intent.action == "uninstall":
            return not package_path.exists()
        return True

    def _cleanup_intent(self, intent: _TransactionIntent) -> None:
        if intent.stage_name:
            stage_path = self._stage_path(intent)
            if stage_path.exists():
                _remove_private_tree(stage_path, self.stage_root)
        if intent.backup_name:
            backup_path = self._backup_path(intent)
            if backup_path.exists():
                _remove_private_tree(backup_path, self.backup_root)
        self._intent_path(intent.operation_id).unlink(missing_ok=True)

    def _validate_graph(self, records: Mapping[str, PackageRecord]) -> None:
        try:
            resolve_install_order(
                [record.manifest for record in records.values()],
                core_version=self.core_version,
            )
        except DependencyResolutionError as error:
            raise TransactionalPackageError("package dependency graph is invalid") from error

    def _write_artifact_marker(
        self,
        package_path: Path,
        artifact: VerifiedPackageArtifact,
    ) -> None:
        write_json_atomic(
            package_path / INTEGRITY_MARKER_FILENAME,
            {
                "schema_version": 1,
                "package_id": artifact.manifest.id,
                "version": artifact.manifest.version,
                "artifact_sha256": artifact.artifact_sha256,
                "signature_key_id": artifact.signature_key_id,
            },
        )

    def _installed_marker_is_valid(
        self,
        package_id: str,
        record: PackageRecord,
    ) -> bool:
        marker_path = self._package_path(package_id) / INTEGRITY_MARKER_FILENAME
        if marker_path.is_symlink() or not marker_path.is_file():
            return False
        try:
            marker = read_json(marker_path, {})
        except Exception:
            return False
        return (
            isinstance(marker, dict)
            and set(marker)
            == {
                "schema_version",
                "package_id",
                "version",
                "artifact_sha256",
                "signature_key_id",
            }
            and marker.get("schema_version") == 1
            and marker.get("package_id") == package_id
            and marker.get("version") == record.manifest.version
            and isinstance(marker.get("artifact_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", marker["artifact_sha256"]) is not None
            and isinstance(marker.get("signature_key_id"), str)
            and bool(marker["signature_key_id"])
        )

    def _artifact_marker_matches(
        self,
        package_path: Path,
        *,
        package_id: str,
        version: str,
        artifact_sha256: str,
        signature_key_id: str,
    ) -> bool:
        marker_path = package_path / INTEGRITY_MARKER_FILENAME
        if marker_path.is_symlink() or not marker_path.is_file():
            return False
        try:
            marker = read_json(marker_path, {})
        except Exception:
            return False
        return marker == {
            "schema_version": 1,
            "package_id": package_id,
            "version": version,
            "artifact_sha256": artifact_sha256,
            "signature_key_id": signature_key_id,
        }

    def _installed_signer(self, package_id: str) -> str:
        marker_path = self._package_path(package_id) / INTEGRITY_MARKER_FILENAME
        try:
            marker = read_json(marker_path, {})
        except Exception:
            raise TransactionalPackageError(
                "installed package integrity marker is invalid"
            ) from None
        signer = marker.get("signature_key_id") if isinstance(marker, dict) else None
        if not isinstance(signer, str) or not signer:
            raise TransactionalPackageError(
                "installed package integrity marker is invalid"
            )
        return signer

    def _read_records(self) -> dict[str, PackageRecord]:
        data = read_json(self.registry_path, {"packages": {}})
        if not isinstance(data, dict) or set(data) != {"packages"}:
            raise TransactionalPackageError("package registry is invalid")
        raw_records = data["packages"]
        if not isinstance(raw_records, dict):
            raise TransactionalPackageError("package registry is invalid")
        try:
            records = {
                package_id: PackageRecord.model_validate(raw)
                for package_id, raw in raw_records.items()
            }
        except Exception as error:
            raise TransactionalPackageError("package registry is invalid") from error
        if any(package_id != record.manifest.id for package_id, record in records.items()):
            raise TransactionalPackageError("package registry identity is invalid")
        return records

    def _write_records(self, records: Mapping[str, PackageRecord]) -> None:
        write_json_atomic(
            self.registry_path,
            {
                "packages": {
                    package_id: record.model_dump(mode="json")
                    for package_id, record in sorted(records.items())
                }
            },
        )

    def _write_intent(self, intent: _TransactionIntent) -> None:
        write_json_atomic(
            self._intent_path(intent.operation_id),
            intent.model_dump(mode="json"),
        )

    def _mark_failed(self, operation_id: str, error_code: str) -> None:
        state = self.operation_journal.state(operation_id)
        if state is not None and state.status == OperationStatus.STARTED:
            self.operation_journal.fail(operation_id, error_code=error_code)

    def _fail_without_intent(self, operation_id: str, error_code: str) -> None:
        self._mark_failed(operation_id, error_code)

    def _inject(self, point: str) -> None:
        if self.failure_injector is not None:
            self.failure_injector(point)

    def _ensure_roots(self) -> None:
        for root in (
            self.packages_root,
            self.transaction_root,
            self.intent_root,
            self.stage_root,
            self.backup_root,
        ):
            if root.is_symlink():
                raise TransactionalPackageError("package lifecycle root cannot be a symlink")
            root.mkdir(parents=True, exist_ok=True)

    def _package_path(self, package_id: str) -> Path:
        return self.packages_root / _validate_package_id(package_id)

    def _intent_path(self, operation_id: str) -> Path:
        token = hashlib.sha256(
            _validate_operation_id(operation_id).encode("utf-8")
        ).hexdigest()
        return self.intent_root / f"{token}.json"

    def _stage_path(self, intent: _TransactionIntent) -> Path:
        if not intent.stage_name:
            raise TransactionalPackageError("package transaction has no staging path")
        expected = f"{self._transaction_prefix(intent)}.stage"
        if intent.stage_name != expected:
            raise TransactionalPackageError("package transaction staging path is invalid")
        return self.stage_root / intent.stage_name

    def _backup_path(self, intent: _TransactionIntent) -> Path:
        if not intent.backup_name:
            raise TransactionalPackageError("package transaction has no backup path")
        expected = f"{self._transaction_prefix(intent)}.backup"
        if intent.backup_name != expected:
            raise TransactionalPackageError("package transaction backup path is invalid")
        return self.backup_root / intent.backup_name

    @staticmethod
    def _transaction_prefix(intent: _TransactionIntent) -> str:
        token = hashlib.sha256(intent.operation_id.encode("utf-8")).hexdigest()[:24]
        return f"{_validate_package_id(intent.package_id)}-{token}"


def _result(
    operation_id: str,
    action: PackageAction,
    record: PackageRecord,
    *,
    replay: bool = False,
) -> PackageLifecycleResult:
    return PackageLifecycleResult(
        operation_id=operation_id,
        action=action,
        package_id=record.manifest.id,
        version=record.manifest.version,
        status=record.status,
        idempotent_replay=replay,
    )


def _validate_operation_id(value: str) -> str:
    if not isinstance(value, str) or not _OPERATION_ID.fullmatch(value):
        raise ValueError("invalid package lifecycle operation id")
    return value


def _validate_package_id(value: str) -> str:
    # Reuse the public manifest validator without accepting path separators.
    from plaik_contracts.packages import PACKAGE_ID_PATTERN

    if not isinstance(value, str) or re.fullmatch(PACKAGE_ID_PATTERN, value) is None:
        raise ValueError("invalid package id")
    return value


def _require_record(
    records: Mapping[str, PackageRecord], package_id: str
) -> PackageRecord:
    try:
        return records[package_id]
    except KeyError as error:
        raise TransactionalPackageError("package is not installed") from error


def _require_enabled_dependencies(
    records: Mapping[str, PackageRecord], package_id: str
) -> None:
    record = _require_record(records, package_id)
    for dependency in record.manifest.dependencies:
        if dependency.optional:
            continue
        target = records.get(dependency.package_id)
        if target is None or target.status != PackageStatus.ENABLED:
            raise TransactionalPackageError("required package dependency is not enabled")
        if not version_matches(target.manifest.version, dependency.version):
            raise TransactionalPackageError("required package dependency is incompatible")


def _require_enabled_capabilities(
    records: Mapping[str, PackageRecord],
    *,
    enabling: str | None = None,
    disabling: str | None = None,
) -> None:
    selected = {
        package_id: record.manifest
        for package_id, record in records.items()
        if package_id != disabling
        and (record.status == PackageStatus.ENABLED or package_id == enabling)
    }
    try:
        resolve_capabilities(selected)
    except DependencyResolutionError as error:
        raise TransactionalPackageError(str(error)) from error


def _required_dependents(
    records: Mapping[str, PackageRecord],
    package_id: str,
    *,
    enabled_only: bool,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            other_id
            for other_id, other in records.items()
            if (not enabled_only or other.status == PackageStatus.ENABLED)
            and any(
                dependency.package_id == package_id and not dependency.optional
                for dependency in other.manifest.dependencies
            )
        )
    )


def _remove_private_tree(path: Path, root: Path) -> None:
    path = Path(path)
    root = Path(root).resolve()
    resolved_parent = path.parent.resolve()
    if resolved_parent != root or path.name in {"", ".", ".."}:
        raise TransactionalPackageError("refusing to remove package path outside its root")
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.exists():
        shutil.rmtree(path)