"""Crash-atomic package lifecycle coordinator with a PostgreSQL 2PC participant."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Protocol

from plaik_contracts import PackageManifest

from .operation_journal import OperationStatus
from .package_lifecycle import (
    TransactionPhase,
    TransactionalPackageError,
    TransactionalPackageManager,
    _TransactionIntent,
)
from .package_sql_recovery import (
    PackageSQLParticipantPhase,
    PackageSQLParticipantRecord,
    PackageSQLRecoveryAction,
    package_sql_recovery_action,
)
from .storage import read_json, write_json_atomic


class PackageSQLCoordinator(Protocol):
    """Database participant boundary used by the local package coordinator."""

    def plan(
        self,
        operation_id: str,
        package_root: Path,
        manifest: PackageManifest,
        artifact_sha256: str,
    ) -> PackageSQLParticipantRecord: ...

    def prepare(
        self,
        record: PackageSQLParticipantRecord,
        package_root: Path,
        manifest: PackageManifest,
    ) -> None: ...

    def inspect(self, record: PackageSQLParticipantRecord) -> bool: ...

    def finish(self, record: PackageSQLParticipantRecord, *, commit: bool) -> None: ...

    def verify_rolled_back(self, record: PackageSQLParticipantRecord) -> None: ...

    def verify_finished(self, record: PackageSQLParticipantRecord) -> None: ...


class CrashAtomicPackageManager(TransactionalPackageManager):
    """Extend the proven local lifecycle with one durable SQL 2PC participant.

    The base lifecycle remains untouched for packages without SQL migrations.
    SQL packages add a co-located participant record under the same transaction
    root. That record is written before PostgreSQL can become prepared and is
    cryptographically/deterministically bound to the base intent's operation,
    package and signed artifact digest.
    """

    def __init__(self, *args, sql_coordinator: PackageSQLCoordinator, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.sql_coordinator = sql_coordinator
        self.sql_intent_root = self.transaction_root / "sql-participants"

    def _ensure_roots(self) -> None:
        super()._ensure_roots()
        if self.sql_intent_root.is_symlink():
            raise TransactionalPackageError(
                "package SQL participant root cannot be a symlink"
            )
        self.sql_intent_root.mkdir(parents=True, exist_ok=True)

    def _execute(self, intent: _TransactionIntent) -> None:
        record = intent.registry_after.get(intent.package_id)
        if (
            intent.action not in {"install", "update"}
            or record is None
            or not record.manifest.migrations
        ):
            super()._execute(intent)
            return
        if intent.artifact_sha256 is None:
            raise TransactionalPackageError(
                "package SQL transaction requires a signed artifact digest"
            )

        if not self._intent_path(intent.operation_id).is_file():
            try:
                self._write_intent(intent)
            except Exception:
                self._mark_failed(intent.operation_id, "package.intent_write_failed")
                raise TransactionalPackageError(
                    "package transaction intent could not be persisted"
                ) from None

        current = intent
        sql_record: PackageSQLParticipantRecord | None = None
        try:
            self._apply_files(intent)
            current = intent.model_copy(update={"phase": TransactionPhase.FILES_APPLIED})
            self._write_intent(current)
            self._inject("after_filesystem")

            package_root = self._package_path(intent.package_id)
            sql_record = self.sql_coordinator.plan(
                intent.operation_id,
                package_root,
                record.manifest,
                intent.artifact_sha256,
            )
            self._validate_sql_binding(intent, sql_record)
            if sql_record.phase != PackageSQLParticipantPhase.PREPARING:
                raise TransactionalPackageError(
                    "package SQL coordinator plan must start in preparing phase"
                )
            self._write_sql_record(sql_record)
            self._inject("after_sql_intent")

            self.sql_coordinator.prepare(sql_record, package_root, record.manifest)
            self._inject("after_sql_prepare")
            sql_record = sql_record.model_copy(
                update={"phase": PackageSQLParticipantPhase.PREPARED}
            )
            self._write_sql_record(sql_record)
            self._inject("after_sql_prepared_marker")

            self._write_records(intent.registry_after)
            current = current.model_copy(update={"phase": TransactionPhase.REGISTRY_APPLIED})
            self._write_intent(current)
            self._inject("after_registry")
        except Exception:
            if sql_record is not None:
                try:
                    self._recover_sql_participant(
                        current,
                        sql_record,
                        local_committed=False,
                    )
                except Exception as error:
                    raise TransactionalPackageError(
                        "package SQL rollback is incomplete and requires recovery"
                    ) from error
            self._rollback_and_fail(current, f"package.{intent.action}_failed")
            raise TransactionalPackageError(
                f"package {intent.action} failed and was rolled back"
            ) from None

        try:
            current = current.model_copy(update={"phase": TransactionPhase.COMMITTED})
            self._write_intent(current)
        except Exception:
            try:
                assert sql_record is not None
                self._recover_sql_participant(
                    current,
                    sql_record,
                    local_committed=False,
                )
            except Exception as error:
                raise TransactionalPackageError(
                    "package SQL rollback is incomplete and requires recovery"
                ) from error
            self._rollback_and_fail(current, f"package.{intent.action}_failed")
            raise TransactionalPackageError(
                f"package {intent.action} failed and was rolled back"
            ) from None

        try:
            self._inject("after_commit_marker")
            assert sql_record is not None
            self._recover_sql_participant(
                current,
                sql_record,
                local_committed=True,
            )
            sql_record = sql_record.model_copy(
                update={"phase": PackageSQLParticipantPhase.FINISHED}
            )
            self._write_sql_record(sql_record)
            self._inject("after_sql_finish")
            self.operation_journal.succeed(intent.operation_id)
        except Exception:
            raise TransactionalPackageError(
                f"package {intent.action} committed; SQL/journal recovery is required"
            ) from None
        self._cleanup_intent(current)

    def _recover_locked(self) -> tuple[str, ...]:
        recovered: list[str] = []
        intents: dict[str, _TransactionIntent] = {}

        sql_records = self._all_sql_records()
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

            sql_record = sql_records.pop(intent.operation_id, None)
            manifest_record = intent.registry_after.get(intent.package_id)
            declares_sql = bool(
                intent.action in {"install", "update"}
                and manifest_record is not None
                and manifest_record.manifest.migrations
            )
            if sql_record is not None:
                self._validate_sql_binding(intent, sql_record)
            elif declares_sql and intent.phase in {
                TransactionPhase.REGISTRY_APPLIED,
                TransactionPhase.COMMITTED,
            }:
                raise TransactionalPackageError(
                    "package SQL transaction lost its durable participant evidence"
                )

            if intent.phase == TransactionPhase.COMMITTED:
                if declares_sql:
                    if sql_record is None:
                        raise TransactionalPackageError(
                            "committed package SQL transaction has no participant record"
                        )
                    self._recover_sql_participant(
                        intent,
                        sql_record,
                        local_committed=True,
                    )
                    if sql_record.phase != PackageSQLParticipantPhase.FINISHED:
                        sql_record = sql_record.model_copy(
                            update={"phase": PackageSQLParticipantPhase.FINISHED}
                        )
                        self._write_sql_record(sql_record)
                if not self._postcondition(intent):
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
                if sql_record is not None:
                    self._recover_sql_participant(
                        intent,
                        sql_record,
                        local_committed=False,
                    )
                self._rollback_intent(intent)
                self._mark_failed(intent.operation_id, "package.recovered_rollback")
                self._cleanup_intent(intent)
            recovered.append(intent.operation_id)

        if sql_records:
            raise TransactionalPackageError(
                "orphan package SQL participant evidence requires repair"
            )

        for state in self.operation_journal.pending():
            if state.action.startswith("package.") and state.operation_id not in intents:
                self.operation_journal.fail(
                    state.operation_id,
                    error_code="package.interrupted_before_prepare",
                )
                recovered.append(state.operation_id)
        return tuple(sorted(set(recovered)))

    def _recover_sql_participant(
        self,
        intent: _TransactionIntent,
        record: PackageSQLParticipantRecord,
        *,
        local_committed: bool,
    ) -> None:
        self._validate_sql_binding(intent, record)
        prepared_exists = self.sql_coordinator.inspect(record)
        action = package_sql_recovery_action(
            local_committed=local_committed,
            evidence=record.to_evidence(),
            prepared_exists=prepared_exists,
        )
        if action == PackageSQLRecoveryAction.ROLLBACK_PREPARED:
            self.sql_coordinator.finish(record, commit=False)
        elif action == PackageSQLRecoveryAction.COMMIT_PREPARED:
            self.sql_coordinator.finish(record, commit=True)
            self.sql_coordinator.verify_finished(record)
        elif action == PackageSQLRecoveryAction.VERIFY_ROLLED_BACK:
            self.sql_coordinator.verify_rolled_back(record)
        elif action == PackageSQLRecoveryAction.VERIFY_FINISHED:
            self.sql_coordinator.verify_finished(record)

    def _validate_sql_binding(
        self,
        intent: _TransactionIntent,
        record: PackageSQLParticipantRecord,
    ) -> None:
        evidence = record.to_evidence()
        if (
            evidence.participant.operation_id != intent.operation_id
            or evidence.participant.package_id != intent.package_id
            or intent.artifact_sha256 is None
            or evidence.participant.artifact_sha256 != intent.artifact_sha256
        ):
            raise TransactionalPackageError(
                "package SQL participant is not bound to the package transaction"
            )

    def _write_sql_record(self, record: PackageSQLParticipantRecord) -> None:
        write_json_atomic(
            self._sql_record_path(record.operation_id),
            record.model_dump(mode="json"),
        )

    def _read_sql_record(self, path: Path) -> PackageSQLParticipantRecord:
        if path.is_symlink() or not path.is_file():
            raise TransactionalPackageError("package SQL participant path is invalid")
        try:
            record = PackageSQLParticipantRecord.model_validate(read_json(path, {}))
            record.to_evidence()
        except Exception as error:
            raise TransactionalPackageError(
                "package SQL participant evidence cannot be validated"
            ) from error
        if path != self._sql_record_path(record.operation_id):
            raise TransactionalPackageError("package SQL participant path is invalid")
        return record

    def _all_sql_records(self) -> dict[str, PackageSQLParticipantRecord]:
        records: dict[str, PackageSQLParticipantRecord] = {}
        for path in sorted(self.sql_intent_root.glob("*.json")):
            record = self._read_sql_record(path)
            if record.operation_id in records:
                raise TransactionalPackageError(
                    "duplicate package SQL participant evidence"
                )
            records[record.operation_id] = record
        return records

    def _sql_record_path(self, operation_id: str) -> Path:
        token = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
        return self.sql_intent_root / f"{token}.json"

    def _cleanup_intent(self, intent: _TransactionIntent) -> None:
        self._sql_record_path(intent.operation_id).unlink(missing_ok=True)
        super()._cleanup_intent(intent)
