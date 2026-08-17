"""Fail-closed offline backup/recovery and reference release commands."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import stat
import sys
from collections.abc import Callable
from pathlib import Path

from . import __version__
from .audit import AuditIntegrityError, AuditLog, AuditOutcome
from .backup import (
    BackupError,
    BackupManifest,
    BackupRecoveryPending,
    PlatformBackupManager,
)
from .checkpoint_anchor import checkpoint_verified_journal
from .config import CoreSettings
from .installer_config import (
    DatabaseBackend,
    InstallerConfiguration,
    InstallerConfigurationStore,
    SQLiteDatabase,
)
from .integrity import (
    FileCheckpointStore,
    IntegrityCheckpointError,
    JournalKind,
)
from .operation_journal import (
    OperationJournal,
    OperationJournalError,
    OperationStatus,
)
from .package_artifacts import Ed25519SignatureVerifier
from .releases import ReleaseDescriptor, ReleaseError, ReleaseManager
from .secret_store import LocalFileSecretProvider, SecretStoreError
from plaik_contracts import SecretReference
from .signing_keys import SigningKeyStoreError, load_ed25519_public_keys


_BACKUP_KEY = SecretReference(
    provider="local", key="platform/backup-integrity", version="v1"
)
_AUDIT_KEY = SecretReference(
    provider="local", key="platform/audit-integrity", version="v1"
)
_OPERATION_KEY = SecretReference(
    provider="local", key="platform/operation-journal-integrity", version="v1"
)
_CHECKPOINT_KEY = SecretReference(
    provider="local", key="platform/integrity-checkpoint", version="v1"
)


class _ReleaseEd25519Verifier:
    def __init__(self, keys: dict[str, bytes]) -> None:
        self._verifier = Ed25519SignatureVerifier(keys)

    def verify(self, key_id: str, message: bytes, signature: bytes) -> None:
        self._verifier.verify(key_id=key_id, payload=message, signature=signature)


def _add_operator_evidence(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--operation-id", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="plaik-ops")
    parser.add_argument("--data-dir", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)

    backup = commands.add_parser("backup")
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    backup_create = backup_commands.add_parser("create")
    backup_create.add_argument("output", type=Path)
    backup_create.add_argument("--include-secrets", action="store_true")
    backup_create.add_argument("--confirm-offline", action="store_true")
    _add_operator_evidence(backup_create)
    backup_verify = backup_commands.add_parser("verify")
    backup_verify.add_argument("archive", type=Path)
    backup_restore = backup_commands.add_parser("restore")
    backup_restore.add_argument("archive", type=Path)
    backup_restore.add_argument("--confirm-offline", action="store_true")
    _add_operator_evidence(backup_restore)

    release = commands.add_parser("release")
    release_commands = release.add_subparsers(dest="release_command", required=True)
    release_stage = release_commands.add_parser("stage")
    release_stage.add_argument("artifact", type=Path)
    release_stage.add_argument("descriptor", type=Path)
    release_stage.add_argument("signature", type=Path)
    _add_operator_evidence(release_stage)
    release_activate = release_commands.add_parser("activate")
    release_activate.add_argument("version")
    release_activate.add_argument("--confirm-marker-only", action="store_true")
    _add_operator_evidence(release_activate)
    release_rollback = release_commands.add_parser("rollback")
    release_rollback.add_argument("--confirm-marker-only", action="store_true")
    _add_operator_evidence(release_rollback)
    release_commands.add_parser("status")
    return parser


def _secret_bytes(provider: LocalFileSecretProvider, reference: SecretReference) -> bytes:
    return provider.read(reference.key, version=reference.version).get_secret_value().encode(
        "utf-8"
    )


def _backup_manager(runtime: CoreSettings) -> PlatformBackupManager:
    provider = LocalFileSecretProvider(runtime.secrets_dir)
    return PlatformBackupManager(
        runtime.data_dir,
        integrity_key=_secret_bytes(provider, _BACKUP_KEY),
        core_version=__version__,
    )


def _release_manager(runtime: CoreSettings) -> ReleaseManager:
    keys = load_ed25519_public_keys(runtime.trusted_release_signing_keys_path)
    return ReleaseManager(
        runtime.releases_dir,
        running_core_version=__version__,
        verifier=_ReleaseEd25519Verifier(keys),
    )


def _security_services(
    runtime: CoreSettings,
) -> tuple[AuditLog, OperationJournal, FileCheckpointStore]:
    provider = LocalFileSecretProvider(runtime.secrets_dir)
    return (
        AuditLog(runtime.audit_log_path, integrity_key=_secret_bytes(provider, _AUDIT_KEY)),
        OperationJournal(
            runtime.operation_journal_path,
            integrity_key=_secret_bytes(provider, _OPERATION_KEY),
        ),
        FileCheckpointStore(
            runtime.integrity_checkpoint_path,
            integrity_key=_secret_bytes(provider, _CHECKPOINT_KEY),
        ),
    )


def _anchor(
    configuration: InstallerConfiguration,
    audit: AuditLog,
    operations: OperationJournal,
    checkpoints: FileCheckpointStore,
) -> int:
    expected_epoch = checkpoints.current_recovery_epoch(configuration.installation_id)
    checkpoint_verified_journal(
        checkpoints,
        configuration.installation_id,
        JournalKind.AUDIT,
        verify=audit.verify,
        expected_recovery_epoch=expected_epoch,
    )
    checkpoint_verified_journal(
        checkpoints,
        configuration.installation_id,
        JournalKind.OPERATIONS,
        verify=operations.verify,
        expected_recovery_epoch=expected_epoch,
    )
    return expected_epoch


def _begin_operation(
    operations: OperationJournal,
    operation_id: str,
    *,
    action: str,
    target: str,
):
    state = operations.begin(operation_id, action=action, target=target)
    if state.status == OperationStatus.FAILED:
        state = operations.retry(operation_id)
    return state


def _target_id(path: Path) -> str:
    normalized = str(path.resolve(strict=False)).encode("utf-8")
    return "archive:" + hashlib.sha256(normalized).hexdigest()


def _schema_generation(root: Path, configuration: InstallerConfiguration) -> int:
    if not isinstance(configuration.database, SQLiteDatabase):
        raise BackupError(
            "filesystem backup supports SQLite only; PostgreSQL requires its dedicated adapter"
        )
    database = (root / configuration.database.path).resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    if database == resolved_root or resolved_root not in database.parents:
        raise BackupError("SQLite database path leaves the Platform data directory")
    try:
        metadata = database.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise BackupError("SQLite database path is unsafe")
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
            row = connection.execute(
                """
                SELECT schema_generation
                FROM plaik_runtime_schema_metadata
                WHERE singleton = 1
                """
            ).fetchone()
    except BackupError:
        raise
    except Exception:
        raise BackupError("SQLite schema generation cannot be verified") from None
    if row is None or not isinstance(row[0], int) or row[0] < 1:
        raise BackupError("SQLite schema generation is invalid")
    return row[0]


def _regular_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum_bytes:
        raise ValueError("operational input is unavailable or too large")
    return path.read_bytes()


def _emit(value) -> None:
    print(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    )


def _audit_once(
    audit: AuditLog,
    *,
    operation_id: str,
    actor_id: str,
    action: str,
    target_type: str,
    target_id: str,
    outcome: AuditOutcome,
) -> None:
    for event in audit.events():
        if (
            event.action == action
            and event.metadata.get("operation_id") == operation_id
            and event.outcome == outcome
        ):
            return
    audit.append(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        metadata={"operation_id": operation_id, "offline": True},
    )


def _record_failure(
    *,
    configuration: InstallerConfiguration,
    audit: AuditLog,
    operations: OperationJournal,
    checkpoints: FileCheckpointStore,
    operation_id: str,
    actor_id: str,
    action: str,
    target_type: str,
    target_id: str,
) -> None:
    state = operations.state(operation_id)
    if state is not None and state.status == OperationStatus.STARTED:
        operations.fail(operation_id, error_code="operation_failed")
    _audit_once(
        audit,
        operation_id=operation_id,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=AuditOutcome.FAILURE,
    )
    _anchor(configuration, audit, operations, checkpoints)


def _run_backup_create(args, runtime: CoreSettings) -> dict:
    if args.confirm_offline is not True:
        raise BackupError("backup creation requires explicit offline confirmation")
    configuration = InstallerConfigurationStore(runtime.installer_config_path).require()
    schema_generation = _schema_generation(runtime.data_dir, configuration)
    audit, operations, checkpoints = _security_services(runtime)
    manager = _backup_manager(runtime)
    target = _target_id(args.output)
    state = _begin_operation(
        operations,
        args.operation_id,
        action="backup.create",
        target=target,
    )
    if state.status == OperationStatus.SUCCEEDED:
        verified = manager.verify(args.output)
        if (
            verified.operation_id != args.operation_id
            or verified.installation_id != configuration.installation_id
            or verified.schema_generation != schema_generation
        ):
            raise BackupError("completed backup evidence does not match the archive")
        return {
            "status": "created",
            "archive": str(args.output.resolve(strict=False)),
            "files": verified.file_count,
            "includes_secrets": verified.includes_secrets,
            "idempotent_replay": True,
        }
    _audit_once(
        audit,
        operation_id=args.operation_id,
        actor_id=args.actor_id,
        action="backup.create.requested",
        target_type="backup",
        target_id=target,
        outcome=AuditOutcome.SUCCESS,
    )
    recovery_epoch = _anchor(configuration, audit, operations, checkpoints)
    try:
        result = manager.create(
            args.output,
            installation_id=configuration.installation_id,
            operation_id=args.operation_id,
            data_backend=configuration.database.backend.value,
            schema_generation=schema_generation,
            recovery_epoch=recovery_epoch,
            confirm_offline=True,
            include_secrets=args.include_secrets,
        )
        operations.succeed(args.operation_id)
        _audit_once(
            audit,
            operation_id=args.operation_id,
            actor_id=args.actor_id,
            action="backup.create",
            target_type="backup",
            target_id=hashlib.sha256(_manifest_for_digest(result)).hexdigest(),
            outcome=AuditOutcome.SUCCESS,
        )
        _anchor(configuration, audit, operations, checkpoints)
        return {
            "status": "created",
            "archive": str(args.output.resolve(strict=False)),
            "files": len(result.files),
            "includes_secrets": result.includes_secrets,
            "idempotent_replay": False,
        }
    except Exception:
        _record_failure(
            configuration=configuration,
            audit=audit,
            operations=operations,
            checkpoints=checkpoints,
            operation_id=args.operation_id,
            actor_id=args.actor_id,
            action="backup.create",
            target_type="backup",
            target_id=target,
        )
        raise


def _manifest_for_digest(manifest: BackupManifest) -> bytes:
    return json.dumps(
        manifest.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _run_backup_restore(args, runtime: CoreSettings) -> dict:
    if args.confirm_offline is not True:
        raise BackupError("restore requires explicit offline confirmation")
    configuration = InstallerConfigurationStore(runtime.installer_config_path).require()
    schema_generation = _schema_generation(runtime.data_dir, configuration)
    audit, operations, checkpoints = _security_services(runtime)
    manager = _backup_manager(runtime)
    verification = manager.verify(args.archive)
    target = "manifest:" + verification.manifest_sha256
    state = _begin_operation(
        operations,
        args.operation_id,
        action="backup.restore",
        target=target,
    )
    if state.status != OperationStatus.SUCCEEDED:
        _audit_once(
            audit,
            operation_id=args.operation_id,
            actor_id=args.actor_id,
            action="backup.restore.requested",
            target_type="backup",
            target_id=verification.manifest_sha256,
            outcome=AuditOutcome.SUCCESS,
        )
        _anchor(configuration, audit, operations, checkpoints)
    current_epoch = checkpoints.current_recovery_epoch(configuration.installation_id)
    provider = LocalFileSecretProvider(runtime.secrets_dir)
    audit_key = _secret_bytes(provider, _AUDIT_KEY)
    operation_key = _secret_bytes(provider, _OPERATION_KEY)

    def validate_staged(staging: Path, manifest: BackupManifest) -> None:
        staged_configuration = InstallerConfigurationStore(
            staging / runtime.installer_config_path.name
        ).require()
        if (
            staged_configuration.installation_id != configuration.installation_id
            or staged_configuration.database.backend != DatabaseBackend.SQLITE
        ):
            raise BackupError("staged backup installation identity is invalid")
        if _schema_generation(staging, staged_configuration) != manifest.schema_generation:
            raise BackupError("staged SQLite schema generation is invalid")
        AuditLog(
            staging / runtime.audit_log_path.name, integrity_key=audit_key
        ).verify()
        OperationJournal(
            staging / runtime.operation_journal_path.name,
            integrity_key=operation_key,
        ).verify()

    def commit_evidence(manifest: BackupManifest, manifest_digest: str) -> None:
        restored_configuration = InstallerConfigurationStore(
            runtime.installer_config_path
        ).require()
        restored_audit = AuditLog(runtime.audit_log_path, integrity_key=audit_key)
        restored_operations = OperationJournal(
            runtime.operation_journal_path, integrity_key=operation_key
        )
        restored_state = _begin_operation(
            restored_operations,
            args.operation_id,
            action="backup.restore",
            target="manifest:" + manifest_digest,
        )
        if restored_state.status != OperationStatus.SUCCEEDED:
            _audit_once(
                restored_audit,
                operation_id=args.operation_id,
                actor_id=args.actor_id,
                action="backup.restore",
                target_type="backup",
                target_id=manifest_digest,
                outcome=AuditOutcome.SUCCESS,
            )
            restored_operations.succeed(args.operation_id)
        audit_head = restored_audit.verify()
        operation_head = restored_operations.verify()
        checkpoints.recover(
            restored_configuration.installation_id,
            {
                JournalKind.AUDIT: (audit_head.event_count, audit_head.head_hash),
                JournalKind.OPERATIONS: (
                    operation_head.event_count,
                    operation_head.head_hash,
                ),
            },
            operation_id=args.operation_id,
            actor_id=args.actor_id,
            manifest_sha256=manifest_digest,
        )

    try:
        result = manager.restore(
            args.archive,
            confirm_offline=True,
            expected_installation_id=configuration.installation_id,
            expected_data_backend=configuration.database.backend.value,
            expected_schema_generation=schema_generation,
            current_recovery_epoch=current_epoch,
            operation_id=args.operation_id,
            actor_id=args.actor_id,
            staged_validator=validate_staged,
            post_commit=commit_evidence,
        )
    except BackupRecoveryPending:
        raise
    except Exception:
        _record_failure(
            configuration=configuration,
            audit=audit,
            operations=operations,
            checkpoints=checkpoints,
            operation_id=args.operation_id,
            actor_id=args.actor_id,
            action="backup.restore",
            target_type="backup",
            target_id=verification.manifest_sha256,
        )
        raise
    return {
        "status": "restored",
        "installation_id": result.installation_id,
        "files": len(result.files),
        "recovery_epoch": checkpoints.current_recovery_epoch(result.installation_id),
    }


def _run_release_mutation(
    *,
    args,
    runtime: CoreSettings,
    action: str,
    target: str,
    mutation: Callable[[], object],
):
    configuration = InstallerConfigurationStore(runtime.installer_config_path).require()
    audit, operations, checkpoints = _security_services(runtime)
    state = _begin_operation(
        operations, args.operation_id, action=action, target=target
    )
    if state.status == OperationStatus.SUCCEEDED:
        return mutation()
    _audit_once(
        audit,
        operation_id=args.operation_id,
        actor_id=args.actor_id,
        action=action + ".requested",
        target_type="release",
        target_id=target,
        outcome=AuditOutcome.SUCCESS,
    )
    _anchor(configuration, audit, operations, checkpoints)
    try:
        result = mutation()
        operations.succeed(args.operation_id)
        _audit_once(
            audit,
            operation_id=args.operation_id,
            actor_id=args.actor_id,
            action=action,
            target_type="release",
            target_id=target,
            outcome=AuditOutcome.SUCCESS,
        )
        _anchor(configuration, audit, operations, checkpoints)
        return result
    except Exception:
        _record_failure(
            configuration=configuration,
            audit=audit,
            operations=operations,
            checkpoints=checkpoints,
            operation_id=args.operation_id,
            actor_id=args.actor_id,
            action=action,
            target_type="release",
            target_id=target,
        )
        raise


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    runtime = CoreSettings(data_dir=args.data_dir)
    try:
        if args.command == "backup":
            if args.backup_command == "create":
                _emit(_run_backup_create(args, runtime))
            elif args.backup_command == "verify":
                result = _backup_manager(runtime).verify(args.archive)
                _emit({"status": "verified", **result.model_dump(mode="json")})
            else:
                _emit(_run_backup_restore(args, runtime))
        else:
            if args.release_command == "stage":
                manager = _release_manager(runtime)
                descriptor = ReleaseDescriptor.model_validate_json(
                    _regular_bytes(args.descriptor, maximum_bytes=256 * 1024)
                )
                result = _run_release_mutation(
                    args=args,
                    runtime=runtime,
                    action="release.stage",
                    target="version:" + descriptor.version,
                    mutation=lambda: manager.stage(
                        args.artifact,
                        descriptor,
                        _regular_bytes(args.signature, maximum_bytes=1024),
                    ),
                )
                _emit({"status": "staged", **result.model_dump(mode="json")})
            elif args.release_command == "activate":
                if args.confirm_marker_only is not True:
                    raise ReleaseError(
                        "activation requires confirmation that only the reference marker changes"
                    )
                manager = _release_manager(runtime)
                result = _run_release_mutation(
                    args=args,
                    runtime=runtime,
                    action="release.activate-marker",
                    target="version:" + args.version,
                    mutation=lambda: manager.activate(args.version),
                )
                _emit({"status": "activated-marker", **result.model_dump(mode="json")})
            elif args.release_command == "rollback":
                if args.confirm_marker_only is not True:
                    raise ReleaseError(
                        "rollback requires confirmation that only the reference marker changes"
                    )
                manager = _release_manager(runtime)
                current = manager.state()
                target = "version:" + (current.previous or "unavailable")
                result = _run_release_mutation(
                    args=args,
                    runtime=runtime,
                    action="release.rollback-marker",
                    target=target,
                    mutation=manager.rollback,
                )
                _emit({"status": "rolled-back-marker", **result.model_dump(mode="json")})
            else:
                manager = _release_manager(runtime)
                _emit({"status": "ok", **manager.state().model_dump(mode="json")})
        return 0
    except (
        AuditIntegrityError,
        BackupError,
        IntegrityCheckpointError,
        OperationJournalError,
        ReleaseError,
        SecretStoreError,
        SigningKeyStoreError,
        ValueError,
    ) as error:
        print(
            json.dumps(
                {"status": "error", "code": type(error).__name__},
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
