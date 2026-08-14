"""Bounded, signed offline SQLite backup and crash-recoverable restore."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import stat
import tempfile
import zipfile
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator, Literal
from uuid import uuid4

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field

from .package_artifacts import INTEGRITY_MARKER_FILENAME
from .storage import (
    exclusive_file_lock,
    fsync_directory_best_effort,
    write_json_atomic,
)


MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.hmac-sha256"
PAYLOAD_PREFIX = "payload/"
RESTORE_MARKER_NAME = ".plaik-restore-commit.json"
_RESTORE_MARKER_MAX_BYTES = 4096
_RESTORE_INTENT_MAX_BYTES = 65_536
_PROTECTED_PLATFORM_SECRET_NAMES = {
    "audit-integrity@v1.secret",
    "backup-integrity@v1.secret",
    "http-csrf-integrity@v1.secret",
    "integrity-checkpoint@v1.secret",
    "operation-journal-integrity@v1.secret",
    "session-pepper@v1.secret",
}


class BackupError(RuntimeError):
    """Backup creation, verification or restore failed safely."""


class BackupRecoveryPending(BackupError):
    """The new data is committed and recovery evidence still needs completion."""


class BackupFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: int = Field(ge=0, le=0o777)


class BackupManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[2] = 2
    core_version: str = Field(min_length=1, max_length=64)
    operation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    installation_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    data_backend: Literal["sqlite", "postgresql"]
    schema_generation: int = Field(ge=1)
    recovery_epoch: int = Field(ge=0)
    created_at: datetime
    includes_secrets: bool
    protected_platform_secrets_excluded: Literal[True] = True
    files: tuple[BackupFile, ...]


class BackupVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    file_count: int
    total_bytes: int
    includes_secrets: bool
    installation_id: str
    operation_id: str
    data_backend: Literal["sqlite", "postgresql"]
    core_version: str
    schema_generation: int
    recovery_epoch: int
    manifest_sha256: str


class RestoreIntent(BaseModel):
    """External, signed state for reconciling either directory-rename crash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    operation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    actor_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9@._:-]{1,127}$")
    installation_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    archive_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    staging_name: str = Field(pattern=r"^\.[A-Za-z0-9._-]{3,160}$")
    previous_name: str = Field(pattern=r"^\.[A-Za-z0-9._-]{3,160}$")
    phase: Literal[
        "prepared", "previous_moved", "committed", "finalized", "aborted"
    ]
    recorded_at: datetime
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


PostCommit = Callable[[BackupManifest, str], None]
StagedValidator = Callable[[Path, BackupManifest], None]


class PlatformBackupManager:
    """Create and restore explicitly offline Platform filesystem snapshots.

    This adapter intentionally supports SQLite only. PostgreSQL needs a
    transactionally consistent ``pg_dump``/restore adapter and fails closed
    here instead of receiving a misleading filesystem copy.
    """

    def __init__(
        self,
        data_dir: Path,
        *,
        integrity_key: bytes,
        core_version: str,
        maximum_file_bytes: int = 1_073_741_824,
        maximum_total_bytes: int = 10_737_418_240,
        maximum_archive_bytes: int = 10_738_466_816,
        maximum_manifest_bytes: int = 1_048_576,
        maximum_member_count: int = 100_000,
        maximum_path_bytes: int = 1024,
        maximum_compression_ratio: int = 1000,
    ) -> None:
        if len(integrity_key) < 32:
            raise ValueError("backup integrity key must contain at least 32 bytes")
        try:
            Version(core_version)
        except InvalidVersion:
            raise ValueError("invalid running Core version") from None
        if maximum_file_bytes < 1 or maximum_total_bytes < maximum_file_bytes:
            raise ValueError("invalid backup size limits")
        if maximum_archive_bytes < 1 or maximum_manifest_bytes < 256:
            raise ValueError("invalid backup metadata limits")
        if maximum_member_count < 1 or maximum_path_bytes < 16:
            raise ValueError("invalid backup member limits")
        if maximum_compression_ratio < 1:
            raise ValueError("invalid backup compression limit")
        self.data_dir = Path(data_dir).resolve(strict=False)
        _reject_broad_root(self.data_dir)
        self._integrity_key = integrity_key
        self.core_version = str(Version(core_version))
        self.maximum_file_bytes = maximum_file_bytes
        self.maximum_total_bytes = maximum_total_bytes
        self.maximum_archive_bytes = maximum_archive_bytes
        self.maximum_manifest_bytes = maximum_manifest_bytes
        self.maximum_member_count = maximum_member_count
        self.maximum_path_bytes = maximum_path_bytes
        self.maximum_compression_ratio = maximum_compression_ratio
        self.restore_intent_path = (
            self.data_dir.parent / f".{self.data_dir.name}-restore-intent.json"
        )
        self._replace = os.replace

    def create(
        self,
        output: Path,
        *,
        installation_id: str,
        operation_id: str,
        data_backend: str,
        schema_generation: int,
        recovery_epoch: int,
        confirm_offline: bool,
        include_secrets: bool = False,
        now: datetime | None = None,
    ) -> BackupManifest:
        if confirm_offline is not True:
            raise BackupError("backup creation requires explicit offline confirmation")
        _require_sqlite(data_backend)
        timestamp = _as_utc(now or datetime.now(UTC))
        output = Path(output).resolve(strict=False)
        if output == self.data_dir or self.data_dir in output.parents:
            raise BackupError("backup output must be outside the Platform data directory")
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}-", suffix=".tmp", dir=output.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        files: list[BackupFile] = []
        total_bytes = 0
        try:
            with zipfile.ZipFile(
                temporary,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=6,
                allowZip64=True,
            ) as archive:
                if self.data_dir.is_dir():
                    for source in sorted(self.data_dir.rglob("*")):
                        relative = source.relative_to(self.data_dir)
                        info = source.lstat()
                        if stat.S_ISLNK(info.st_mode):
                            raise BackupError("backup source contains a symbolic link")
                        if _excluded(relative, include_secrets=include_secrets):
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        if len(files) >= self.maximum_member_count:
                            raise BackupError("backup contains too many files")
                        relative_name = _safe_relative(
                            relative.as_posix(), maximum_path_bytes=self.maximum_path_bytes
                        )
                        digest, copied_size, copied_mode = self._write_payload(
                            archive, relative, relative_name
                        )
                        total_bytes += copied_size
                        if total_bytes > self.maximum_total_bytes:
                            raise BackupError("backup source exceeds the total size limit")
                        files.append(
                            BackupFile(
                                path=relative_name,
                                size=copied_size,
                                sha256=digest,
                                mode=copied_mode,
                            )
                        )
                manifest = BackupManifest(
                    core_version=self.core_version,
                    operation_id=operation_id,
                    installation_id=installation_id,
                    data_backend="sqlite",
                    schema_generation=schema_generation,
                    recovery_epoch=recovery_epoch,
                    created_at=timestamp,
                    includes_secrets=include_secrets,
                    files=tuple(files),
                )
                manifest_bytes = _manifest_bytes(manifest)
                if len(manifest_bytes) > self.maximum_manifest_bytes:
                    raise BackupError("backup manifest exceeds the size limit")
                archive.writestr(MANIFEST_NAME, manifest_bytes)
                archive.writestr(SIGNATURE_NAME, self._sign(manifest_bytes))
            if temporary.stat().st_size > self.maximum_archive_bytes:
                raise BackupError("backup archive exceeds the size limit")
            self._publish_archive(temporary, output)
            fsync_directory_best_effort(output.parent)
            return manifest
        except BackupError:
            raise
        except Exception:
            raise BackupError("backup could not be created") from None
        finally:
            temporary.unlink(missing_ok=True)

    def verify(self, archive_path: Path) -> BackupVerification:
        manifest, manifest_bytes = self._verified_manifest(Path(archive_path))
        return BackupVerification(
            file_count=len(manifest.files),
            total_bytes=sum(item.size for item in manifest.files),
            includes_secrets=manifest.includes_secrets,
            installation_id=manifest.installation_id,
            operation_id=manifest.operation_id,
            data_backend=manifest.data_backend,
            core_version=manifest.core_version,
            schema_generation=manifest.schema_generation,
            recovery_epoch=manifest.recovery_epoch,
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )

    def restore(
        self,
        archive_path: Path,
        *,
        confirm_offline: bool,
        expected_installation_id: str,
        expected_data_backend: str,
        expected_schema_generation: int,
        current_recovery_epoch: int,
        operation_id: str,
        actor_id: str,
        staged_validator: StagedValidator,
        post_commit: PostCommit,
    ) -> BackupManifest:
        if confirm_offline is not True:
            raise BackupError("restore requires explicit offline confirmation")
        _require_sqlite(expected_data_backend)
        parent = self.data_dir.parent
        parent.mkdir(parents=True, exist_ok=True)
        archive_copy = self._copy_archive_to_private_file(Path(archive_path), parent)
        staging: Path | None = None
        committed = False
        intent: RestoreIntent | None = None
        try:
            manifest, manifest_bytes = self._verified_manifest(archive_copy)
            manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
            archive_digest = _hash_file_bounded(
                archive_copy, maximum_bytes=self.maximum_archive_bytes
            )
            self._validate_restore_identity(
                manifest,
                expected_installation_id=expected_installation_id,
                expected_data_backend=expected_data_backend,
                expected_schema_generation=expected_schema_generation,
                current_recovery_epoch=current_recovery_epoch,
            )
            with exclusive_file_lock(self.restore_intent_path):
                existing = self._read_intent()
                if existing is not None:
                    existing = self._reconcile_intent(existing)
                    if existing.phase == "committed":
                        if (
                            existing.operation_id != operation_id
                            or existing.actor_id != actor_id
                            or existing.installation_id != manifest.installation_id
                            or existing.archive_sha256 != archive_digest
                            or existing.manifest_sha256 != manifest_digest
                        ):
                            raise BackupRecoveryPending(
                                "a committed restore requires recovery completion"
                            )
                        committed = True
                        post_commit(manifest, manifest_digest)
                        self._finalize_intent(existing)
                        return manifest
                    if existing.phase not in {"finalized", "aborted"}:
                        raise BackupRecoveryPending(
                            "an interrupted restore requires reconciliation"
                        )

                staging = Path(
                    tempfile.mkdtemp(prefix=f".{self.data_dir.name}-restore-", dir=parent)
                )
                previous = parent / f".{self.data_dir.name}-previous-{uuid4().hex}"
                self._extract_verified(archive_copy, manifest, staging)
                self._preserve_existing_secrets(
                    staging, preserve_all=not manifest.includes_secrets
                )
                marker = {
                    "operation_id": operation_id,
                    "archive_sha256": archive_digest,
                    "manifest_sha256": manifest_digest,
                }
                write_json_atomic(staging / RESTORE_MARKER_NAME, marker)
                staged_validator(staging, manifest)
                fsync_directory_best_effort(staging)
                intent = self._new_intent(
                    operation_id=operation_id,
                    actor_id=actor_id,
                    installation_id=manifest.installation_id,
                    archive_sha256=archive_digest,
                    manifest_sha256=manifest_digest,
                    staging=staging,
                    previous=previous,
                    phase="prepared",
                )
                self._write_intent(intent)
                if self.data_dir.exists():
                    self._replace(self.data_dir, previous)
                    intent = self._change_intent(intent, "previous_moved")
                    self._write_intent(intent)
                self._replace(staging, self.data_dir)
                staging = None
                committed = True
                intent = self._change_intent(intent, "committed")
                self._write_intent(intent)
                fsync_directory_best_effort(parent)
                post_commit(manifest, manifest_digest)
                self._finalize_intent(intent)
                return manifest
        except BackupRecoveryPending:
            raise
        except BackupError:
            if committed:
                raise BackupRecoveryPending(
                    "restore committed; recovery evidence is pending"
                ) from None
            self._rollback_precommit(intent)
            raise
        except Exception:
            if committed:
                raise BackupRecoveryPending(
                    "restore committed; recovery evidence is pending"
                ) from None
            self._rollback_precommit(intent)
            raise BackupError("backup restore failed; previous data was preserved") from None
        finally:
            archive_copy.unlink(missing_ok=True)
            if staging is not None and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def reconcile_restore(self) -> RestoreIntent | None:
        """Repair a crash between the two directory renames, without finalizing.

        A committed result remains pending until the caller recreates durable
        journal/checkpoint evidence and retries :meth:`restore` with the same
        operation ID and archive.
        """

        with exclusive_file_lock(self.restore_intent_path):
            intent = self._read_intent()
            return self._reconcile_intent(intent) if intent is not None else None

    def _validate_restore_identity(
        self,
        manifest: BackupManifest,
        *,
        expected_installation_id: str,
        expected_data_backend: str,
        expected_schema_generation: int,
        current_recovery_epoch: int,
    ) -> None:
        if manifest.installation_id != expected_installation_id:
            raise BackupError("backup belongs to a different installation")
        if manifest.data_backend != expected_data_backend:
            raise BackupError("backup database backend does not match")
        if manifest.schema_generation != expected_schema_generation:
            raise BackupError("backup schema generation is incompatible")
        if manifest.recovery_epoch > current_recovery_epoch:
            raise BackupError("backup recovery epoch is newer than trusted state")

    def _verified_manifest(self, archive_path: Path) -> tuple[BackupManifest, bytes]:
        try:
            with self._open_zip(archive_path) as archive:
                infos = archive.infolist()
                if len(infos) > self.maximum_member_count + 2:
                    raise BackupError("backup contains too many members")
                names = [info.filename for info in infos]
                if len(names) != len(set(names)):
                    raise BackupError("backup contains duplicate paths")
                if MANIFEST_NAME not in names or SIGNATURE_NAME not in names:
                    raise BackupError("backup manifest or signature is missing")
                by_name = {info.filename: info for info in infos}
                for info in infos:
                    self._validate_zip_info(info)
                manifest_bytes = _read_member_bounded(
                    archive,
                    by_name[MANIFEST_NAME],
                    maximum_bytes=self.maximum_manifest_bytes,
                )
                signature_bytes = _read_member_bounded(
                    archive, by_name[SIGNATURE_NAME], maximum_bytes=128
                )
                try:
                    signature = signature_bytes.decode("ascii")
                except UnicodeDecodeError:
                    raise BackupError("backup manifest signature is invalid") from None
                if not hmac.compare_digest(signature, self._sign(manifest_bytes)):
                    raise BackupError("backup manifest signature is invalid")
                manifest = BackupManifest.model_validate_json(manifest_bytes)
                if str(Version(manifest.core_version)) != self.core_version:
                    raise BackupError("backup Core version is incompatible")
                if len(manifest.files) > self.maximum_member_count:
                    raise BackupError("backup manifest contains too many files")
                paths = [item.path for item in manifest.files]
                if len(paths) != len(set(paths)):
                    raise BackupError("backup manifest contains duplicate paths")
                expected_payload = {PAYLOAD_PREFIX + item.path for item in manifest.files}
                if set(names) != expected_payload | {MANIFEST_NAME, SIGNATURE_NAME}:
                    raise BackupError("backup members do not match the manifest")
                total = 0
                for item in manifest.files:
                    safe_path = _safe_relative(
                        item.path, maximum_path_bytes=self.maximum_path_bytes
                    )
                    if safe_path != item.path:
                        raise BackupError("backup manifest path is not canonical")
                    info = by_name[PAYLOAD_PREFIX + item.path]
                    if info.file_size != item.size:
                        raise BackupError("backup payload size is invalid")
                    digest = hashlib.sha256()
                    with archive.open(info, mode="r") as source:
                        copied = _copy_and_hash(
                            source,
                            None,
                            digest,
                            maximum_bytes=self.maximum_file_bytes,
                        )
                    total += copied
                    if total > self.maximum_total_bytes:
                        raise BackupError("backup exceeds the total size limit")
                    if copied != item.size or digest.hexdigest() != item.sha256:
                        raise BackupError("backup payload checksum is invalid")
                return manifest, manifest_bytes
        except BackupError:
            raise
        except Exception:
            raise BackupError("backup could not be verified") from None

    def _validate_zip_info(self, info: zipfile.ZipInfo) -> None:
        if len(info.filename.encode("utf-8")) > self.maximum_path_bytes + len(PAYLOAD_PREFIX):
            raise BackupError("backup member path exceeds the size limit")
        if info.flag_bits & 0x1:
            raise BackupError("encrypted backup members are unsupported")
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise BackupError("unsupported backup compression method")
        if _zip_member_is_link(info):
            raise BackupError("backup contains a symbolic link")
        limit = self.maximum_manifest_bytes if info.filename == MANIFEST_NAME else (
            128 if info.filename == SIGNATURE_NAME else self.maximum_file_bytes
        )
        if info.file_size > limit:
            raise BackupError("backup member exceeds the size limit")
        if info.file_size > max(
            4096, info.compress_size * self.maximum_compression_ratio
        ):
            raise BackupError("backup member exceeds the compression ratio limit")

    def _extract_verified(
        self, archive_path: Path, manifest: BackupManifest, staging: Path
    ) -> None:
        with self._open_zip(archive_path) as archive:
            for item in manifest.files:
                target = staging.joinpath(*PurePosixPath(item.path).parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                digest = hashlib.sha256()
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(target, flags, 0o600)
                try:
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise BackupError("restore target is not a regular file")
                    with archive.open(PAYLOAD_PREFIX + item.path, mode="r") as source:
                        with os.fdopen(descriptor, "wb", closefd=False) as destination:
                            size = _copy_and_hash(
                                source,
                                destination,
                                digest,
                                maximum_bytes=self.maximum_file_bytes,
                            )
                            destination.flush()
                            os.fsync(destination.fileno())
                finally:
                    os.close(descriptor)
                if size != item.size or digest.hexdigest() != item.sha256:
                    raise BackupError("backup payload changed during restore")
                os.chmod(target, _restored_mode(item.mode))

    def _write_payload(
        self, archive: zipfile.ZipFile, relative: Path, relative_name: str
    ) -> tuple[str, int, int]:
        digest = hashlib.sha256()
        info = zipfile.ZipInfo(PAYLOAD_PREFIX + relative_name)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o100600 & 0xFFFF) << 16
        with _open_regular_beneath(self.data_dir, relative) as (source, source_info):
            if source_info.st_size > self.maximum_file_bytes:
                raise BackupError("backup source file exceeds the size limit")
            with archive.open(info, mode="w") as destination:
                copied = _copy_and_hash(
                    source, destination, digest, maximum_bytes=self.maximum_file_bytes
                )
        return digest.hexdigest(), copied, stat.S_IMODE(source_info.st_mode)

    def _preserve_existing_secrets(self, staging: Path, *, preserve_all: bool) -> None:
        source_root = self.data_dir / "secrets"
        if not source_root.is_dir():
            return
        destination_root = staging / "secrets"
        destination_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        preserved_files = 0
        preserved_bytes = 0
        for source in source_root.rglob("*"):
            relative = source.relative_to(source_root)
            should_preserve = preserve_all or relative.parts[:1] == ("platform",)
            if not should_preserve:
                continue
            info = source.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise BackupError("existing secret storage contains a symbolic link")
            destination = destination_root / relative
            if stat.S_ISDIR(info.st_mode):
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(destination, 0o700)
            elif stat.S_ISREG(info.st_mode):
                if preserved_files >= self.maximum_member_count:
                    raise BackupError("existing secret storage contains too many files")
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with _open_regular_beneath(source_root, relative) as (
                    stream,
                    source_info,
                ):
                    if source_info.st_size > self.maximum_file_bytes:
                        raise BackupError("existing secret file exceeds the size limit")
                    if preserved_bytes + source_info.st_size > self.maximum_total_bytes:
                        raise BackupError("existing secret storage exceeds the total size limit")
                    descriptor = os.open(
                        destination,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_TRUNC
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                    )
                    try:
                        with os.fdopen(descriptor, "wb", closefd=False) as target:
                            copied = _copy_and_hash(
                                stream,
                                target,
                                hashlib.sha256(),
                                maximum_bytes=self.maximum_file_bytes,
                            )
                            target.flush()
                            os.fsync(target.fileno())
                    finally:
                        os.close(descriptor)
                preserved_files += 1
                preserved_bytes += copied
                os.chmod(destination, 0o600)
            else:
                raise BackupError("existing secret storage contains a special file")

    def _copy_archive_to_private_file(self, source: Path, parent: Path) -> Path:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{self.data_dir.name}-archive-", suffix=".zip", dir=parent
        )
        target = Path(name)
        try:
            digest = hashlib.sha256()
            with _open_regular_path(source) as stream:
                with os.fdopen(descriptor, "wb", closefd=False) as output:
                    _copy_and_hash(
                        stream,
                        output,
                        digest,
                        maximum_bytes=self.maximum_archive_bytes,
                    )
                    output.flush()
                    os.fsync(output.fileno())
            os.close(descriptor)
            descriptor = -1
            return target
        except Exception:
            target.unlink(missing_ok=True)
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _publish_archive(self, temporary: Path, output: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(temporary, flags)
        except OSError:
            raise BackupError("backup output cannot be published safely") from None
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise BackupError("backup output cannot be published safely")
            os.fsync(descriptor)
            self._replace(temporary, output)
            try:
                after = os.fstat(descriptor)
                current = os.stat(output, follow_symlinks=False)
            except OSError:
                raise BackupError("backup output changed while it was published") from None
            if (
                not stat.S_ISREG(after.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or after.st_dev != before.st_dev
                or after.st_ino != before.st_ino
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or current.st_dev != after.st_dev
                or current.st_ino != after.st_ino
                or current.st_size != after.st_size
                or current.st_mtime_ns != after.st_mtime_ns
            ):
                raise BackupError("backup output changed while it was published")
        finally:
            os.close(descriptor)

    @contextmanager
    def _open_zip(self, path: Path) -> Iterator[zipfile.ZipFile]:
        with _open_regular_path(path) as stream:
            info = os.fstat(stream.fileno())
            if info.st_size > self.maximum_archive_bytes:
                raise BackupError("backup archive exceeds the size limit")
            with zipfile.ZipFile(stream, mode="r") as archive:
                yield archive

    def _new_intent(
        self,
        *,
        operation_id: str,
        actor_id: str,
        installation_id: str,
        archive_sha256: str,
        manifest_sha256: str,
        staging: Path,
        previous: Path,
        phase: str,
    ) -> RestoreIntent:
        body = {
            "format_version": 1,
            "operation_id": operation_id,
            "actor_id": actor_id,
            "installation_id": installation_id,
            "archive_sha256": archive_sha256,
            "manifest_sha256": manifest_sha256,
            "staging_name": staging.name,
            "previous_name": previous.name,
            "phase": phase,
            "recorded_at": datetime.now(UTC),
        }
        return self._signed_intent(body)

    def _change_intent(self, intent: RestoreIntent, phase: str) -> RestoreIntent:
        body = intent.model_dump(mode="json", exclude={"signature"})
        body.update({"phase": phase, "recorded_at": datetime.now(UTC)})
        return self._signed_intent(body)

    def _signed_intent(self, body: dict) -> RestoreIntent:
        normalized = RestoreIntent.model_validate(
            {**body, "signature": "0" * 64}
        ).model_dump(mode="json", exclude={"signature"})
        return RestoreIntent.model_validate(
            {**normalized, "signature": self._sign_json(normalized)}
        )

    def _write_intent(self, intent: RestoreIntent) -> None:
        write_json_atomic(self.restore_intent_path, intent.model_dump(mode="json"))

    def _read_intent(self) -> RestoreIntent | None:
        try:
            os.lstat(self.restore_intent_path)
        except FileNotFoundError:
            return None
        except OSError:
            raise BackupRecoveryPending("restore intent cannot be verified") from None
        try:
            with _open_regular_path(self.restore_intent_path) as stream:
                payload = stream.read(_RESTORE_INTENT_MAX_BYTES + 1)
        except BackupError:
            raise BackupRecoveryPending("restore intent cannot be verified") from None
        if len(payload) > _RESTORE_INTENT_MAX_BYTES:
            raise BackupRecoveryPending("restore intent exceeds the size limit")
        try:
            intent = RestoreIntent.model_validate_json(payload)
        except Exception:
            raise BackupRecoveryPending("restore intent cannot be verified") from None
        body = intent.model_dump(mode="json", exclude={"signature"})
        if not hmac.compare_digest(intent.signature, self._sign_json(body)):
            raise BackupRecoveryPending("restore intent signature is invalid")
        self._intent_paths(intent)
        return intent

    def _intent_paths(self, intent: RestoreIntent) -> tuple[Path, Path]:
        parent = self.data_dir.parent
        staging = parent / intent.staging_name
        previous = parent / intent.previous_name
        if (
            staging.parent != parent
            or previous.parent != parent
            or not staging.name.startswith(f".{self.data_dir.name}-restore-")
            or not previous.name.startswith(f".{self.data_dir.name}-previous-")
        ):
            raise BackupRecoveryPending("restore intent paths are invalid")
        return staging, previous

    def _reconcile_intent(self, intent: RestoreIntent) -> RestoreIntent:
        staging, previous = self._intent_paths(intent)
        if intent.phase in {"finalized", "aborted"}:
            self._cleanup_path(staging)
            self._cleanup_path(previous)
            self._cleanup_restore_marker()
            fsync_directory_best_effort(self.data_dir.parent)
            return intent
        marker_matches = self._restore_marker_matches(intent)
        if intent.phase in {"prepared", "previous_moved"} and marker_matches:
            committed = self._change_intent(intent, "committed")
            self._write_intent(committed)
            return committed
        if intent.phase in {"prepared", "previous_moved"}:
            data_exists = self.data_dir.exists()
            staging_exists = staging.exists()
            previous_exists = previous.exists()
            if data_exists and not staging_exists:
                raise BackupRecoveryPending("restore commit state is uncertain")
            if not data_exists and previous_exists:
                self._replace(previous, self.data_dir)
            if not self.data_dir.exists():
                raise BackupRecoveryPending("restore reconciliation cannot locate data")
            self._cleanup_path(staging)
            aborted = self._change_intent(intent, "aborted")
            self._write_intent(aborted)
            fsync_directory_best_effort(self.data_dir.parent)
            return aborted
        if intent.phase == "committed":
            if not self.data_dir.exists():
                raise BackupRecoveryPending("committed restore data is unavailable")
            if not marker_matches:
                raise BackupRecoveryPending(
                    "committed restore marker is missing or invalid"
                )
        return intent

    def _restore_marker_matches(self, intent: RestoreIntent) -> bool:
        marker = self.data_dir / RESTORE_MARKER_NAME
        try:
            with _open_regular_path(marker) as stream:
                payload = stream.read(_RESTORE_MARKER_MAX_BYTES + 1)
            if len(payload) > _RESTORE_MARKER_MAX_BYTES:
                return False
            value = json.loads(payload)
            return value == {
                "operation_id": intent.operation_id,
                "archive_sha256": intent.archive_sha256,
                "manifest_sha256": intent.manifest_sha256,
            }
        except Exception:
            return False

    def _cleanup_restore_marker(self) -> None:
        try:
            (self.data_dir / RESTORE_MARKER_NAME).unlink(missing_ok=True)
        except OSError:
            return
        fsync_directory_best_effort(self.data_dir)

    def _finalize_intent(self, intent: RestoreIntent) -> None:
        finalized = self._change_intent(intent, "finalized")
        self._write_intent(finalized)
        staging, previous = self._intent_paths(finalized)
        # The directory switch and recovery evidence are already durable.
        # Cleanup cannot replace that successful outcome and is reconciled on
        # the next operation if it fails.
        self._cleanup_path(staging)
        self._cleanup_path(previous)
        self._cleanup_restore_marker()
        fsync_directory_best_effort(self.data_dir.parent)

    def _rollback_precommit(self, intent: RestoreIntent | None) -> None:
        if intent is None:
            return
        try:
            staging, previous = self._intent_paths(intent)
            if not self.data_dir.exists() and previous.exists():
                self._replace(previous, self.data_dir)
            self._cleanup_path(staging)
            aborted = self._change_intent(intent, "aborted")
            self._write_intent(aborted)
        except Exception as error:
            raise BackupRecoveryPending(
                "restore rollback requires operator reconciliation"
            ) from error

    @staticmethod
    def _cleanup_path(path: Path) -> None:
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
        except OSError:
            pass

    def _sign(self, manifest_bytes: bytes) -> str:
        return hmac.new(self._integrity_key, manifest_bytes, hashlib.sha256).hexdigest()

    def _sign_json(self, value: dict) -> str:
        return self._sign(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )


def _copy_and_hash(
    source: BinaryIO,
    destination: BinaryIO | None,
    digest,
    *,
    maximum_bytes: int,
) -> int:
    copied = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        copied += len(chunk)
        if copied > maximum_bytes:
            raise BackupError("backup member exceeds the size limit")
        digest.update(chunk)
        if destination is not None:
            destination.write(chunk)
    return copied


def _manifest_bytes(manifest: BackupManifest) -> bytes:
    return json.dumps(
        manifest.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _safe_relative(value: str, *, maximum_path_bytes: int) -> str:
    path = PurePosixPath(value)
    if (
        len(value.encode("utf-8")) > maximum_path_bytes
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in value
        or "\x00" in value
    ):
        raise BackupError("backup contains an unsafe relative path")
    canonical = path.as_posix()
    if canonical.startswith(PAYLOAD_PREFIX):
        raise BackupError("backup payload path uses a reserved prefix")
    return canonical


def _excluded(path: Path, *, include_secrets: bool) -> bool:
    if not path.parts:
        return True
    if path.parts[0] == "secrets":
        if not include_secrets:
            return True
        if len(path.parts) >= 2 and path.parts[1] == "platform":
            return True
        if path.name in _PROTECTED_PLATFORM_SECRET_NAMES:
            return True
    name = path.name
    if name == INTEGRITY_MARKER_FILENAME:
        return False
    return name.endswith(".lock") or name.startswith(".") or name.endswith(".tmp")


def _zip_member_is_link(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _restored_mode(mode: int) -> int:
    executable = mode & 0o100
    return 0o700 if executable else 0o600


def _reject_broad_root(path: Path) -> None:
    if path == Path(path.anchor) or path == Path.home().resolve(strict=False):
        raise ValueError("backup data directory is too broad")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("backup timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _require_sqlite(value: str) -> None:
    if value != "sqlite":
        raise BackupError(
            "filesystem backup supports SQLite only; PostgreSQL requires its dedicated adapter"
        )


def _read_member_bounded(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, *, maximum_bytes: int
) -> bytes:
    with archive.open(info, mode="r") as stream:
        value = stream.read(maximum_bytes + 1)
    if len(value) > maximum_bytes:
        raise BackupError("backup metadata exceeds the size limit")
    return value


@contextmanager
def _open_regular_path(path: Path) -> Iterator[BinaryIO]:
    target = Path(path)
    if not hasattr(os, "O_NOFOLLOW") and target.is_symlink():
        raise BackupError("backup input is unavailable or unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError:
        raise BackupError("backup input is unavailable or unsafe") from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BackupError("backup input is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            yield stream
        try:
            after = os.fstat(descriptor)
            current = os.stat(target, follow_symlinks=False)
        except OSError:
            raise BackupError("backup input changed while it was read") from None
        if (
            not stat.S_ISREG(after.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or current.st_dev != after.st_dev
            or current.st_ino != after.st_ino
            or current.st_size != after.st_size
            or current.st_mtime_ns != after.st_mtime_ns
            or current.st_ctime_ns != after.st_ctime_ns
        ):
            raise BackupError("backup input changed while it was read")
    finally:
        os.close(descriptor)


@contextmanager
def _open_regular_beneath(root: Path, relative: Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Open a stable regular file beneath root without following path swaps."""

    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise BackupError("backup source path is unsafe")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow | cloexec
    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_descriptor = os.open(parts[-1], os.O_RDONLY | nofollow | cloexec, dir_fd=current)
        descriptors.append(file_descriptor)
        info = os.fstat(file_descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise BackupError("backup source is not a regular file")
        with os.fdopen(file_descriptor, "rb", closefd=False) as stream:
            yield stream, info
            try:
                after = os.fstat(file_descriptor)
            except OSError:
                raise BackupError("backup source changed while it was read") from None
            if (
                after.st_dev != info.st_dev
                or after.st_ino != info.st_ino
                or after.st_size != info.st_size
                or after.st_mtime_ns != info.st_mtime_ns
                or after.st_ctime_ns != info.st_ctime_ns
            ):
                raise BackupError("backup source changed while it was read")
    except BackupError:
        raise
    except OSError:
        raise BackupError("backup source changed or is unsafe") from None
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _hash_file_bounded(path: Path, *, maximum_bytes: int) -> str:
    digest = hashlib.sha256()
    with _open_regular_path(path) as stream:
        _copy_and_hash(stream, None, digest, maximum_bytes=maximum_bytes)
    return digest.hexdigest()