"""Independent monotonic checkpoints for audit and operation journal heads."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Mapping, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .storage import exclusive_file_lock, fsync_directory_best_effort


GENESIS_HASH = "0" * 64
_MAX_CHECKPOINT_RECORD_BYTES = 16 * 1024
_INSTALLATION_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_ACTOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:-]{1,127}$")


class IntegrityCheckpointError(RuntimeError):
    """An integrity checkpoint is missing, corrupt or non-monotonic."""


class JournalKind(StrEnum):
    AUDIT = "audit"
    OPERATIONS = "operations"


class IntegrityCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1, 2] = 1
    sequence: int = Field(ge=1)
    installation_id: str
    journal: JournalKind
    event_count: int = Field(ge=0)
    head_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    recorded_at: datetime
    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    recovery_epoch: int = Field(default=0, ge=0)
    recovery_operation_id: str | None = None
    recovery_actor_id: str | None = None
    recovery_manifest_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )


class CheckpointProvider(Protocol):
    def checkpoint(
        self,
        installation_id: str,
        journal: JournalKind,
        *,
        event_count: int,
        head_hash: str,
        now: datetime | None = None,
        expected_recovery_epoch: int | None = None,
    ) -> IntegrityCheckpoint: ...

    def current_recovery_epoch(self, installation_id: str) -> int: ...

    def latest(
        self, installation_id: str, journal: JournalKind
    ) -> IntegrityCheckpoint | None: ...

    def verify_current(
        self,
        installation_id: str,
        journal: JournalKind,
        *,
        event_count: int,
        head_hash: str,
    ) -> IntegrityCheckpoint: ...


class FileCheckpointStore:
    """Reference append-only checkpoint provider stored outside journal data."""

    def __init__(self, path: Path, *, integrity_key: bytes) -> None:
        if len(integrity_key) < 32:
            raise ValueError("checkpoint integrity key must contain at least 32 bytes")
        self.path = Path(path)
        self._integrity_key = integrity_key

    def checkpoint(
        self,
        installation_id: str,
        journal: JournalKind,
        *,
        event_count: int,
        head_hash: str,
        now: datetime | None = None,
        expected_recovery_epoch: int | None = None,
    ) -> IntegrityCheckpoint:
        installation_id = _validate_installation_id(installation_id)
        journal = JournalKind(journal)
        event_count, head_hash = _validate_head(event_count, head_hash)
        expected_recovery_epoch = _validate_expected_recovery_epoch(
            expected_recovery_epoch
        )
        timestamp = _as_utc(now or datetime.now(UTC))
        with exclusive_file_lock(self.path):
            records = self._read_and_verify()
            recovery_epoch = _current_recovery_epoch(records, installation_id)
            if (
                expected_recovery_epoch is not None
                and recovery_epoch != expected_recovery_epoch
            ):
                raise IntegrityCheckpointError(
                    "recovery epoch changed while checkpointing"
                )
            existing = _latest(records, installation_id, journal)
            if existing is not None:
                if (
                    existing.event_count == event_count
                    and hmac.compare_digest(existing.head_hash, head_hash)
                ):
                    return existing
                if event_count <= existing.event_count:
                    raise IntegrityCheckpointError(
                        "integrity checkpoint cannot move backward"
                    )
            previous_hash = (
                records[-1].checkpoint_hash if records else GENESIS_HASH
            )
            body = {
                "format_version": 2,
                "sequence": len(records) + 1,
                "installation_id": installation_id,
                "journal": journal.value,
                "event_count": event_count,
                "head_hash": head_hash,
                "recorded_at": timestamp.isoformat(),
                "previous_hash": previous_hash,
                "recovery_epoch": recovery_epoch,
                "recovery_operation_id": None,
                "recovery_actor_id": None,
                "recovery_manifest_sha256": None,
            }
            record = IntegrityCheckpoint.model_validate(
                {**body, "checkpoint_hash": self._sign(body)}
            )
            self._append(record)
            return record

    def current_recovery_epoch(self, installation_id: str) -> int:
        """Return the verified recovery generation for an installation."""

        installation_id = _validate_installation_id(installation_id)
        with exclusive_file_lock(self.path):
            return _current_recovery_epoch(
                self._read_and_verify(),
                installation_id,
            )

    def recover(
        self,
        installation_id: str,
        heads: Mapping[JournalKind, tuple[int, str]],
        *,
        operation_id: str,
        actor_id: str,
        manifest_sha256: str,
        now: datetime | None = None,
    ) -> tuple[IntegrityCheckpoint, IntegrityCheckpoint]:
        """Rebase both restored journal heads into one signed recovery epoch.

        The two records are serialized in one append and fsync. A partial write
        therefore fails closed on the next verification instead of silently
        accepting only one restored journal. Re-entry with the same operation
        ID and exact heads is idempotent only while that recovery pair remains
        the current trusted head set.
        """

        installation_id = _validate_installation_id(installation_id)
        operation_id = _validate_operation_id(operation_id)
        actor_id = _validate_actor_id(actor_id)
        if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
            raise ValueError("invalid recovery manifest digest")
        normalized: dict[JournalKind, tuple[int, str]] = {}
        for journal in JournalKind:
            try:
                event_count, head_hash = heads[journal]
            except (KeyError, TypeError):
                raise ValueError("recovery requires both journal heads") from None
            normalized[journal] = _validate_head(event_count, head_hash)
        if len(heads) != len(JournalKind):
            raise ValueError("recovery contains an unknown journal head")
        timestamp = _as_utc(now or datetime.now(UTC))

        with exclusive_file_lock(self.path):
            records = self._read_and_verify()
            prior = [
                record
                for record in records
                if record.installation_id == installation_id
                and record.recovery_operation_id == operation_id
            ]
            if prior:
                if len(prior) != len(JournalKind):
                    raise IntegrityCheckpointError(
                        "recovery checkpoint set is incomplete"
                    )
                by_journal = {record.journal: record for record in prior}
                if set(by_journal) != set(JournalKind):
                    raise IntegrityCheckpointError(
                        "recovery checkpoint set is invalid"
                    )
                for journal, record in by_journal.items():
                    latest = _latest(records, installation_id, journal)
                    if latest is None or latest.sequence != record.sequence:
                        raise IntegrityCheckpointError(
                            "recovery operation is no longer current"
                        )
                for journal, (event_count, head_hash) in normalized.items():
                    record = by_journal[journal]
                    if (
                        record.event_count != event_count
                        or not hmac.compare_digest(record.head_hash, head_hash)
                        or record.recovery_actor_id != actor_id
                        or record.recovery_manifest_sha256 != manifest_sha256
                    ):
                        raise IntegrityCheckpointError(
                            "recovery operation ID is bound to different evidence"
                        )
                return by_journal[JournalKind.AUDIT], by_journal[JournalKind.OPERATIONS]

            recovery_epoch = _current_recovery_epoch(records, installation_id) + 1
            previous_hash = records[-1].checkpoint_hash if records else GENESIS_HASH
            created: list[IntegrityCheckpoint] = []
            for journal in JournalKind:
                event_count, head_hash = normalized[journal]
                body = {
                    "format_version": 2,
                    "sequence": len(records) + len(created) + 1,
                    "installation_id": installation_id,
                    "journal": journal.value,
                    "event_count": event_count,
                    "head_hash": head_hash,
                    "recorded_at": timestamp.isoformat(),
                    "previous_hash": previous_hash,
                    "recovery_epoch": recovery_epoch,
                    "recovery_operation_id": operation_id,
                    "recovery_actor_id": actor_id,
                    "recovery_manifest_sha256": manifest_sha256,
                }
                record = IntegrityCheckpoint.model_validate(
                    {**body, "checkpoint_hash": self._sign(body)}
                )
                created.append(record)
                previous_hash = record.checkpoint_hash
            self._append_many(created)
            return created[0], created[1]

    def latest(
        self, installation_id: str, journal: JournalKind
    ) -> IntegrityCheckpoint | None:
        installation_id = _validate_installation_id(installation_id)
        journal = JournalKind(journal)
        with exclusive_file_lock(self.path):
            return _latest(self._read_and_verify(), installation_id, journal)

    def verify_current(
        self,
        installation_id: str,
        journal: JournalKind,
        *,
        event_count: int,
        head_hash: str,
    ) -> IntegrityCheckpoint:
        event_count, head_hash = _validate_head(event_count, head_hash)
        record = self.latest(installation_id, journal)
        if record is None:
            raise IntegrityCheckpointError("trusted integrity checkpoint is missing")
        if record.event_count != event_count or not hmac.compare_digest(
            record.head_hash, head_hash
        ):
            raise IntegrityCheckpointError(
                "journal head does not match the trusted integrity checkpoint"
            )
        return record

    def verify(self) -> tuple[IntegrityCheckpoint, ...]:
        with exclusive_file_lock(self.path):
            return tuple(self._read_and_verify())

    def _read_and_verify(self) -> list[IntegrityCheckpoint]:
        try:
            descriptor = _open_checkpoint_readonly(self.path)
        except FileNotFoundError:
            return []
        records: list[IntegrityCheckpoint] = []
        previous_hash = GENESIS_HASH
        try:
            initial = os.fstat(descriptor)
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                line_number = 0
                while True:
                    line = stream.readline(_MAX_CHECKPOINT_RECORD_BYTES + 1)
                    if not line:
                        break
                    line_number += 1
                    if len(line) > _MAX_CHECKPOINT_RECORD_BYTES:
                        raise IntegrityCheckpointError(
                            "integrity checkpoint record exceeds the size limit"
                        )
                    if not line.endswith(b"\n"):
                        raise IntegrityCheckpointError(
                            "integrity checkpoint has an incomplete record"
                        )
                    record = IntegrityCheckpoint.model_validate_json(line)
                    if record.sequence != line_number:
                        raise IntegrityCheckpointError(
                            "integrity checkpoint sequence is invalid"
                        )
                    if not hmac.compare_digest(record.previous_hash, previous_hash):
                        raise IntegrityCheckpointError(
                            "integrity checkpoint chain is broken"
                        )
                    body = _checkpoint_body(record)
                    if not hmac.compare_digest(
                        record.checkpoint_hash,
                        self._sign(body),
                    ):
                        raise IntegrityCheckpointError(
                            "integrity checkpoint signature is invalid"
                        )
                    previous_hash = record.checkpoint_hash
                    records.append(record)
            _require_stable_read(self.path, descriptor, initial)
            _validate_checkpoint_records(records)
        except IntegrityCheckpointError:
            raise
        except Exception:
            raise IntegrityCheckpointError(
                "integrity checkpoint could not be verified"
            ) from None
        finally:
            os.close(descriptor)
        return records

    def _append(self, record: IntegrityCheckpoint) -> None:
        self._append_many((record,))

    def _append_many(self, records) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        was_present = self.path.exists()
        payload = "".join(
            json.dumps(
                record.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
            for record in records
        ).encode("utf-8")
        if not hasattr(os, "O_NOFOLLOW") and self.path.is_symlink():
            raise IntegrityCheckpointError("integrity checkpoint path is unsafe")
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError:
            raise IntegrityCheckpointError(
                "integrity checkpoint path cannot be opened safely"
            ) from None
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise IntegrityCheckpointError(
                    "integrity checkpoint path is not a regular file"
                )
            _enforce_owner_only_permissions(descriptor)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("checkpoint append did not make progress")
                view = view[written:]
            os.fsync(descriptor)
            try:
                after = os.fstat(descriptor)
                current = os.stat(self.path, follow_symlinks=False)
            except OSError:
                raise IntegrityCheckpointError(
                    "integrity checkpoint changed while it was appended"
                ) from None
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if (
                not stat.S_ISREG(after.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or after.st_dev != before.st_dev
                or after.st_ino != before.st_ino
                or after.st_size != before.st_size + len(payload)
                or any(getattr(current, field) != getattr(after, field) for field in fields)
            ):
                raise IntegrityCheckpointError(
                    "integrity checkpoint changed while it was appended"
                )
        finally:
            os.close(descriptor)
        if not was_present:
            fsync_directory_best_effort(self.path.parent)

    def _sign(self, body: dict) -> str:
        return sign_integrity_checkpoint(self._integrity_key, body)


def sign_integrity_checkpoint(integrity_key: bytes, body: Mapping) -> str:
    payload = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hmac.new(integrity_key, payload, hashlib.sha256).hexdigest()


def _latest(
    records: list[IntegrityCheckpoint],
    installation_id: str,
    journal: JournalKind,
) -> IntegrityCheckpoint | None:
    return next(
        (
            record
            for record in reversed(records)
            if record.installation_id == installation_id and record.journal == journal
        ),
        None,
    )


def _checkpoint_body(record: IntegrityCheckpoint) -> dict:
    body = {
        "sequence": record.sequence,
        "installation_id": record.installation_id,
        "journal": record.journal.value,
        "event_count": record.event_count,
        "head_hash": record.head_hash,
        "recorded_at": record.recorded_at.isoformat(),
        "previous_hash": record.previous_hash,
    }
    if record.format_version >= 2:
        body.update(
            {
                "format_version": record.format_version,
                "recovery_epoch": record.recovery_epoch,
                "recovery_operation_id": record.recovery_operation_id,
                "recovery_actor_id": record.recovery_actor_id,
                "recovery_manifest_sha256": record.recovery_manifest_sha256,
            }
        )
    return body


def _validate_checkpoint_records(records: list[IntegrityCheckpoint]) -> None:
    recovery_groups: dict[tuple[str, str], list[IntegrityCheckpoint]] = {}
    latest_epoch: dict[str, int] = {}
    epoch_operations: dict[tuple[str, int], str] = {}

    for record in records:
        try:
            _validate_installation_id(record.installation_id)
            _as_utc(record.recorded_at)
        except ValueError:
            raise IntegrityCheckpointError(
                "integrity checkpoint metadata is invalid"
            ) from None

        prior_epoch = latest_epoch.get(record.installation_id, 0)
        if record.recovery_epoch < prior_epoch:
            raise IntegrityCheckpointError(
                "integrity checkpoint recovery epoch moved backward"
            )
        latest_epoch[record.installation_id] = record.recovery_epoch

        if record.format_version == 1:
            if (
                record.recovery_epoch != 0
                or record.recovery_operation_id is not None
                or record.recovery_actor_id is not None
                or record.recovery_manifest_sha256 is not None
            ):
                raise IntegrityCheckpointError(
                    "format version 1 checkpoint contains unsigned recovery metadata"
                )
            continue

        operation_id = record.recovery_operation_id
        actor_id = record.recovery_actor_id
        manifest_sha256 = record.recovery_manifest_sha256
        if operation_id is None:
            if actor_id is not None or manifest_sha256 is not None:
                raise IntegrityCheckpointError(
                    "recovery checkpoint metadata is incomplete"
                )
            continue
        if record.recovery_epoch < 1 or actor_id is None or manifest_sha256 is None:
            raise IntegrityCheckpointError(
                "recovery checkpoint metadata is incomplete"
            )
        try:
            _validate_operation_id(operation_id)
            _validate_actor_id(actor_id)
        except ValueError:
            raise IntegrityCheckpointError(
                "recovery checkpoint metadata is invalid"
            ) from None

        epoch_key = (record.installation_id, record.recovery_epoch)
        existing_operation = epoch_operations.setdefault(epoch_key, operation_id)
        if existing_operation != operation_id:
            raise IntegrityCheckpointError(
                "recovery epoch is bound to multiple operations"
            )
        recovery_groups.setdefault(
            (record.installation_id, operation_id), []
        ).append(record)

    for group in recovery_groups.values():
        if len(group) != len(JournalKind):
            raise IntegrityCheckpointError("recovery checkpoint set is incomplete")
        by_journal = {record.journal: record for record in group}
        if set(by_journal) != set(JournalKind):
            raise IntegrityCheckpointError("recovery checkpoint set is invalid")
        first = group[0]
        if any(
            record.recovery_epoch != first.recovery_epoch
            or record.recovery_actor_id != first.recovery_actor_id
            or record.recovery_manifest_sha256 != first.recovery_manifest_sha256
            for record in group[1:]
        ):
            raise IntegrityCheckpointError(
                "recovery checkpoint evidence is inconsistent"
            )
        sequences = sorted(record.sequence for record in group)
        if sequences[-1] != sequences[0] + 1:
            raise IntegrityCheckpointError(
                "recovery checkpoint set is not contiguous"
            )


def _current_recovery_epoch(
    records: list[IntegrityCheckpoint], installation_id: str
) -> int:
    relevant = [
        record for record in records if record.installation_id == installation_id
    ]
    if not relevant:
        return 0
    latest_by_journal = {
        journal: _latest(records, installation_id, journal) for journal in JournalKind
    }
    epochs = {
        record.recovery_epoch
        for record in latest_by_journal.values()
        if record is not None
    }
    if len(epochs) > 1:
        raise IntegrityCheckpointError("journal recovery epochs disagree")
    return max(record.recovery_epoch for record in relevant)


def _validate_installation_id(value: str) -> str:
    if not isinstance(value, str) or not _INSTALLATION_ID.fullmatch(value):
        raise ValueError("invalid checkpoint installation id")
    return value


def _validate_operation_id(value: str) -> str:
    if not isinstance(value, str) or not _OPERATION_ID.fullmatch(value):
        raise ValueError("invalid recovery operation id")
    return value


def _validate_actor_id(value: str) -> str:
    if not isinstance(value, str) or not _ACTOR_ID.fullmatch(value):
        raise ValueError("invalid recovery actor id")
    return value


def _validate_head(event_count: int, head_hash: str) -> tuple[int, str]:
    if not isinstance(event_count, int) or event_count < 0:
        raise ValueError("checkpoint event count must be non-negative")
    if not isinstance(head_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", head_hash):
        raise ValueError("invalid checkpoint head hash")
    return event_count, head_hash


def _validate_expected_recovery_epoch(value: int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("expected recovery epoch must be a non-negative integer")
    return value


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("checkpoint timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _open_checkpoint_readonly(path: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW") and path.is_symlink():
        raise IntegrityCheckpointError("integrity checkpoint path is unsafe")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError:
        raise IntegrityCheckpointError(
            "integrity checkpoint path cannot be opened safely"
        ) from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise IntegrityCheckpointError(
                "integrity checkpoint path is not a regular file"
            )
        _enforce_owner_only_permissions(descriptor)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _require_stable_read(path: Path, descriptor: int, initial: os.stat_result) -> None:
    try:
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        raise IntegrityCheckpointError(
            "integrity checkpoint changed while it was read"
        ) from None
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        not stat.S_ISREG(current.st_mode)
        or any(getattr(after, field) != getattr(initial, field) for field in fields)
        or any(getattr(current, field) != getattr(after, field) for field in fields)
    ):
        raise IntegrityCheckpointError(
            "integrity checkpoint changed while it was read"
        )


def _enforce_owner_only_permissions(descriptor: int) -> None:
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(descriptor, 0o600)
