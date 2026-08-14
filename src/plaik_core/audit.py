"""Append-only, tamper-evident audit journal.

Every event is chained with HMAC-SHA256.  The integrity key must be supplied by
the deployment secret store and is never persisted beside the journal.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterator, Mapping

from pydantic import BaseModel, ConfigDict

from .storage import fsync_directory_best_effort


GENESIS_HASH = "0" * 64
_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
_SENSITIVE_PARTS = {
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
}
_SENSITIVE_COMPACT_KEYS = {
    "accesstoken",
    "apikey",
    "clientsecret",
    "privatekey",
    "refreshtoken",
    "sessioncookie",
}
MAX_AUDIT_METADATA_BYTES = 64 * 1024
MAX_AUDIT_METADATA_DEPTH = 16
MAX_AUDIT_METADATA_KEYS = 512
MAX_AUDIT_METADATA_ITEMS = 4096
MAX_AUDIT_METADATA_KEY_BYTES = 128
MAX_AUDIT_RECORD_BYTES = 128 * 1024


class AuditIntegrityError(RuntimeError):
    """The audit journal is malformed or its integrity chain does not verify."""


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int
    occurred_at: datetime
    actor_id: str | None
    action: str
    target_type: str
    target_id: str | None
    outcome: AuditOutcome
    metadata: dict[str, Any]
    previous_hash: str
    event_hash: str


class AuditVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_count: int
    head_hash: str


class AuditLog:
    """Serialize bounded audit events to an append-only JSONL hash chain.

    The file is protected against concurrent writers on Unix with an advisory
    file lock and against concurrent writers in one process on all platforms.
    A database-backed implementation should use a database advisory lock and a
    restricted INSERT-only role while preserving this API.
    """

    def __init__(self, path: Path, *, integrity_key: bytes) -> None:
        if len(integrity_key) < 32:
            raise ValueError("audit integrity key must contain at least 32 bytes")
        self.path = path
        self._integrity_key = integrity_key
        self._thread_lock = threading.RLock()

    def append(
        self,
        *,
        actor_id: str | None,
        action: str,
        target_type: str,
        target_id: str | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        metadata: Mapping[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        action = _validate_name(action, "action")
        target_type = _validate_name(target_type, "target type")
        timestamp = _as_utc(occurred_at or datetime.now(UTC))
        safe_metadata = _json_copy(metadata or {})
        if not isinstance(safe_metadata, dict):
            raise TypeError("audit metadata must be an object")

        with self._exclusive_lock():
            event_count = 0
            previous_hash = GENESIS_HASH
            for existing in self._iter_verified_events():
                event_count = existing.sequence
                previous_hash = existing.event_hash
            body = {
                "sequence": event_count + 1,
                "occurred_at": timestamp.isoformat(),
                "actor_id": actor_id,
                "action": action,
                "target_type": target_type,
                "target_id": target_id,
                "outcome": AuditOutcome(outcome).value,
                "metadata": safe_metadata,
                "previous_hash": previous_hash,
            }
            event = AuditEvent.model_validate(
                {**body, "event_hash": self._sign(body)}
            )
            self._append_line(event.model_dump(mode="json"))
            return event

    def events(self) -> tuple[AuditEvent, ...]:
        with self._exclusive_lock():
            return tuple(self._iter_verified_events())

    def verify(self, *, expected_head: str | None = None) -> AuditVerification:
        with self._exclusive_lock():
            event_count = 0
            head = GENESIS_HASH
            for event in self._iter_verified_events():
                event_count = event.sequence
                head = event.event_hash
        if expected_head is not None and not hmac.compare_digest(head, expected_head):
            raise AuditIntegrityError("audit head does not match the trusted checkpoint")
        return AuditVerification(event_count=event_count, head_hash=head)

    def _iter_verified_events(self) -> Iterator[AuditEvent]:
        if self.path is None:
            # Database-backed adapters historically override _read_and_verify().
            # Preserve that adapter boundary while file journals stream records.
            yield from self._read_and_verify()  # type: ignore[attr-defined]
            return
        try:
            descriptor = _open_regular_readonly(self.path)
        except FileNotFoundError:
            return
        previous_hash = GENESIS_HASH
        try:
            initial = os.fstat(descriptor)
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                line_number = 0
                while True:
                    line = stream.readline(MAX_AUDIT_RECORD_BYTES + 1)
                    if not line:
                        break
                    line_number += 1
                    if len(line) > MAX_AUDIT_RECORD_BYTES:
                        raise AuditIntegrityError(
                            f"audit line {line_number} exceeds the size limit"
                        )
                    if not line.endswith(b"\n"):
                        raise AuditIntegrityError(
                            f"audit line {line_number} is incomplete"
                        )
                    raw = json.loads(line)
                    event = AuditEvent.model_validate(raw)
                    if event.sequence != line_number:
                        raise AuditIntegrityError(
                            f"invalid audit sequence at line {line_number}"
                        )
                    if event.previous_hash != previous_hash:
                        raise AuditIntegrityError(
                            f"broken audit chain at line {line_number}"
                        )
                    body = _event_body(event)
                    expected = self._sign(body)
                    if not hmac.compare_digest(event.event_hash, expected):
                        raise AuditIntegrityError(
                            f"invalid audit signature at line {line_number}"
                        )
                    previous_hash = event.event_hash
                    yield event
            _require_stable_read(self.path, descriptor, initial)
        except AuditIntegrityError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
            raise AuditIntegrityError("audit journal cannot be verified") from error
        finally:
            os.close(descriptor)

    def _sign(self, body: Mapping[str, Any]) -> str:
        serialized = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return hmac.new(self._integrity_key, serialized, hashlib.sha256).hexdigest()

    def _append_line(self, value: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        was_present = self.path.exists()
        payload = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        if len(payload) > MAX_AUDIT_RECORD_BYTES:
            raise ValueError("audit event exceeds the size limit")
        if not hasattr(os, "O_NOFOLLOW") and self.path.is_symlink():
            raise AuditIntegrityError("audit journal path is unsafe")
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
            raise AuditIntegrityError(
                "audit journal path cannot be opened safely"
            ) from None
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuditIntegrityError("audit journal path is not a regular file")
            _enforce_owner_only_permissions(descriptor)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("audit append did not make progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if not was_present:
            fsync_directory_best_effort(self.path.parent)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        with self._thread_lock:
            if not hasattr(os, "O_NOFOLLOW") and lock_path.is_symlink():
                raise AuditIntegrityError("audit lock path is unsafe")
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(lock_path, flags, 0o600)
            except OSError:
                raise AuditIntegrityError(
                    "audit lock path cannot be opened safely"
                ) from None
            locked = False
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise AuditIntegrityError("audit lock path is not a regular file")
                _enforce_owner_only_permissions(descriptor)
                try:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                    locked = True
                except ImportError:
                    # The process-local lock remains active on platforms without
                    # fcntl; production multi-process storage must provide its
                    # own transactional writer lock.
                    pass
                yield
            finally:
                if locked:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)


def _validate_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not _NAME_PATTERN.fullmatch(value):
        raise ValueError(f"invalid audit {label}")
    return value


def _enforce_owner_only_permissions(descriptor: int) -> None:
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(descriptor, 0o600)


def _open_regular_readonly(path: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW") and path.is_symlink():
        raise AuditIntegrityError("audit journal path is unsafe")
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
        raise AuditIntegrityError(
            "audit journal path cannot be opened safely"
        ) from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AuditIntegrityError("audit journal path is not a regular file")
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
        raise AuditIntegrityError("audit journal changed while it was read") from None
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        not stat.S_ISREG(current.st_mode)
        or any(getattr(after, field) != getattr(initial, field) for field in fields)
        or any(getattr(current, field) != getattr(after, field) for field in fields)
    ):
        raise AuditIntegrityError("audit journal changed while it was read")


def _event_body(event: AuditEvent) -> dict[str, Any]:
    return {
        "sequence": event.sequence,
        "occurred_at": event.occurred_at.isoformat(),
        "actor_id": event.actor_id,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "outcome": event.outcome.value,
        "metadata": event.metadata,
        "previous_hash": event.previous_hash,
    }


def _json_copy(value: Any) -> Any:
    if not isinstance(value, Mapping):
        raise TypeError("audit metadata must be an object")
    _validate_metadata_structure(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_AUDIT_METADATA_BYTES:
            raise ValueError("audit metadata exceeds the size limit")
        return json.loads(encoded)
    except ValueError as error:
        if str(error) == "audit metadata exceeds the size limit":
            raise
        raise TypeError("audit metadata must be JSON-serializable") from None
    except (OverflowError, RecursionError, TypeError, UnicodeError):
        raise TypeError("audit metadata must be JSON-serializable") from None


def _validate_metadata_structure(value: Mapping[str, Any]) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    seen_containers: set[int] = set()
    key_count = 0
    item_count = 0
    while stack:
        current, depth = stack.pop()
        item_count += 1
        if item_count > MAX_AUDIT_METADATA_ITEMS:
            raise ValueError("audit metadata exceeds the item limit")
        if depth > MAX_AUDIT_METADATA_DEPTH:
            raise ValueError("audit metadata exceeds the depth limit")
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen_containers:
                raise ValueError("audit metadata must be acyclic")
            seen_containers.add(identity)
            for key, nested in current.items():
                if not isinstance(key, str):
                    raise ValueError("audit metadata field names must be strings")
                try:
                    key_size = len(key.encode("utf-8"))
                except UnicodeError:
                    raise ValueError("audit metadata field name is invalid") from None
                if (
                    not 1 <= key_size <= MAX_AUDIT_METADATA_KEY_BYTES
                    or any(ord(character) < 32 or ord(character) == 127 for character in key)
                ):
                    raise ValueError("audit metadata field name is invalid")
                key_count += 1
                if key_count > MAX_AUDIT_METADATA_KEYS:
                    raise ValueError("audit metadata exceeds the key limit")
                if _is_sensitive_metadata_key(key):
                    raise ValueError("audit metadata contains a sensitive field")
                stack.append((nested, depth + 1))
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in seen_containers:
                raise ValueError("audit metadata must be acyclic")
            seen_containers.add(identity)
            stack.extend((nested, depth + 1) for nested in current)


def _is_sensitive_metadata_key(key: str) -> bool:
    with_camel_boundaries = re.sub(
        r"(?<=[a-z0-9])(?=[A-Z])",
        "_",
        key,
    )
    ordered_parts = [
        part
        for part in re.split(
            r"[^A-Za-z0-9]+",
            with_camel_boundaries.casefold(),
        )
        if part
    ]
    parts = set(ordered_parts)
    compact = "".join(ordered_parts)
    return bool(parts & _SENSITIVE_PARTS) or compact in _SENSITIVE_COMPACT_KEYS


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("audit timestamp must be timezone-aware")
    return value.astimezone(UTC)
