"""Durable, append-only operation attempts for recovery and idempotency."""

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
_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_NAME = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}$")
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
MAX_OPERATION_RECORD_BYTES = 16 * 1024


class OperationJournalError(RuntimeError):
    """Base error for operation-journal failures."""


class OperationJournalIntegrityError(OperationJournalError):
    """The journal is malformed or its HMAC chain does not verify."""


class OperationConflictError(OperationJournalError):
    """An idempotency ID was reused for a different logical operation."""


class OperationTransitionError(OperationJournalError):
    """An operation attempt cannot move to the requested state."""


class OperationStatus(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class OperationEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int
    operation_id: str
    attempt: int
    action: str
    target: str
    status: OperationStatus
    occurred_at: datetime
    error_code: str | None
    previous_hash: str
    event_hash: str


class OperationState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str
    attempt: int
    action: str
    target: str
    status: OperationStatus
    started_at: datetime
    finished_at: datetime | None
    error_code: str | None
    last_sequence: int


class OperationJournalVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_count: int
    operation_count: int
    pending_count: int
    head_hash: str


class OperationJournal:
    """Persist idempotent operation attempts as an HMAC-chained JSONL journal.

    ``operation_id`` is the caller-owned idempotency identifier. A failed
    logical operation can be retried under the same identifier; every retry has
    a monotonically increasing attempt number. A started attempt without a
    terminal event is returned by :meth:`pending` after process restart.
    """

    def __init__(self, path: Path, *, integrity_key: bytes) -> None:
        if len(integrity_key) < 32:
            raise ValueError("operation journal integrity key must contain at least 32 bytes")
        self.path = path
        self._integrity_key = integrity_key
        self._thread_lock = threading.RLock()

    def begin(
        self,
        operation_id: str,
        *,
        action: str,
        target: str,
        occurred_at: datetime | None = None,
    ) -> OperationState:
        """Start once, or return the existing state for a duplicate request."""

        operation_id = _validate_operation_id(operation_id)
        action = _validate_name(action, "action")
        target = _validate_target(target)
        timestamp = _as_utc(occurred_at or datetime.now(UTC))
        with self._exclusive_lock():
            events, states = self._read_and_verify()
            existing = states.get(operation_id)
            if existing is not None:
                self._require_same_operation(existing, action=action, target=target)
                return existing
            event = self._new_event(
                events,
                operation_id=operation_id,
                attempt=1,
                action=action,
                target=target,
                status=OperationStatus.STARTED,
                occurred_at=timestamp,
            )
            self._append_line(event.model_dump(mode="json"))
            return _initial_state(event)

    def retry(
        self,
        operation_id: str,
        *,
        occurred_at: datetime | None = None,
    ) -> OperationState:
        """Begin the next attempt after failure; pending retries are idempotent."""

        operation_id = _validate_operation_id(operation_id)
        timestamp = _as_utc(occurred_at or datetime.now(UTC))
        with self._exclusive_lock():
            events, states = self._read_and_verify()
            current = _require_state(states, operation_id)
            if current.status == OperationStatus.STARTED:
                return current
            if current.status == OperationStatus.SUCCEEDED:
                raise OperationTransitionError("a succeeded operation cannot be retried")
            if current.finished_at is None or timestamp < current.finished_at:
                raise OperationTransitionError(
                    "operation retry predates the previous attempt"
                )
            event = self._new_event(
                events,
                operation_id=operation_id,
                attempt=current.attempt + 1,
                action=current.action,
                target=current.target,
                status=OperationStatus.STARTED,
                occurred_at=timestamp,
            )
            self._append_line(event.model_dump(mode="json"))
            return _initial_state(event)

    def succeed(
        self,
        operation_id: str,
        *,
        occurred_at: datetime | None = None,
    ) -> OperationState:
        return self._finish(
            operation_id,
            status=OperationStatus.SUCCEEDED,
            error_code=None,
            occurred_at=occurred_at,
        )

    def fail(
        self,
        operation_id: str,
        *,
        error_code: str,
        occurred_at: datetime | None = None,
    ) -> OperationState:
        return self._finish(
            operation_id,
            status=OperationStatus.FAILED,
            error_code=_validate_error_code(error_code),
            occurred_at=occurred_at,
        )

    def state(self, operation_id: str) -> OperationState | None:
        operation_id = _validate_operation_id(operation_id)
        with self._exclusive_lock():
            _events, states = self._read_and_verify()
            return states.get(operation_id)

    def states(self) -> dict[str, OperationState]:
        with self._exclusive_lock():
            _events, states = self._read_and_verify()
            return dict(sorted(states.items()))

    def pending(self) -> tuple[OperationState, ...]:
        """Return started attempts that require resume or explicit failure."""

        return tuple(
            state
            for state in self.states().values()
            if state.status == OperationStatus.STARTED
        )

    def events(self) -> tuple[OperationEvent, ...]:
        with self._exclusive_lock():
            events, _states = self._read_and_verify()
            return tuple(events)

    def verify(
        self,
        *,
        expected_head: str | None = None,
    ) -> OperationJournalVerification:
        with self._exclusive_lock():
            events, states = self._read_and_verify()
        head_hash = events[-1].event_hash if events else GENESIS_HASH
        if expected_head is not None and not hmac.compare_digest(
            head_hash, expected_head
        ):
            raise OperationJournalIntegrityError(
                "operation journal head does not match the trusted checkpoint"
            )
        return OperationJournalVerification(
            event_count=len(events),
            operation_count=len(states),
            pending_count=sum(
                state.status == OperationStatus.STARTED for state in states.values()
            ),
            head_hash=head_hash,
        )

    def _finish(
        self,
        operation_id: str,
        *,
        status: OperationStatus,
        error_code: str | None,
        occurred_at: datetime | None,
    ) -> OperationState:
        operation_id = _validate_operation_id(operation_id)
        timestamp = _as_utc(occurred_at or datetime.now(UTC))
        with self._exclusive_lock():
            events, states = self._read_and_verify()
            current = _require_state(states, operation_id)
            if current.status == status:
                if status != OperationStatus.FAILED or current.error_code == error_code:
                    return current
            if current.status != OperationStatus.STARTED:
                raise OperationTransitionError(
                    f"cannot mark {current.status.value} operation as {status.value}"
                )
            if timestamp < current.started_at:
                raise OperationJournalIntegrityError(
                    "terminal operation event predates its attempt"
                )
            event = self._new_event(
                events,
                operation_id=operation_id,
                attempt=current.attempt,
                action=current.action,
                target=current.target,
                status=status,
                error_code=error_code,
                occurred_at=timestamp,
            )
            self._append_line(event.model_dump(mode="json"))
            return _terminal_state(current, event)

    def _new_event(
        self,
        events: list[OperationEvent],
        *,
        operation_id: str,
        attempt: int,
        action: str,
        target: str,
        status: OperationStatus,
        occurred_at: datetime,
        error_code: str | None = None,
    ) -> OperationEvent:
        body = {
            "sequence": len(events) + 1,
            "operation_id": operation_id,
            "attempt": attempt,
            "action": action,
            "target": target,
            "status": status.value,
            "occurred_at": occurred_at.isoformat(),
            "error_code": error_code,
            "previous_hash": events[-1].event_hash if events else GENESIS_HASH,
        }
        return OperationEvent.model_validate(
            {**body, "event_hash": self._sign(body)}
        )

    def _read_and_verify(
        self,
    ) -> tuple[list[OperationEvent], dict[str, OperationState]]:
        try:
            descriptor = _open_regular_readonly(self.path)
        except FileNotFoundError:
            return [], {}
        events: list[OperationEvent] = []
        states: dict[str, OperationState] = {}
        previous_hash = GENESIS_HASH
        try:
            initial = os.fstat(descriptor)
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                line_number = 0
                while True:
                    line = stream.readline(MAX_OPERATION_RECORD_BYTES + 1)
                    if not line:
                        break
                    line_number += 1
                    if len(line) > MAX_OPERATION_RECORD_BYTES:
                        raise OperationJournalIntegrityError(
                            f"operation journal line {line_number} exceeds the size limit"
                        )
                    if not line.endswith(b"\n"):
                        raise OperationJournalIntegrityError(
                            f"operation journal line {line_number} is incomplete"
                        )
                    event = OperationEvent.model_validate(json.loads(line))
                    if event.sequence != line_number:
                        raise OperationJournalIntegrityError(
                            f"invalid operation sequence at line {line_number}"
                        )
                    if event.previous_hash != previous_hash:
                        raise OperationJournalIntegrityError(
                            f"broken operation chain at line {line_number}"
                        )
                    if not hmac.compare_digest(
                        event.event_hash,
                        self._sign(_event_body(event)),
                    ):
                        raise OperationJournalIntegrityError(
                            f"invalid operation signature at line {line_number}"
                        )
                    states[event.operation_id] = _apply_event(
                        states.get(event.operation_id), event
                    )
                    previous_hash = event.event_hash
                    events.append(event)
            _require_stable_read(self.path, descriptor, initial)
        except OperationJournalIntegrityError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise OperationJournalIntegrityError(
                "operation journal cannot be verified"
            ) from error
        finally:
            os.close(descriptor)
        return events, states

    def _sign(self, body: Mapping[str, Any]) -> str:
        payload = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return hmac.new(self._integrity_key, payload, hashlib.sha256).hexdigest()

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
        if len(payload) > MAX_OPERATION_RECORD_BYTES:
            raise ValueError("operation journal event exceeds the size limit")
        if not hasattr(os, "O_NOFOLLOW") and self.path.is_symlink():
            raise OperationJournalIntegrityError("operation journal path is unsafe")
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
            raise OperationJournalIntegrityError(
                "operation journal path cannot be opened safely"
            ) from None
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OperationJournalIntegrityError(
                    "operation journal path is not a regular file"
                )
            _enforce_owner_only_permissions(descriptor)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("operation journal append did not make progress")
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
                raise OperationJournalIntegrityError(
                    "operation journal lock path is unsafe"
                )
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(lock_path, flags, 0o600)
            except OSError:
                raise OperationJournalIntegrityError(
                    "operation journal lock path cannot be opened safely"
                ) from None
            locked = False
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OperationJournalIntegrityError(
                        "operation journal lock path is not a regular file"
                    )
                _enforce_owner_only_permissions(descriptor)
                try:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                    locked = True
                except ImportError:
                    # The process-local lock remains active. A production adapter
                    # on a platform without fcntl must provide a transactional lock.
                    pass
                yield
            finally:
                if locked:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    @staticmethod
    def _require_same_operation(
        existing: OperationState,
        *,
        action: str,
        target: str,
    ) -> None:
        if existing.action != action or existing.target != target:
            raise OperationConflictError(
                "operation ID is already bound to a different action or target"
            )


def _apply_event(
    current: OperationState | None,
    event: OperationEvent,
) -> OperationState:
    _validate_event_fields(event)
    if current is None:
        if event.status != OperationStatus.STARTED or event.attempt != 1:
            raise OperationJournalIntegrityError(
                "an operation must begin with started attempt 1"
            )
        return _initial_state(event)
    if current.action != event.action or current.target != event.target:
        raise OperationJournalIntegrityError(
            "operation action and target must remain immutable"
        )
    if event.status == OperationStatus.STARTED:
        if current.status != OperationStatus.FAILED:
            raise OperationJournalIntegrityError(
                "only a failed operation can begin another attempt"
            )
        if event.attempt != current.attempt + 1:
            raise OperationJournalIntegrityError("invalid operation retry attempt")
        if current.finished_at is None or event.occurred_at < current.finished_at:
            raise OperationJournalIntegrityError(
                "operation retry predates the previous attempt"
            )
        return _initial_state(event)
    if current.status != OperationStatus.STARTED or event.attempt != current.attempt:
        raise OperationJournalIntegrityError("invalid terminal operation transition")
    if event.occurred_at < current.started_at:
        raise OperationJournalIntegrityError(
            "terminal operation event predates its attempt"
        )
    return _terminal_state(current, event)


def _validate_event_fields(event: OperationEvent) -> None:
    _validate_operation_id(event.operation_id)
    _validate_name(event.action, "action")
    _validate_target(event.target)
    if event.attempt < 1:
        raise OperationJournalIntegrityError("operation attempt must be positive")
    try:
        _as_utc(event.occurred_at)
    except ValueError as error:
        raise OperationJournalIntegrityError(
            "operation timestamp must be timezone-aware"
        ) from error
    if event.status == OperationStatus.FAILED:
        if event.error_code is None:
            raise OperationJournalIntegrityError("failed operation requires an error code")
        _validate_error_code(event.error_code)
    elif event.error_code is not None:
        raise OperationJournalIntegrityError(
            "only failed operations may contain an error code"
        )


def _initial_state(event: OperationEvent) -> OperationState:
    return OperationState(
        operation_id=event.operation_id,
        attempt=event.attempt,
        action=event.action,
        target=event.target,
        status=OperationStatus.STARTED,
        started_at=event.occurred_at,
        finished_at=None,
        error_code=None,
        last_sequence=event.sequence,
    )


def _terminal_state(current: OperationState, event: OperationEvent) -> OperationState:
    return current.model_copy(
        update={
            "status": event.status,
            "finished_at": event.occurred_at,
            "error_code": event.error_code,
            "last_sequence": event.sequence,
        }
    )


def _event_body(event: OperationEvent) -> dict[str, Any]:
    return {
        "sequence": event.sequence,
        "operation_id": event.operation_id,
        "attempt": event.attempt,
        "action": event.action,
        "target": event.target,
        "status": event.status.value,
        "occurred_at": event.occurred_at.isoformat(),
        "error_code": event.error_code,
        "previous_hash": event.previous_hash,
    }


def _require_state(
    states: Mapping[str, OperationState],
    operation_id: str,
) -> OperationState:
    try:
        return states[operation_id]
    except KeyError as error:
        raise OperationTransitionError(f"unknown operation: {operation_id}") from error


def _validate_operation_id(value: str) -> str:
    if not isinstance(value, str) or not _OPERATION_ID.fullmatch(value):
        raise ValueError("invalid operation ID")
    return value


def _validate_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ValueError(f"invalid operation {label}")
    return value


def _validate_target(value: str) -> str:
    if not isinstance(value, str) or not _TARGET.fullmatch(value):
        raise ValueError("invalid operation target")
    return value


def _validate_error_code(value: str) -> str:
    if not isinstance(value, str) or not _ERROR_CODE.fullmatch(value):
        raise ValueError("invalid safe operation error code")
    return value


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("operation timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _open_regular_readonly(path: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW") and path.is_symlink():
        raise OperationJournalIntegrityError("operation journal path is unsafe")
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
        raise OperationJournalIntegrityError(
            "operation journal path cannot be opened safely"
        ) from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OperationJournalIntegrityError(
                "operation journal path is not a regular file"
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
        raise OperationJournalIntegrityError(
            "operation journal changed while it was read"
        ) from None
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        not stat.S_ISREG(current.st_mode)
        or any(getattr(after, field) != getattr(initial, field) for field in fields)
        or any(getattr(current, field) != getattr(after, field) for field in fields)
    ):
        raise OperationJournalIntegrityError(
            "operation journal changed while it was read"
        )


def _enforce_owner_only_permissions(descriptor: int) -> None:
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(descriptor, 0o600)