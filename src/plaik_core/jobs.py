"""Durable reference job queue with leases, retries and idempotency."""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from plaik_contracts import JobExecutionContext

from .storage import exclusive_file_lock, read_json, write_json_atomic


_JOB_TYPE = re.compile(r"^[a-z][a-z0-9-]{1,63}\.[a-z][a-z0-9._-]{1,95}$")
_OWNER = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_WORKER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$")
_SENSITIVE_KEYS = {
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
MAX_JOB_PAYLOAD_BYTES = 64 * 1024
MAX_JOB_PAYLOAD_DEPTH = 16
MAX_JOB_PAYLOAD_KEYS = 512
MAX_JOB_PAYLOAD_ITEMS = 4096
MAX_JOB_PAYLOAD_KEY_BYTES = 128
DEFAULT_MAXIMUM_JOB_RECORDS = 4096
HARD_MAXIMUM_JOB_RECORDS = 100_000
MAXIMUM_TERMINAL_PURGE_BATCH = 1000


class JobQueueError(RuntimeError):
    """A durable job operation violates queue invariants."""


class JobQueueCapacityError(JobQueueError):
    """The durable queue rejected new work at its configured hard ceiling."""


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class JobRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    type: str
    idempotency_key: str
    payload: dict[str, Any]
    status: JobStatus
    attempts: int = 0
    maximum_attempts: int = Field(ge=1, le=32)
    scheduled_at: datetime
    created_at: datetime
    updated_at: datetime
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    fencing_token: int = Field(default=0, ge=0)
    error_code: str | None = None

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: Mapping[str, Any]) -> dict[str, Any]:
        return _safe_payload(value)


JobHandler = Callable[[JobExecutionContext], None]


class JobQueue(Protocol):
    """Durable job state machine shared by JSON and PostgreSQL adapters."""

    def enqueue(
        self,
        job_type: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
        maximum_attempts: int = 5,
        scheduled_at: datetime | None = None,
        now: datetime | None = None,
    ) -> JobRecord: ...

    def cancel_owner(self, owner: str, *, now: datetime | None = None) -> int: ...

    def claim(
        self,
        worker_id: str,
        *,
        lease: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> JobRecord | None: ...

    def succeed(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        now: datetime | None = None,
    ) -> JobRecord: ...

    def fail(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        error_code: str,
        now: datetime | None = None,
    ) -> JobRecord: ...

    def records(self) -> dict[str, JobRecord]: ...

    def leased(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        now: datetime | None = None,
    ) -> JobRecord | None: ...

    def purge_terminal(self, *, before: datetime, limit: int = 100) -> int: ...


class DurableJobQueue:
    """JSON reference queue; production adapters preserve this state machine."""

    REGISTRY_VERSION = 1

    def __init__(
        self,
        path: Path,
        *,
        base_retry_delay: timedelta = timedelta(seconds=5),
        maximum_retry_delay: timedelta = timedelta(hours=1),
        maximum_records: int = DEFAULT_MAXIMUM_JOB_RECORDS,
    ) -> None:
        if base_retry_delay <= timedelta(0):
            raise ValueError("base retry delay must be positive")
        if maximum_retry_delay < base_retry_delay:
            raise ValueError("maximum retry delay cannot be below base delay")
        if not isinstance(maximum_records, int) or isinstance(maximum_records, bool):
            raise TypeError("maximum job records must be an integer")
        if not 1 <= maximum_records <= HARD_MAXIMUM_JOB_RECORDS:
            raise ValueError(
                "maximum job records must be between 1 and "
                f"{HARD_MAXIMUM_JOB_RECORDS}"
            )
        self.path = path
        self.base_retry_delay = base_retry_delay
        self.maximum_retry_delay = maximum_retry_delay
        self.maximum_records = maximum_records

    def enqueue(
        self,
        job_type: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
        maximum_attempts: int = 5,
        scheduled_at: datetime | None = None,
        now: datetime | None = None,
    ) -> JobRecord:
        job_type = _validate_job_type(job_type)
        idempotency_key = _validate_idempotency_key(idempotency_key)
        safe_payload = _safe_payload(payload)
        timestamp = _as_utc(now or datetime.now(UTC))
        due = _as_utc(scheduled_at or timestamp)
        if not 1 <= maximum_attempts <= 32:
            raise ValueError("maximum attempts must be between 1 and 32")
        with exclusive_file_lock(self.path):
            records = self._read()
            existing = next(
                (
                    record
                    for record in records.values()
                    if record.idempotency_key == idempotency_key
                ),
                None,
            )
            if existing is not None:
                if existing.type != job_type or existing.payload != safe_payload:
                    raise JobQueueError(
                        "job idempotency key is bound to another operation"
                    )
                return existing
            if len(records) >= self.maximum_records:
                raise JobQueueCapacityError("job queue capacity is exhausted")
            record = JobRecord(
                id=str(uuid4()),
                type=job_type,
                idempotency_key=idempotency_key,
                payload=safe_payload,
                status=JobStatus.QUEUED,
                maximum_attempts=maximum_attempts,
                scheduled_at=due,
                created_at=timestamp,
                updated_at=timestamp,
            )
            records[record.id] = record
            self._write(records)
            return record

    def cancel_owner(self, owner: str, *, now: datetime | None = None) -> int:
        """Fail queued and running jobs in the owner's job-type namespace."""

        prefix = _owner_job_prefix(owner)
        timestamp = _as_utc(now or datetime.now(UTC))
        with exclusive_file_lock(self.path):
            records = self._read()
            changed = 0
            for job_id, record in tuple(records.items()):
                if record.status not in {JobStatus.QUEUED, JobStatus.RUNNING}:
                    continue
                if not record.type.startswith(prefix):
                    continue
                records[job_id] = record.model_copy(
                    update={
                        "status": JobStatus.FAILED,
                        "updated_at": timestamp,
                        "lease_owner": None,
                        "lease_expires_at": None,
                        "error_code": "job.owner_inactive",
                    }
                )
                changed += 1
            if changed:
                self._write(records)
            return changed

    def claim(
        self,
        worker_id: str,
        *,
        lease: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> JobRecord | None:
        worker_id = _validate_worker_id(worker_id)
        if not timedelta(seconds=1) <= lease <= timedelta(hours=1):
            raise ValueError("job lease must be between 1 second and 1 hour")
        timestamp = _as_utc(now or datetime.now(UTC))
        with exclusive_file_lock(self.path):
            records = self._read()
            records = self._recover_expired(records, timestamp)
            due = sorted(
                (
                    record
                    for record in records.values()
                    if record.status == JobStatus.QUEUED
                    and record.scheduled_at <= timestamp
                ),
                key=lambda record: (record.scheduled_at, record.created_at, record.id),
            )
            if not due:
                self._write(records)
                return None
            selected = due[0]
            claimed = selected.model_copy(
                update={
                    "status": JobStatus.RUNNING,
                    "attempts": selected.attempts + 1,
                    "updated_at": timestamp,
                    "lease_owner": worker_id,
                    "lease_expires_at": timestamp + lease,
                    "fencing_token": selected.fencing_token + 1,
                    "error_code": None,
                }
            )
            records[claimed.id] = claimed
            self._write(records)
            return claimed

    def succeed(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        now: datetime | None = None,
    ) -> JobRecord:
        return self._finish(
            job_id,
            worker_id,
            fencing_token=fencing_token,
            succeeded=True,
            now=now,
        )

    def fail(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        error_code: str,
        now: datetime | None = None,
    ) -> JobRecord:
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{1,127}", error_code):
            raise ValueError("invalid safe job error code")
        return self._finish(
            job_id,
            worker_id,
            fencing_token=fencing_token,
            succeeded=False,
            error_code=error_code,
            now=now,
        )

    def records(self) -> dict[str, JobRecord]:
        return dict(sorted(self._read().items()))

    def leased(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        now: datetime | None = None,
    ) -> JobRecord | None:
        """Return the job only while this worker still holds a live lease."""

        worker_id = _validate_worker_id(worker_id)
        if (
            not isinstance(fencing_token, int)
            or isinstance(fencing_token, bool)
            or fencing_token < 1
        ):
            raise ValueError("job fencing token must be a positive integer")
        timestamp = _as_utc(now or datetime.now(UTC))
        with exclusive_file_lock(self.path):
            current = self._read().get(job_id)
            if (
                current is None
                or current.status != JobStatus.RUNNING
                or current.lease_owner != worker_id
                or current.fencing_token != fencing_token
                or current.lease_expires_at is None
                or timestamp >= current.lease_expires_at
            ):
                return None
            return current

    def purge_terminal(self, *, before: datetime, limit: int = 100) -> int:
        """Remove a bounded terminal batch older than an explicit UTC cutoff."""

        cutoff = _as_utc(before)
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError("terminal purge limit must be an integer")
        if not 1 <= limit <= MAXIMUM_TERMINAL_PURGE_BATCH:
            raise ValueError(
                "terminal purge limit must be between 1 and "
                f"{MAXIMUM_TERMINAL_PURGE_BATCH}"
            )
        with exclusive_file_lock(self.path):
            records = self._read()
            terminal = sorted(
                (
                    record
                    for record in records.values()
                    if record.status in {JobStatus.SUCCEEDED, JobStatus.FAILED}
                    and record.updated_at < cutoff
                ),
                key=lambda record: (record.updated_at, record.id),
            )[:limit]
            if not terminal:
                return 0
            for record in terminal:
                del records[record.id]
            self._write(records)
            return len(terminal)

    def _finish(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        succeeded: bool,
        error_code: str | None = None,
        now: datetime | None,
    ) -> JobRecord:
        worker_id = _validate_worker_id(worker_id)
        if (
            not isinstance(fencing_token, int)
            or isinstance(fencing_token, bool)
            or fencing_token < 1
        ):
            raise ValueError("job fencing token must be a positive integer")
        timestamp = _as_utc(now or datetime.now(UTC))
        with exclusive_file_lock(self.path):
            records = self._read()
            try:
                current = records[job_id]
            except KeyError as error:
                raise JobQueueError("job does not exist") from error
            if current.status != JobStatus.RUNNING or current.lease_owner != worker_id:
                raise JobQueueError("worker does not own the running job")
            if current.fencing_token != fencing_token:
                raise JobQueueError("job fencing token is stale")
            if current.lease_expires_at is None or timestamp >= current.lease_expires_at:
                raise JobQueueError("job lease has expired")
            if succeeded:
                updated = current.model_copy(
                    update={
                        "status": JobStatus.SUCCEEDED,
                        "updated_at": timestamp,
                        "lease_owner": None,
                        "lease_expires_at": None,
                        "error_code": None,
                    }
                )
            elif current.attempts >= current.maximum_attempts:
                updated = current.model_copy(
                    update={
                        "status": JobStatus.FAILED,
                        "updated_at": timestamp,
                        "lease_owner": None,
                        "lease_expires_at": None,
                        "error_code": error_code,
                    }
                )
            else:
                delay = min(
                    self.base_retry_delay * (2 ** (current.attempts - 1)),
                    self.maximum_retry_delay,
                )
                updated = current.model_copy(
                    update={
                        "status": JobStatus.QUEUED,
                        "scheduled_at": timestamp + delay,
                        "updated_at": timestamp,
                        "lease_owner": None,
                        "lease_expires_at": None,
                        "error_code": error_code,
                    }
                )
            records[job_id] = updated
            self._write(records)
            return updated

    def _recover_expired(
        self, records: dict[str, JobRecord], now: datetime
    ) -> dict[str, JobRecord]:
        recovered = dict(records)
        for job_id, record in records.items():
            if (
                record.status == JobStatus.RUNNING
                and record.lease_expires_at is not None
                and record.lease_expires_at <= now
            ):
                terminal = record.attempts >= record.maximum_attempts
                recovered[job_id] = record.model_copy(
                    update={
                        "status": JobStatus.FAILED if terminal else JobStatus.QUEUED,
                        "scheduled_at": now,
                        "updated_at": now,
                        "lease_owner": None,
                        "lease_expires_at": None,
                        "error_code": "job.lease_expired",
                    }
                )
        return recovered

    def _read(self) -> dict[str, JobRecord]:
        data = read_json(self.path, {"version": self.REGISTRY_VERSION, "jobs": {}})
        if data.get("version") != self.REGISTRY_VERSION:
            raise JobQueueError("unsupported job registry version")
        jobs = data.get("jobs")
        if not isinstance(jobs, dict):
            raise JobQueueError("job registry is malformed")
        return {
            job_id: JobRecord.model_validate(record)
            for job_id, record in jobs.items()
        }

    def _write(self, records: dict[str, JobRecord]) -> None:
        write_json_atomic(
            self.path,
            {
                "version": self.REGISTRY_VERSION,
                "jobs": {
                    job_id: record.model_dump(mode="json")
                    for job_id, record in sorted(records.items())
                },
            },
        )


class DelegatingJobQueue:
    """Route job mutations to the live backend; drain leftover JSON first."""

    def __init__(
        self,
        resolve: Callable[[], JobQueue],
        *,
        fallback: JobQueue | None = None,
    ) -> None:
        self._resolve = resolve
        self._fallback = fallback

    def enqueue(
        self,
        job_type: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
        maximum_attempts: int = 5,
        scheduled_at: datetime | None = None,
        now: datetime | None = None,
    ) -> JobRecord:
        return self._resolve().enqueue(
            job_type,
            payload,
            idempotency_key=idempotency_key,
            maximum_attempts=maximum_attempts,
            scheduled_at=scheduled_at,
            now=now,
        )

    def cancel_owner(self, owner: str, *, now: datetime | None = None) -> int:
        live = self._resolve()
        changed = live.cancel_owner(owner, now=now)
        fallback = self._fallback
        leftover_error: Exception | None = None
        if fallback is not None and fallback is not live:
            try:
                changed += fallback.cancel_owner(owner, now=now)
            except Exception as error:
                leftover_error = error
        if leftover_error is not None:
            raise leftover_error
        return changed

    def claim(
        self,
        worker_id: str,
        *,
        lease: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> JobRecord | None:
        live = self._resolve()
        fallback = self._fallback
        leftover_error: Exception | None = None
        if fallback is not None and fallback is not live:
            try:
                leftover = fallback.claim(worker_id, lease=lease, now=now)
            except Exception as error:
                leftover_error = error
            else:
                if leftover is not None:
                    return leftover
        live_error: Exception | None = None
        claimed = None
        try:
            claimed = live.claim(worker_id, lease=lease, now=now)
        except Exception as error:
            live_error = error
        if leftover_error is not None and claimed is None:
            if live_error is not None:
                raise leftover_error from live_error
            raise leftover_error
        if live_error is not None:
            raise live_error
        return claimed

    def succeed(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        now: datetime | None = None,
    ) -> JobRecord:
        return self._backend_for(job_id).succeed(
            job_id,
            worker_id,
            fencing_token=fencing_token,
            now=now,
        )

    def fail(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        error_code: str,
        now: datetime | None = None,
    ) -> JobRecord:
        return self._backend_for(job_id).fail(
            job_id,
            worker_id,
            fencing_token=fencing_token,
            error_code=error_code,
            now=now,
        )

    def records(self) -> dict[str, JobRecord]:
        live = self._resolve()
        fallback = self._fallback
        merged: dict[str, JobRecord] = {}
        if fallback is not None and fallback is not live:
            merged.update(fallback.records())
        merged.update(live.records())
        return dict(sorted(merged.items()))

    def leased(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        now: datetime | None = None,
    ) -> JobRecord | None:
        live = self._resolve()
        fallback = self._fallback
        leftover_error: Exception | None = None
        if fallback is not None and fallback is not live:
            try:
                leftover = fallback.leased(
                    job_id,
                    worker_id,
                    fencing_token=fencing_token,
                    now=now,
                )
            except Exception as error:
                leftover_error = error
            else:
                if leftover is not None:
                    return leftover
        live_error: Exception | None = None
        live_lease = None
        try:
            live_lease = live.leased(
                job_id,
                worker_id,
                fencing_token=fencing_token,
                now=now,
            )
        except Exception as error:
            live_error = error
        if leftover_error is not None and live_lease is None:
            if live_error is not None:
                raise leftover_error from live_error
            raise leftover_error
        if live_error is not None:
            raise live_error
        return live_lease

    def purge_terminal(self, *, before: datetime, limit: int = 100) -> int:
        live = self._resolve()
        purged = live.purge_terminal(before=before, limit=limit)
        fallback = self._fallback
        if fallback is not None and fallback is not live and purged < limit:
            purged += fallback.purge_terminal(before=before, limit=limit - purged)
        return purged

    def _backend_for(self, job_id: str) -> JobQueue:
        live = self._resolve()
        fallback = self._fallback
        if fallback is not None and fallback is not live:
            try:
                leftover_records = fallback.records()
            except Exception:
                leftover_records = {}
            if job_id in leftover_records and job_id not in live.records():
                return fallback
        return live


class JobRunner:
    def __init__(
        self,
        queue: JobQueue,
        handlers: Mapping[str, JobHandler],
    ) -> None:
        self.queue = queue
        self.handlers = handlers
        for job_type, handler in self.handlers.items():
            _validate_job_type(job_type)
            if not callable(handler):
                raise TypeError("job handler must be callable")

    def run_once(
        self,
        worker_id: str,
        *,
        now: datetime | None = None,
    ) -> JobRecord | None:
        job = self.queue.claim(worker_id, now=now)
        if job is None:
            return None
        live = self.queue.leased(
            job.id,
            worker_id,
            fencing_token=job.fencing_token,
            now=now,
        )
        if live is None:
            return self.queue.records().get(job.id)
        handler = self.handlers.get(live.type)
        if handler is None:
            return self._complete(
                live.id,
                worker_id,
                fencing_token=live.fencing_token,
                succeeded=False,
                error_code="job.handler_missing",
                now=now,
            )
        if live.lease_expires_at is None or live.lease_owner is None:
            raise JobQueueError("claimed job is missing lease context")
        context = JobExecutionContext(
            job_id=live.id,
            idempotency_key=live.idempotency_key,
            attempt=live.attempts,
            fencing_token=live.fencing_token,
            lease_owner=live.lease_owner,
            lease_expires_at=live.lease_expires_at,
            payload=live.payload,
        )
        try:
            handler(context)
        except Exception as error:
            safe_code = f"job.{type(error).__name__.casefold()}"[:128]
            return self._complete(
                live.id,
                worker_id,
                fencing_token=live.fencing_token,
                succeeded=False,
                error_code=safe_code,
                now=now,
            )
        return self._complete(
            live.id,
            worker_id,
            fencing_token=live.fencing_token,
            succeeded=True,
            now=now,
        )

    def _complete(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        succeeded: bool,
        error_code: str | None = None,
        now: datetime | None = None,
    ) -> JobRecord | None:
        try:
            if succeeded:
                return self.queue.succeed(
                    job_id,
                    worker_id,
                    fencing_token=fencing_token,
                    now=now,
                )
            if error_code is None:
                raise JobQueueError("failed job is missing an error code")
            return self.queue.fail(
                job_id,
                worker_id,
                fencing_token=fencing_token,
                error_code=error_code,
                now=now,
            )
        except JobQueueError:
            return self.queue.records().get(job_id)


class JobDrainPump:
    """Serialize JSON job drain and skip same-thread re-entry from handlers."""

    def __init__(self, runner: JobRunner, *, worker_id: str = "plaik-core") -> None:
        self._runner = runner
        self._worker_id = _validate_worker_id(worker_id)
        self.deferred = True
        self._lock = threading.Lock()
        self._thread: int | None = None

    def drain(self) -> None:
        if self.deferred:
            return
        me = threading.get_ident()
        if self._thread == me:
            return
        with self._lock:
            if self._thread == me:
                return
            self._thread = me
            try:
                while self._runner.run_once(self._worker_id) is not None:
                    pass
            finally:
                self._thread = None


def _safe_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise TypeError("job payload must be an object")
    _validate_payload_structure(payload)
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_JOB_PAYLOAD_BYTES:
            raise JobQueueError("job payload exceeds its size limit")
        copied = json.loads(encoded)
    except JobQueueError:
        raise
    except (OverflowError, RecursionError, TypeError, ValueError, UnicodeError):
        raise JobQueueError("job payload must be JSON-safe") from None
    return copied


def _validate_payload_structure(payload: Mapping[str, Any]) -> None:
    stack: list[tuple[Any, int]] = [(payload, 1)]
    seen_containers: set[int] = set()
    key_count = 0
    item_count = 0
    while stack:
        value, depth = stack.pop()
        item_count += 1
        if item_count > MAX_JOB_PAYLOAD_ITEMS:
            raise JobQueueError("job payload exceeds its item limit")
        if depth > MAX_JOB_PAYLOAD_DEPTH:
            raise JobQueueError("job payload exceeds its depth limit")
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in seen_containers:
                raise JobQueueError("job payload must be an acyclic JSON object")
            seen_containers.add(identity)
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise JobQueueError("job payload keys must be strings")
                try:
                    key_size = len(key.encode("utf-8"))
                except UnicodeError:
                    raise JobQueueError("job payload keys must be valid UTF-8") from None
                if (
                    not 1 <= key_size <= MAX_JOB_PAYLOAD_KEY_BYTES
                    or any(ord(character) < 32 or ord(character) == 127 for character in key)
                ):
                    raise JobQueueError("job payload contains an invalid key")
                key_count += 1
                if key_count > MAX_JOB_PAYLOAD_KEYS:
                    raise JobQueueError("job payload exceeds its key limit")
                if _is_sensitive_payload_key(key):
                    raise JobQueueError("job payload contains a sensitive field")
                stack.append((nested, depth + 1))
        elif isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in seen_containers:
                raise JobQueueError("job payload must be an acyclic JSON object")
            seen_containers.add(identity)
            stack.extend((nested, depth + 1) for nested in value)


def _is_sensitive_payload_key(key: str) -> bool:
    with_camel_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    ordered_parts = [
        part
        for part in re.split(r"[^A-Za-z0-9]+", with_camel_boundaries.casefold())
        if part
    ]
    parts = set(ordered_parts)
    compact = "".join(ordered_parts)
    return bool(parts & _SENSITIVE_KEYS) or compact in _SENSITIVE_COMPACT_KEYS


def _validate_job_type(value: str) -> str:
    if not isinstance(value, str) or not _JOB_TYPE.fullmatch(value):
        raise ValueError("invalid namespaced job type")
    return value


def _owner_job_prefix(owner: str) -> str:
    if not isinstance(owner, str) or not _OWNER.fullmatch(owner):
        raise ValueError("invalid extension owner id")
    return f"{owner}."


def _validate_worker_id(value: str) -> str:
    if not isinstance(value, str) or not _WORKER_ID.fullmatch(value):
        raise ValueError("invalid worker id")
    return value


def _validate_idempotency_key(value: str) -> str:
    if not isinstance(value, str) or not _IDEMPOTENCY_KEY.fullmatch(value):
        raise ValueError("invalid job idempotency key")
    return value


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("job timestamp must be timezone-aware")
    return value.astimezone(UTC)
