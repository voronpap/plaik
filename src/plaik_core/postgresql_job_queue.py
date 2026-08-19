"""PostgreSQL-backed durable job queue with the JSON adapter's state machine."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from .database import ConnectionFactory, DatabaseConnection
from .jobs import (
    DEFAULT_MAXIMUM_JOB_RECORDS,
    HARD_MAXIMUM_JOB_RECORDS,
    MAXIMUM_TERMINAL_PURGE_BATCH,
    JobQueueCapacityError,
    JobQueueError,
    JobRecord,
    JobStatus,
    _as_utc,
    _owner_job_prefix,
    _safe_payload,
    _validate_idempotency_key,
    _validate_job_type,
    _validate_worker_id,
)

_TABLE = "plaik_core.plaik_job_queue"
_LOCK_NOT_AVAILABLE = "55P03"
_UNIQUE_VIOLATION = "23505"
_ENQUEUE_LOCK_TIMEOUT = "1ms"
_ENQUEUE_SAVEPOINT = "plaik_job_enqueue"
JOB_QUEUE_ENQUEUE_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"plaik-v2:job-queue:enqueue:v1").digest()[:8],
    byteorder="big",
    signed=True,
)
_COLUMNS = (
    "id, type, idempotency_key, payload_json, status, attempts, "
    "maximum_attempts, scheduled_at, created_at, updated_at, "
    "lease_owner, lease_expires_at, fencing_token, error_code"
)


def _is_sqlstate(error: BaseException, code: str) -> bool:
    for attr in ("sqlstate", "pgcode"):
        value = getattr(error, attr, None)
        if isinstance(value, str) and value.upper() == code:
            return True
    diagnostic = getattr(error, "diag", None)
    state = getattr(diagnostic, "sqlstate", None)
    return isinstance(state, str) and state.upper() == code


def _payload_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _load_payload(raw: Any) -> dict[str, Any]:
    if type(raw) is dict:
        return raw
    raise JobQueueError("job payload must be a JSON object")


def _as_record(row: Any) -> JobRecord:
    return JobRecord(
        id=str(row[0]),
        type=str(row[1]),
        idempotency_key=str(row[2]),
        payload=_load_payload(row[3]),
        status=JobStatus(str(row[4])),
        attempts=int(row[5]),
        maximum_attempts=int(row[6]),
        scheduled_at=_as_utc(row[7]),
        created_at=_as_utc(row[8]),
        updated_at=_as_utc(row[9]),
        lease_owner=row[10],
        lease_expires_at=None if row[11] is None else _as_utc(row[11]),
        fencing_token=int(row[12]),
        error_code=row[13],
    )


class PostgreSQLJobQueue:
    """Canonical PostgreSQL persistence for the DurableJobQueue state machine."""

    def __init__(
        self,
        connect: ConnectionFactory,
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
        self._connect = connect
        self.base_retry_delay = base_retry_delay
        self.maximum_retry_delay = maximum_retry_delay
        self.maximum_records = maximum_records
        self._lock = threading.RLock()

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
        encoded = _payload_json(safe_payload)
        with self._transaction() as connection:
            with connection.cursor() as cursor:
                # Wait for the enqueue lock before lock_timeout; 1ms would
                # otherwise fail concurrent inserts instead of serializing them.
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (JOB_QUEUE_ENQUEUE_LOCK_KEY,),
                )
                cursor.execute(f"SET LOCAL lock_timeout = '{_ENQUEUE_LOCK_TIMEOUT}'")
                cursor.execute(f"SAVEPOINT {_ENQUEUE_SAVEPOINT}")
                try:
                    cursor.execute(
                        f"SELECT COUNT(*) FROM {_TABLE}",
                    )
                    count_row = cursor.fetchone()
                    count = int(count_row[0]) if count_row is not None else 0
                    cursor.execute(
                        f"""
                        SELECT {_COLUMNS} FROM {_TABLE}
                        WHERE idempotency_key = %s
                        """,
                        (idempotency_key,),
                    )
                    existing = cursor.fetchone()
                    if existing is not None:
                        current = _as_record(existing)
                        if (
                            current.type != job_type
                            or current.payload != safe_payload
                        ):
                            raise JobQueueError(
                                "job idempotency key is bound to another operation"
                            )
                        return current
                    if count >= self.maximum_records:
                        raise JobQueueCapacityError("job queue capacity is exhausted")
                    cursor.execute(
                        f"""
                        INSERT INTO {_TABLE} (
                            id, type, idempotency_key, payload_json, status,
                            attempts, maximum_attempts, scheduled_at, created_at,
                            updated_at, lease_owner, lease_expires_at,
                            fencing_token, error_code
                        )
                        VALUES (
                            %s, %s, %s, %s::jsonb, %s,
                            0, %s, %s, %s,
                            %s, NULL, NULL,
                            0, NULL
                        )
                        RETURNING {_COLUMNS}
                        """,
                        (
                            record.id,
                            record.type,
                            record.idempotency_key,
                            encoded,
                            record.status.value,
                            record.maximum_attempts,
                            record.scheduled_at,
                            record.created_at,
                            record.updated_at,
                        ),
                    )
                    row = cursor.fetchone()
                except JobQueueError:
                    raise
                except Exception as error:
                    if not _is_sqlstate(error, _LOCK_NOT_AVAILABLE) and not _is_sqlstate(
                        error, _UNIQUE_VIOLATION
                    ):
                        raise JobQueueError("PostgreSQL job enqueue failed") from error
                    cursor.execute(f"ROLLBACK TO SAVEPOINT {_ENQUEUE_SAVEPOINT}")
                    cursor.execute(
                        f"""
                        SELECT {_COLUMNS} FROM {_TABLE}
                        WHERE idempotency_key = %s
                        """,
                        (idempotency_key,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise JobQueueError(
                            "job enqueue could not wait for a locked idempotency key"
                        ) from error
                    current = _as_record(row)
                    if current.type != job_type or current.payload != safe_payload:
                        raise JobQueueError(
                            "job idempotency key is bound to another operation"
                        ) from None
                    return current
        if row is None:
            raise JobQueueError("PostgreSQL job insert returned no identity")
        return _as_record(row)

    def cancel_owner(self, owner: str, *, now: datetime | None = None) -> int:
        prefix = _owner_job_prefix(owner)
        timestamp = _as_utc(now or datetime.now(UTC))
        with self._transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    UPDATE {_TABLE}
                    SET status = %s,
                        updated_at = %s,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        error_code = %s
                    WHERE status IN (%s, %s)
                      AND type LIKE %s
                    """,
                    (
                        JobStatus.FAILED.value,
                        timestamp,
                        "job.owner_inactive",
                        JobStatus.QUEUED.value,
                        JobStatus.RUNNING.value,
                        f"{prefix}%",
                    ),
                )
                return int(getattr(cursor, "rowcount", 0) or 0)

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
        expires = timestamp + lease
        with self._transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    UPDATE {_TABLE}
                    SET status = CASE
                            WHEN attempts >= maximum_attempts THEN %s
                            ELSE %s
                        END,
                        scheduled_at = %s,
                        updated_at = %s,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        error_code = %s
                    WHERE status = %s
                      AND lease_expires_at IS NOT NULL
                      AND lease_expires_at <= %s
                    """,
                    (
                        JobStatus.FAILED.value,
                        JobStatus.QUEUED.value,
                        timestamp,
                        timestamp,
                        "job.lease_expired",
                        JobStatus.RUNNING.value,
                        timestamp,
                    ),
                )
                cursor.execute(
                    f"""
                    SELECT {_COLUMNS} FROM {_TABLE}
                    WHERE status = %s AND scheduled_at <= %s
                    ORDER BY scheduled_at, created_at, id
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                    """,
                    (JobStatus.QUEUED.value, timestamp),
                )
                selected = cursor.fetchone()
                if selected is None:
                    return None
                current = _as_record(selected)
                cursor.execute(
                    f"""
                    UPDATE {_TABLE}
                    SET status = %s,
                        attempts = attempts + 1,
                        updated_at = %s,
                        lease_owner = %s,
                        lease_expires_at = %s,
                        fencing_token = fencing_token + 1,
                        error_code = NULL
                    WHERE id = %s
                    RETURNING {_COLUMNS}
                    """,
                    (
                        JobStatus.RUNNING.value,
                        timestamp,
                        worker_id,
                        expires,
                        current.id,
                    ),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        return _as_record(row)

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
        with self._transaction(commit=False) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT {_COLUMNS} FROM {_TABLE} ORDER BY id",
                )
                rows = cursor.fetchall()
        return {record.id: record for record in (_as_record(row) for row in rows)}

    def leased(
        self,
        job_id: str,
        worker_id: str,
        *,
        fencing_token: int,
        now: datetime | None = None,
    ) -> JobRecord | None:
        worker_id = _validate_worker_id(worker_id)
        if (
            not isinstance(fencing_token, int)
            or isinstance(fencing_token, bool)
            or fencing_token < 1
        ):
            raise ValueError("job fencing token must be a positive integer")
        timestamp = _as_utc(now or datetime.now(UTC))
        with self._transaction(commit=False) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT {_COLUMNS} FROM {_TABLE} WHERE id = %s",
                    (job_id,),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        current = _as_record(row)
        if (
            current.status != JobStatus.RUNNING
            or current.lease_owner != worker_id
            or current.fencing_token != fencing_token
            or current.lease_expires_at is None
            or timestamp >= current.lease_expires_at
        ):
            return None
        return current

    def purge_terminal(self, *, before: datetime, limit: int = 100) -> int:
        cutoff = _as_utc(before)
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError("terminal purge limit must be an integer")
        if not 1 <= limit <= MAXIMUM_TERMINAL_PURGE_BATCH:
            raise ValueError(
                "terminal purge limit must be between 1 and "
                f"{MAXIMUM_TERMINAL_PURGE_BATCH}"
            )
        with self._transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    DELETE FROM {_TABLE}
                    WHERE id IN (
                        SELECT id FROM {_TABLE}
                        WHERE status IN (%s, %s)
                          AND updated_at < %s
                        ORDER BY updated_at, id
                        LIMIT %s
                    )
                    """,
                    (
                        JobStatus.SUCCEEDED.value,
                        JobStatus.FAILED.value,
                        cutoff,
                        limit,
                    ),
                )
                return int(getattr(cursor, "rowcount", 0) or 0)

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
        with self._transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    SELECT {_COLUMNS} FROM {_TABLE}
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (job_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise JobQueueError("job does not exist")
                current = _as_record(row)
                if current.status != JobStatus.RUNNING or current.lease_owner != worker_id:
                    raise JobQueueError("worker does not own the running job")
                if current.fencing_token != fencing_token:
                    raise JobQueueError("job fencing token is stale")
                if (
                    current.lease_expires_at is None
                    or timestamp >= current.lease_expires_at
                ):
                    raise JobQueueError("job lease has expired")
                if succeeded:
                    status = JobStatus.SUCCEEDED.value
                    next_scheduled = current.scheduled_at
                    next_error = None
                elif current.attempts >= current.maximum_attempts:
                    status = JobStatus.FAILED.value
                    next_scheduled = current.scheduled_at
                    next_error = error_code
                else:
                    delay = min(
                        self.base_retry_delay * (2 ** (current.attempts - 1)),
                        self.maximum_retry_delay,
                    )
                    status = JobStatus.QUEUED.value
                    next_scheduled = timestamp + delay
                    next_error = error_code
                cursor.execute(
                    f"""
                    UPDATE {_TABLE}
                    SET status = %s,
                        scheduled_at = %s,
                        updated_at = %s,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        error_code = %s
                    WHERE id = %s
                    RETURNING {_COLUMNS}
                    """,
                    (
                        status,
                        next_scheduled,
                        timestamp,
                        next_error,
                        job_id,
                    ),
                )
                updated = cursor.fetchone()
        if updated is None:
            raise JobQueueError("PostgreSQL job finish returned no identity")
        return _as_record(updated)

    @contextmanager
    def _transaction(self, *, commit: bool = True) -> Iterator[DatabaseConnection]:
        with self._lock:
            connection: DatabaseConnection | None = None
            try:
                connection = self._connect()
                yield connection
                if commit:
                    connection.commit()
                else:
                    connection.rollback()
            except Exception:
                if connection is not None:
                    try:
                        connection.rollback()
                    except Exception:
                        pass
                raise
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass
