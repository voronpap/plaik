"""PostgreSQL-backed durable event outbox."""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError

from plaik_contracts import EventEnvelope, ResourceRef, ScopeRef

from .envelope import dump_resource, dump_scope, envelope_from_row
from .event_outbox import OutboxEnvelopeError
from .extension_runtime import _json_snapshot

_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


@dataclass(frozen=True, slots=True)
class PostgreSQLOutboxEvent:
    id: str
    owner: str
    contract: str
    version: str
    payload: dict[str, Any]
    idempotency_key: str | None
    attempt_count: int
    scope_json: Any = None
    resource_json: Any = None
    correlation_id: str | None = None
    created_at: datetime | None = None

    def as_envelope(self) -> EventEnvelope:
        if self.created_at is None:
            raise OutboxEnvelopeError("outbox envelope is invalid")
        try:
            return envelope_from_row(
                event_id=self.id,
                owner=self.owner,
                contract=self.contract,
                version=self.version,
                payload=self.payload,
                scope_raw=self.scope_json,
                resource_raw=self.resource_json,
                idempotency_key=self.idempotency_key,
                correlation_id=self.correlation_id,
                created_at=self.created_at,
            )
        except (ValidationError, TypeError, ValueError):
            raise OutboxEnvelopeError("outbox envelope is invalid") from None


class PostgreSQLEventOutbox:
    """Store outbox rows in the caller-owned PostgreSQL transaction."""

    def enqueue(
        self,
        connection,
        *,
        owner: str,
        contract: str,
        version: str,
        payload: Mapping[str, Any],
        idempotency_key: str | None = None,
        scope: ScopeRef | None = None,
        resource: ResourceRef | None = None,
        correlation_id: str | None = None,
    ) -> str:
        snapshot = _json_snapshot(payload)
        event_id = str(uuid.uuid4())
        created_at = datetime.now(UTC)
        persisted_scope = dump_scope(scope or ScopeRef.installation())
        persisted_resource = dump_resource(resource)
        try:
            envelope = envelope_from_row(
                event_id=event_id,
                owner=owner,
                contract=contract,
                version=version,
                payload=snapshot,
                scope_raw=persisted_scope,
                resource_raw=persisted_resource,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
                created_at=created_at,
            )
        except (ValidationError, TypeError, ValueError):
            raise OutboxEnvelopeError("outbox envelope is invalid") from None
        persisted_scope = dump_scope(envelope.scope)
        persisted_resource = dump_resource(envelope.resource)
        payload_json = json.dumps(
            envelope.payload, sort_keys=True, separators=(",", ":")
        )
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO plaik_core.plaik_event_outbox
                    (id, owner, contract, version, payload_json, idempotency_key,
                     created_at, scope_json, resource_json, correlation_id)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb, %s::jsonb, %s)
                ON CONFLICT (owner, contract, idempotency_key)
                    WHERE idempotency_key IS NOT NULL
                DO UPDATE SET id = plaik_core.plaik_event_outbox.id
                RETURNING id
                """,
                (
                    envelope.id,
                    envelope.owner,
                    envelope.contract,
                    envelope.version,
                    payload_json,
                    envelope.idempotency_key,
                    envelope.created_at,
                    persisted_scope,
                    persisted_resource,
                    envelope.correlation_id,
                ),
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError("PostgreSQL outbox insert returned no identity")
        return str(row[0])

    def claim_pending(
        self, connection, *, limit: int = 100
    ) -> tuple[PostgreSQLOutboxEvent, ...]:
        if not 1 <= limit <= 1000:
            raise ValueError("outbox dispatch limit must be between 1 and 1000")
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, owner, contract, version, payload_json,
                       idempotency_key, attempt_count,
                       scope_json, resource_json, correlation_id, created_at
                FROM plaik_core.plaik_event_outbox
                WHERE dispatched_at IS NULL
                  AND dead_at IS NULL
                  AND available_at <= clock_timestamp()
                ORDER BY available_at, created_at, id
                FOR UPDATE SKIP LOCKED
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return tuple(
            PostgreSQLOutboxEvent(
                id=str(row[0]),
                owner=str(row[1]),
                contract=str(row[2]),
                version=str(row[3]),
                payload=row[4] if isinstance(row[4], dict) else json.loads(row[4]),
                idempotency_key=row[5],
                attempt_count=int(row[6]),
                scope_json=row[7],
                resource_json=row[8],
                correlation_id=row[9],
                created_at=row[10],
            )
            for row in rows
        )

    def mark_dispatched(self, connection, event_id: str) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE plaik_core.plaik_event_outbox
                SET dispatched_at = %s, last_error_code = NULL
                WHERE id = %s AND dispatched_at IS NULL AND dead_at IS NULL
                """,
                (datetime.now(UTC), event_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("outbox event is not pending")

    def record_failure(
        self,
        connection,
        event_id: str,
        *,
        error_code: str,
        max_attempts: int = 8,
        backoff_seconds: int = 5,
    ) -> bool:
        if not _ERROR_CODE.fullmatch(error_code):
            raise ValueError("outbox error code is invalid")
        if not 1 <= max_attempts <= 100:
            raise ValueError("outbox max attempts must be between 1 and 100")
        if not 1 <= backoff_seconds <= 3600:
            raise ValueError("outbox backoff must be between 1 and 3600 seconds")
        now = datetime.now(UTC)
        retry_at = now + timedelta(seconds=backoff_seconds)
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE plaik_core.plaik_event_outbox
                SET attempt_count = attempt_count + 1,
                    last_error_code = %s,
                    available_at = CASE
                        WHEN attempt_count + 1 >= %s THEN available_at
                        ELSE %s
                    END,
                    dead_at = CASE
                        WHEN attempt_count + 1 >= %s THEN %s
                        ELSE NULL
                    END
                WHERE id = %s AND dispatched_at IS NULL AND dead_at IS NULL
                RETURNING dead_at IS NOT NULL
                """,
                (error_code, max_attempts, retry_at, max_attempts, now, event_id),
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError("outbox event is not pending")
        return bool(row[0])

    def requeue_dead_letter(self, connection, event_id: str) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE plaik_core.plaik_event_outbox
                SET dead_at = NULL,
                    available_at = %s,
                    attempt_count = 0,
                    last_error_code = NULL
                WHERE id = %s AND dispatched_at IS NULL AND dead_at IS NOT NULL
                """,
                (datetime.now(UTC), event_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("outbox event is not a dead letter")
