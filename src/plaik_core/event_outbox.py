"""Durable transaction-coupled event outbox primitives."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from plaik_contracts import EventEnvelope, ResourceRef, ScopeRef

from .envelope import dump_resource, dump_scope, envelope_from_row
from .extension_runtime import EventBus, _json_snapshot


@dataclass(frozen=True, slots=True)
class OutboxEvent:
    id: str
    owner: str
    contract: str
    version: str
    payload: dict[str, Any]
    idempotency_key: str | None
    created_at: str
    scope_json: str | None = None
    resource_json: str | None = None
    correlation_id: str | None = None

    def as_envelope(self) -> EventEnvelope:
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


class SQLiteEventOutbox:
    """Persist events in the caller's SQLite transaction before dispatch."""

    def ensure_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS plaik_event_outbox (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                contract TEXT NOT NULL,
                version TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                idempotency_key TEXT,
                created_at TEXT NOT NULL,
                dispatched_at TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_plaik_event_outbox_idempotency
            ON plaik_event_outbox(owner, contract, idempotency_key)
            WHERE idempotency_key IS NOT NULL
            """
        )
        for column, declaration in (
            ("scope_json", "TEXT"),
            ("resource_json", "TEXT"),
            ("correlation_id", "TEXT"),
        ):
            try:
                connection.execute(
                    f"ALTER TABLE plaik_event_outbox ADD COLUMN {column} {declaration}"
                )
            except sqlite3.OperationalError as error:
                if "duplicate column" not in str(error).casefold():
                    raise

    def enqueue(
        self,
        connection: sqlite3.Connection,
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
        created_at = datetime.now(UTC).isoformat()
        persisted_scope = dump_scope(scope or ScopeRef.installation())
        persisted_resource = dump_resource(resource)
        try:
            connection.execute(
                """
                INSERT INTO plaik_event_outbox
                    (id, owner, contract, version, payload_json, idempotency_key,
                     created_at, scope_json, resource_json, correlation_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    owner,
                    contract,
                    version,
                    json.dumps(snapshot, sort_keys=True, separators=(",", ":")),
                    idempotency_key,
                    created_at,
                    persisted_scope,
                    persisted_resource,
                    correlation_id,
                ),
            )
        except sqlite3.IntegrityError:
            if idempotency_key is None:
                raise
            row = connection.execute(
                """
                SELECT id FROM plaik_event_outbox
                WHERE owner = ? AND contract = ? AND idempotency_key = ?
                """,
                (owner, contract, idempotency_key),
            ).fetchone()
            if row is None:
                raise
            return str(row[0])
        return event_id

    def pending(
        self, connection: sqlite3.Connection, *, limit: int = 100
    ) -> tuple[OutboxEvent, ...]:
        if not 1 <= limit <= 1000:
            raise ValueError("outbox dispatch limit must be between 1 and 1000")
        rows = connection.execute(
            """
            SELECT id, owner, contract, version, payload_json, idempotency_key,
                   created_at, scope_json, resource_json, correlation_id
            FROM plaik_event_outbox
            WHERE dispatched_at IS NULL
            ORDER BY created_at, id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return tuple(
            OutboxEvent(
                id=str(row[0]),
                owner=str(row[1]),
                contract=str(row[2]),
                version=str(row[3]),
                payload=json.loads(row[4]),
                idempotency_key=row[5],
                created_at=str(row[6]),
                scope_json=row[7],
                resource_json=row[8],
                correlation_id=row[9],
            )
            for row in rows
        )

    def mark_dispatched(self, connection: sqlite3.Connection, event_id: str) -> None:
        cursor = connection.execute(
            """
            UPDATE plaik_event_outbox SET dispatched_at = ?
            WHERE id = ? AND dispatched_at IS NULL
            """,
            (datetime.now(UTC).isoformat(), event_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("outbox event is not pending")


class EventOutboxDispatcher:
    def __init__(self, outbox: SQLiteEventOutbox, bus: EventBus) -> None:
        self.outbox = outbox
        self.bus = bus

    def dispatch(self, connection: sqlite3.Connection, *, limit: int = 100) -> int:
        delivered = 0
        for event in self.outbox.pending(connection, limit=limit):
            envelope = event.as_envelope()
            self.bus.publish(
                owner=event.owner,
                contract=event.contract,
                version=event.version,
                payload=event.payload,
                idempotency_key=event.idempotency_key,
                scope=envelope.scope,
                resource=envelope.resource,
                correlation_id=envelope.correlation_id,
            )
            self.outbox.mark_dispatched(connection, event.id)
            connection.commit()
            delivered += 1
        return delivered
