"""Durable transaction-coupled event outbox primitives."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

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

    def enqueue(
        self,
        connection: sqlite3.Connection,
        *,
        owner: str,
        contract: str,
        version: str,
        payload: Mapping[str, Any],
        idempotency_key: str | None = None,
    ) -> str:
        snapshot = _json_snapshot(payload)
        event_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        try:
            connection.execute(
                """
                INSERT INTO plaik_event_outbox
                    (id, owner, contract, version, payload_json, idempotency_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    owner,
                    contract,
                    version,
                    json.dumps(snapshot, sort_keys=True, separators=(",", ":")),
                    idempotency_key,
                    created_at,
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
            SELECT id, owner, contract, version, payload_json, idempotency_key, created_at
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
            self.bus.publish(
                owner=event.owner,
                contract=event.contract,
                version=event.version,
                payload=event.payload,
            )
            self.outbox.mark_dispatched(connection, event.id)
            connection.commit()
            delivered += 1
        return delivered
