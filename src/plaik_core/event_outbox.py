"""Durable transaction-coupled event outbox primitives."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from plaik_contracts import EventEnvelope, ResourceRef, ScopeRef

from .envelope import dump_resource, dump_scope, envelope_from_row
from .extension_runtime import EventBus, _json_snapshot


_QUARANTINE_REASON = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class OutboxEnvelopeError(ValueError):
    """An outbox row is not a valid EventEnvelope."""


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
        except (ValidationError, TypeError, ValueError) as error:
            raise OutboxEnvelopeError("outbox envelope is invalid") from error


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
            ("quarantined_at", "TEXT"),
            ("quarantine_reason", "TEXT"),
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
        try:
            connection.execute(
                """
                INSERT INTO plaik_event_outbox
                    (id, owner, contract, version, payload_json, idempotency_key,
                     created_at, scope_json, resource_json, correlation_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.id,
                    envelope.owner,
                    envelope.contract,
                    envelope.version,
                    payload_json,
                    envelope.idempotency_key,
                    envelope.created_at.isoformat(),
                    persisted_scope,
                    persisted_resource,
                    envelope.correlation_id,
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
        return envelope.id

    def pending(
        self, connection: sqlite3.Connection, *, limit: int = 100
    ) -> tuple[OutboxEvent, ...]:
        if not 1 <= limit <= 1000:
            raise ValueError("outbox dispatch limit must be between 1 and 1000")
        events: list[OutboxEvent] = []
        for row in self._pending_rows(connection, limit=limit):
            event = self._event_from_row(row)
            if event is not None:
                events.append(event)
        return tuple(events)

    def _pending_rows(
        self, connection: sqlite3.Connection, *, limit: int
    ) -> tuple[tuple[Any, ...], ...]:
        rows = connection.execute(
            """
            SELECT id, owner, contract, version, payload_json, idempotency_key,
                   created_at, scope_json, resource_json, correlation_id
            FROM plaik_event_outbox
            WHERE dispatched_at IS NULL AND quarantined_at IS NULL
            ORDER BY created_at, id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return tuple(rows)

    def quarantined(
        self, connection: sqlite3.Connection, *, limit: int = 100
    ) -> tuple[tuple[str, str], ...]:
        if not 1 <= limit <= 1000:
            raise ValueError("outbox dispatch limit must be between 1 and 1000")
        rows = connection.execute(
            """
            SELECT id, quarantine_reason
            FROM plaik_event_outbox
            WHERE quarantined_at IS NOT NULL
            ORDER BY quarantined_at, id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return tuple((str(row[0]), str(row[1] or "invalid_envelope")) for row in rows)

    def quarantine(
        self, connection: sqlite3.Connection, event_id: str, *, reason: str
    ) -> None:
        if not _QUARANTINE_REASON.fullmatch(reason):
            raise ValueError("outbox quarantine reason is invalid")
        cursor = connection.execute(
            """
            UPDATE plaik_event_outbox
            SET quarantined_at = ?, quarantine_reason = ?
            WHERE id = ? AND dispatched_at IS NULL AND quarantined_at IS NULL
            """,
            (datetime.now(UTC).isoformat(), reason, event_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("outbox event is not pending")

    def mark_dispatched(self, connection: sqlite3.Connection, event_id: str) -> None:
        cursor = connection.execute(
            """
            UPDATE plaik_event_outbox SET dispatched_at = ?
            WHERE id = ? AND dispatched_at IS NULL AND quarantined_at IS NULL
            """,
            (datetime.now(UTC).isoformat(), event_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("outbox event is not pending")

    def _event_from_row(self, row: tuple[Any, ...]) -> OutboxEvent | None:
        try:
            payload = json.loads(row[4], parse_constant=_reject_json_constant)
            json.dumps(payload, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        return OutboxEvent(
            id=str(row[0]),
            owner=str(row[1]),
            contract=str(row[2]),
            version=str(row[3]),
            payload=payload,
            idempotency_key=row[5],
            created_at=str(row[6]),
            scope_json=row[7],
            resource_json=row[8],
            correlation_id=row[9],
        )


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"nonstandard JSON constant: {value}")


class EventOutboxDispatcher:
    def __init__(self, outbox: SQLiteEventOutbox, bus: EventBus) -> None:
        self.outbox = outbox
        self.bus = bus

    def dispatch(self, connection: sqlite3.Connection, *, limit: int = 100) -> int:
        if not 1 <= limit <= 1000:
            raise ValueError("outbox dispatch limit must be between 1 and 1000")
        delivered = 0
        while delivered < limit:
            rows = self.outbox._pending_rows(connection, limit=limit)
            if not rows:
                break
            quarantined = 0
            for row in rows:
                event = self.outbox._event_from_row(row)
                if event is None:
                    self.outbox.quarantine(
                        connection, str(row[0]), reason="invalid_payload_json"
                    )
                    connection.commit()
                    quarantined += 1
                    continue
                try:
                    envelope = event.as_envelope()
                except OutboxEnvelopeError:
                    self.outbox.quarantine(
                        connection, event.id, reason="invalid_envelope"
                    )
                    connection.commit()
                    quarantined += 1
                    continue
                self.bus.publish(
                    owner=envelope.owner,
                    contract=envelope.contract,
                    version=envelope.version,
                    payload=envelope.payload,
                    idempotency_key=envelope.idempotency_key,
                    scope=envelope.scope,
                    resource=envelope.resource,
                    correlation_id=envelope.correlation_id,
                )
                self.outbox.mark_dispatched(connection, event.id)
                connection.commit()
                delivered += 1
                if delivered >= limit:
                    break
            if quarantined == 0:
                break
        return delivered


class SqliteDurableEvents:
    """Persist then dispatch: SQLite commit is the EventPublisher linearization point."""

    def __init__(
        self,
        path: Path,
        bus: EventBus,
        *,
        dispatch_after_enqueue: bool = True,
    ) -> None:
        self.path = Path(path)
        self.bus = bus
        self.outbox = SQLiteEventOutbox()
        self.dispatcher = EventOutboxDispatcher(self.outbox, bus)
        self._lock = threading.RLock()
        self._idle = threading.Condition(self._lock)
        self._dispatch_after_enqueue = dispatch_after_enqueue
        self._dispatching = False
        self._dispatch_thread: int | None = None

    def defer_dispatch(self) -> None:
        """Hold rows until subscribers from the current host sync exist."""

        with self._idle:
            self._dispatch_after_enqueue = False
            while self._dispatching and self._dispatch_thread != threading.get_ident():
                self._idle.wait()

    def enable_live_dispatch(self) -> None:
        with self._idle:
            self._dispatch_after_enqueue = True

    def persist(
        self,
        *,
        owner: str,
        contract: str,
        version: str,
        payload: Mapping[str, Any],
        idempotency_key: str | None = None,
        scope: ScopeRef | None = None,
        resource: ResourceRef | None = None,
        correlation_id: str | None = None,
    ) -> None:
        """Enqueue and commit under the caller's authorization lock.

        Host generation fencing must hold until this method returns so a stale
        publisher cannot commit after unbind. Do not claim or drain here:
        wait-for-dispatch while holding that lock deadlocks a handler that
        re-enters the host. The caller must ``drain()`` after releasing it.
        """

        with self._idle:
            connection = self._open()
            try:
                self.outbox.enqueue(
                    connection,
                    owner=owner,
                    contract=contract,
                    version=version,
                    payload=payload,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    resource=resource,
                    correlation_id=correlation_id,
                )
                connection.commit()
            finally:
                connection.close()

    def publish(
        self,
        *,
        owner: str,
        contract: str,
        version: str,
        payload: Mapping[str, Any],
        idempotency_key: str | None = None,
        scope: ScopeRef | None = None,
        resource: ResourceRef | None = None,
        correlation_id: str | None = None,
    ) -> int:
        self.persist(
            owner=owner,
            contract=contract,
            version=version,
            payload=payload,
            idempotency_key=idempotency_key,
            scope=scope,
            resource=resource,
            correlation_id=correlation_id,
        )
        return self.drain()

    def drain(self, *, limit: int = 100) -> int:
        """Deliver pending rows after crash between commit and ack."""

        with self._idle:
            if not self._claim_dispatch_locked():
                return 0
        try:
            return self._drain_claimed(limit=limit)
        finally:
            self._release_dispatch()

    def recover_subscribers(self, *, limit: int = 100) -> int:
        with self._idle:
            while self._dispatching and self._dispatch_thread != threading.get_ident():
                self._idle.wait()
            self._dispatch_after_enqueue = True
            if not self._claim_dispatch_locked():
                return 0
        try:
            return self._drain_claimed(limit=limit)
        finally:
            self._release_dispatch()

    def _claim_dispatch_locked(self) -> bool:
        me = threading.get_ident()
        if self._dispatching and self._dispatch_thread == me:
            return False
        while self._dispatching:
            self._idle.wait()
            if not self._dispatch_after_enqueue and not self._dispatching:
                return False
        if not self._dispatch_after_enqueue:
            return False
        self._dispatching = True
        self._dispatch_thread = me
        return True

    def _release_dispatch(self) -> None:
        with self._idle:
            self._dispatching = False
            self._dispatch_thread = None
            self._idle.notify_all()

    def _drain_claimed(self, *, limit: int) -> int:
        delivered = 0
        remaining = limit
        while remaining > 0:
            connection = self._open()
            try:
                batch = self.dispatcher.dispatch(connection, limit=remaining)
            finally:
                connection.close()
            if batch == 0:
                break
            delivered += batch
            remaining -= batch
        return delivered

    def pending_count(self) -> int:
        with self._lock:
            connection = self._open()
            try:
                return len(self.outbox.pending(connection))
            finally:
                connection.close()

    def _open(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30)
        self.outbox.ensure_schema(connection)
        connection.commit()
        return connection


class DelegatingDurableEvents:
    """Route persist/drain to the live backend without swapping host publication."""

    def __init__(self, resolve: Callable[[], Any]) -> None:
        self._resolve = resolve

    def persist(
        self,
        *,
        owner: str,
        contract: str,
        version: str,
        payload: Mapping[str, Any],
        idempotency_key: str | None = None,
        scope: ScopeRef | None = None,
        resource: ResourceRef | None = None,
        correlation_id: str | None = None,
    ) -> None:
        self._resolve().persist(
            owner=owner,
            contract=contract,
            version=version,
            payload=payload,
            idempotency_key=idempotency_key,
            scope=scope,
            resource=resource,
            correlation_id=correlation_id,
        )

    def publish(
        self,
        *,
        owner: str,
        contract: str,
        version: str,
        payload: Mapping[str, Any],
        idempotency_key: str | None = None,
        scope: ScopeRef | None = None,
        resource: ResourceRef | None = None,
        correlation_id: str | None = None,
    ) -> int:
        return self._resolve().publish(
            owner=owner,
            contract=contract,
            version=version,
            payload=payload,
            idempotency_key=idempotency_key,
            scope=scope,
            resource=resource,
            correlation_id=correlation_id,
        )

    def drain(self, *, limit: int = 100) -> int:
        return self._resolve().drain(limit=limit)

    def defer_dispatch(self) -> None:
        self._resolve().defer_dispatch()

    def enable_live_dispatch(self) -> None:
        self._resolve().enable_live_dispatch()

    def recover_subscribers(self, *, limit: int = 100) -> int:
        return self._resolve().recover_subscribers(limit=limit)
