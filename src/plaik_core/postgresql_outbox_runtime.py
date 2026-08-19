"""Composition facade for bounded PostgreSQL outbox dispatch."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from typing import Any

from plaik_contracts import ResourceRef, ScopeRef

from .database import DatabaseConnection
from .extension_runtime import EventBus
from .postgresql_event_outbox import PostgreSQLEventOutbox
from .postgresql_outbox_dispatch import (
    DurableEventSink,
    EventBusSink,
    PostgreSQLOutboxDispatcher,
)


class PostgreSQLOutboxRuntime:
    """Own a dispatch connection for one bounded outbox drain operation."""

    def __init__(
        self,
        connect: Callable[[], DatabaseConnection],
        sink: DurableEventSink,
    ) -> None:
        self._connect = connect
        self._dispatcher = PostgreSQLOutboxDispatcher(PostgreSQLEventOutbox(), sink)

    def dispatch(
        self,
        *,
        limit: int = 100,
        max_attempts: int = 8,
        base_backoff_seconds: int = 5,
    ) -> int:
        connection = self._connect()
        try:
            return self._dispatcher.dispatch(
                connection,
                limit=limit,
                max_attempts=max_attempts,
                base_backoff_seconds=base_backoff_seconds,
            )
        finally:
            try:
                connection.close()
            except Exception:
                pass


class PostgreSQLDurableEvents:
    """Persist then dispatch: PostgreSQL commit is the EventPublisher linearization point."""

    def __init__(
        self,
        connect: Callable[[], DatabaseConnection],
        bus: EventBus,
        *,
        dispatch_after_enqueue: bool = True,
    ) -> None:
        self._connect = connect
        self.bus = bus
        self.outbox = PostgreSQLEventOutbox()
        self._runtime = PostgreSQLOutboxRuntime(connect, EventBusSink(bus))
        self._lock = threading.RLock()
        self._idle = threading.Condition(self._lock)
        self._dispatch_after_enqueue = dispatch_after_enqueue
        self._dispatching = False
        self._dispatch_thread: int | None = None

    def defer_dispatch(self) -> None:
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

        Do not claim or drain here: wait-for-dispatch while holding that lock
        deadlocks a handler that re-enters the host.
        """

        with self._idle:
            connection = self._connect()
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
                try:
                    connection.close()
                except Exception:
                    pass

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
        with self._idle:
            if not self._claim_dispatch_locked():
                return 0
        try:
            return self._runtime.dispatch(limit=limit)
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
            return self._runtime.dispatch(limit=limit)
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
