"""Composition facade for bounded PostgreSQL outbox dispatch."""

from __future__ import annotations

from collections.abc import Callable

from .database import DatabaseConnection
from .postgresql_event_outbox import PostgreSQLEventOutbox
from .postgresql_outbox_dispatch import DurableEventSink, PostgreSQLOutboxDispatcher


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
