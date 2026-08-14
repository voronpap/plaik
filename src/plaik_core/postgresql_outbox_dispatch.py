"""Crash-safe PostgreSQL outbox dispatch."""

from __future__ import annotations

from typing import Protocol

from .postgresql_event_outbox import PostgreSQLEventOutbox, PostgreSQLOutboxEvent


class DurableEventSink(Protocol):
    """Deliver one immutable outbox event using its id for downstream dedupe."""

    def deliver(self, event: PostgreSQLOutboxEvent) -> None: ...


class PermanentOutboxDeliveryError(RuntimeError):
    """Delivery cannot succeed without operator or contract intervention."""


class PostgreSQLOutboxDispatcher:
    """Dispatch one locked row per transaction with bounded retry semantics."""

    def __init__(self, outbox: PostgreSQLEventOutbox, sink: DurableEventSink) -> None:
        self.outbox = outbox
        self.sink = sink

    def dispatch(
        self,
        connection,
        *,
        limit: int = 100,
        max_attempts: int = 8,
        base_backoff_seconds: int = 5,
    ) -> int:
        if not 1 <= limit <= 1000:
            raise ValueError("outbox dispatch limit must be between 1 and 1000")
        if not 1 <= max_attempts <= 100:
            raise ValueError("outbox max attempts must be between 1 and 100")
        if not 1 <= base_backoff_seconds <= 3600:
            raise ValueError("outbox backoff must be between 1 and 3600 seconds")

        delivered = 0
        for _ in range(limit):
            claimed = self.outbox.claim_pending(connection, limit=1)
            if not claimed:
                connection.rollback()
                break
            event = claimed[0]
            try:
                self.sink.deliver(event)
            except PermanentOutboxDeliveryError:
                self.outbox.record_failure(
                    connection,
                    event.id,
                    error_code="delivery_permanent",
                    max_attempts=event.attempt_count + 1,
                    backoff_seconds=base_backoff_seconds,
                )
                connection.commit()
                continue
            except Exception:
                exponent = min(event.attempt_count, 10)
                delay = min(base_backoff_seconds * (2**exponent), 3600)
                self.outbox.record_failure(
                    connection,
                    event.id,
                    error_code="delivery_failed",
                    max_attempts=max_attempts,
                    backoff_seconds=delay,
                )
                connection.commit()
                continue

            try:
                self.outbox.mark_dispatched(connection, event.id)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            delivered += 1
        return delivered
