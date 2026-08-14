from .migrations import Migration

POSTGRESQL_EVENT_OUTBOX_MIGRATION = Migration(
    owner="core",
    version="0007-event-outbox",
    statements=(
        "CREATE TABLE plaik_event_outbox (id TEXT PRIMARY KEY, owner TEXT NOT NULL, contract TEXT NOT NULL, version TEXT NOT NULL, payload_json JSONB NOT NULL, idempotency_key TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0), last_error_code TEXT, dispatched_at TIMESTAMPTZ, dead_at TIMESTAMPTZ, CHECK (NOT (dispatched_at IS NOT NULL AND dead_at IS NOT NULL)))",
        "CREATE UNIQUE INDEX plaik_event_outbox_idempotency_idx ON plaik_event_outbox (owner, contract, idempotency_key) WHERE idempotency_key IS NOT NULL",
        "CREATE INDEX plaik_event_outbox_pending_idx ON plaik_event_outbox (available_at, created_at, id) WHERE dispatched_at IS NULL AND dead_at IS NULL",
    ),
)
