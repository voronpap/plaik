from .migrations import Migration

POSTGRESQL_EVENT_OUTBOX_ENVELOPE_MIGRATION = Migration(
    owner="core",
    version="0008-event-outbox-envelope",
    statements=(
        "ALTER TABLE plaik_event_outbox ADD COLUMN scope_json JSONB",
        "ALTER TABLE plaik_event_outbox ADD COLUMN resource_json JSONB",
        "ALTER TABLE plaik_event_outbox ADD COLUMN correlation_id TEXT",
    ),
)
