from .migrations import Migration

POSTGRESQL_JOB_QUEUE_MIGRATION = Migration(
    owner="core",
    version="0009-job-queue",
    statements=(
        """
        CREATE TABLE plaik_job_queue (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            payload_json JSONB NOT NULL,
            status TEXT NOT NULL
                CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            maximum_attempts INTEGER NOT NULL
                CHECK (maximum_attempts BETWEEN 1 AND 32),
            scheduled_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            lease_owner TEXT,
            lease_expires_at TIMESTAMPTZ,
            fencing_token BIGINT NOT NULL DEFAULT 0
                CHECK (fencing_token >= 0),
            error_code TEXT,
            CHECK (
                NOT (
                    status = 'running'
                    AND (lease_owner IS NULL OR lease_expires_at IS NULL)
                )
            ),
            CHECK (
                NOT (
                    status <> 'running'
                    AND (lease_owner IS NOT NULL OR lease_expires_at IS NOT NULL)
                )
            )
        )
        """,
        """
        CREATE UNIQUE INDEX plaik_job_queue_idempotency_idx
            ON plaik_job_queue (idempotency_key)
        """,
        """
        CREATE INDEX plaik_job_queue_due_idx
            ON plaik_job_queue (scheduled_at, created_at, id)
            WHERE status = 'queued'
        """,
        """
        CREATE INDEX plaik_job_queue_active_type_idx
            ON plaik_job_queue (type)
            WHERE status IN ('queued', 'running')
        """,
    ),
)
