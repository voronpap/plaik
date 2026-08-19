"""Production PostgreSQL composition, migrations, and Core bootstrap.

The module imports psycopg lazily so reference/SQLite installations can import
Core without the PostgreSQL extra.  Credentials are resolved only when a new
owned connection is opened and are passed to psycopg as keyword arguments,
never interpolated into a DSN or an exception.
"""

from __future__ import annotations

import hashlib
import importlib
import re
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .database import (
    ConnectionFactory,
    DatabaseConnection,
    DatabasePreflightResult,
    preflight_connection,
)
from .installer_config import InstallerConfiguration, PostgreSQLDatabase
from .migrations import (
    Migration,
    MigrationApplyError,
    MigrationChecksumError,
    MigrationError,
    MigrationLedgerEntry,
    MigrationLockError,
    MigrationRunResult,
    MigrationStateError,
    MigrationStatus,
    OWNER_PATTERN,
    _erase_sql_literals_and_comments,
)
from .postgresql_event_outbox_migration import POSTGRESQL_EVENT_OUTBOX_MIGRATION
from .postgresql_event_outbox_envelope_migration import (
    POSTGRESQL_EVENT_OUTBOX_ENVELOPE_MIGRATION,
)
from .secret_store import SecretProvider, SecretProviderRegistry


META_SCHEMA = "plaik_meta"
CORE_SCHEMA = "plaik_core"
LEDGER_TABLE = "plaik_migration_ledger"
ATTEMPT_TABLE = "plaik_migration_attempts"
MIGRATION_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"plaik-v2:database-migrations:v1").digest()[:8],
    byteorder="big",
    signed=True,
)

POSTGRESQL_CORE_MIGRATIONS = (
    Migration(
        owner="core",
        version="0001-platform-context",
        statements=(
            """
            CREATE TABLE plaik_installations (
                id TEXT PRIMARY KEY,
                profile TEXT NOT NULL,
                locale TEXT NOT NULL,
                timezone TEXT NOT NULL,
                public_url TEXT NOT NULL,
                config_digest CHAR(64) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """,
            """
            CREATE TABLE plaik_store_groups (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL
                    REFERENCES plaik_installations(id),
                created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """,
            """
            CREATE TABLE plaik_stores (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL
                    REFERENCES plaik_installations(id),
                group_id TEXT NOT NULL REFERENCES plaik_store_groups(id),
                created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """,
        ),
    ),
    Migration(
        owner="core",
        version="0002-runtime-operations",
        statements=(
            """
            CREATE TABLE plaik_runtime_schema_metadata (
                singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
                schema_generation INTEGER NOT NULL CHECK (schema_generation >= 1),
                minimum_reader_generation INTEGER NOT NULL
                    CHECK (
                        minimum_reader_generation >= 1
                        AND minimum_reader_generation <= schema_generation
                    ),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """,
            """
            INSERT INTO plaik_runtime_schema_metadata
                (singleton, schema_generation, minimum_reader_generation)
            VALUES (1, 2, 1)
            """,
        ),
    ),
    Migration(
        owner="core",
        version="0003-identity-security",
        statements=(
            """
            CREATE TABLE plaik_roles (
                id TEXT PRIMARY KEY,
                permissions JSONB NOT NULL,
                protected BOOLEAN NOT NULL DEFAULT FALSE
            )
            """,
            """
            INSERT INTO plaik_roles (id, permissions, protected)
            VALUES (
                'super_admin',
                '["*"]'::jsonb,
                TRUE
            )
            ON CONFLICT (id) DO NOTHING
            """,
            """
            CREATE TABLE plaik_users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """,
            """
            CREATE UNIQUE INDEX plaik_users_email_lower_idx
                ON plaik_users (lower(email))
            """,
            """
            CREATE TABLE plaik_user_roles (
                user_id TEXT NOT NULL
                    REFERENCES plaik_users(id) ON DELETE CASCADE,
                role_id TEXT NOT NULL
                    REFERENCES plaik_roles(id) ON DELETE RESTRICT,
                PRIMARY KEY (user_id, role_id)
            )
            """,
            """
            CREATE TABLE plaik_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL
                    REFERENCES plaik_users(id) ON DELETE CASCADE,
                token_digest TEXT NOT NULL,
                issued_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked_at TIMESTAMPTZ
            )
            """,
            """
            CREATE TABLE plaik_journal_lines (
                journal_id TEXT NOT NULL,
                sequence BIGINT NOT NULL,
                content TEXT NOT NULL,
                PRIMARY KEY (journal_id, sequence)
            )
            """,
            # Core platform SettingsStore shape (version + scopes), not package
            # product data. PostgreSQL installs use this table as the live store;
            # SQLite/reference installs keep the JSON file.
            """
            CREATE TABLE plaik_settings_registry (
                singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL,
                scopes JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """,
            """
            UPDATE plaik_runtime_schema_metadata
            SET schema_generation = 3,
                minimum_reader_generation = 1,
                updated_at = clock_timestamp()
            WHERE singleton = 1
            """,
        ),
    ),
    Migration(
        owner="core",
        version="0004-integrity-checkpoints",
        statements=(
            """
            CREATE TABLE plaik_integrity_checkpoints (
                sequence BIGINT PRIMARY KEY,
                format_version SMALLINT NOT NULL DEFAULT 2,
                installation_id TEXT NOT NULL,
                journal TEXT NOT NULL
                    CHECK (journal IN ('audit', 'operations')),
                event_count BIGINT NOT NULL CHECK (event_count >= 0),
                head_hash CHAR(64) NOT NULL,
                recorded_at TIMESTAMPTZ NOT NULL,
                previous_hash CHAR(64) NOT NULL,
                checkpoint_hash CHAR(64) NOT NULL,
                recovery_epoch INTEGER NOT NULL DEFAULT 0 CHECK (recovery_epoch >= 0),
                recovery_operation_id TEXT,
                recovery_actor_id TEXT,
                recovery_manifest_sha256 CHAR(64),
                CHECK (head_hash ~ '^[0-9a-f]{64}$'),
                CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
                CHECK (checkpoint_hash ~ '^[0-9a-f]{64}$'),
                CHECK (
                    recovery_manifest_sha256 IS NULL
                    OR recovery_manifest_sha256 ~ '^[0-9a-f]{64}$'
                )
            )
            """,
            """
            CREATE INDEX plaik_integrity_checkpoints_latest_idx
                ON plaik_integrity_checkpoints (
                    installation_id,
                    journal,
                    sequence DESC
                )
            """,
            """
            UPDATE plaik_runtime_schema_metadata
            SET schema_generation = 4,
                minimum_reader_generation = 1,
                updated_at = clock_timestamp()
            WHERE singleton = 1
            """,
        ),
    ),
    Migration(
        owner="core",
        version="0005-session-cleanup-indexes",
        statements=(
            """
            CREATE INDEX plaik_sessions_terminal_expiry_idx
                ON plaik_sessions (expires_at, id)
                WHERE revoked_at IS NULL
            """,
            """
            CREATE INDEX plaik_sessions_terminal_revoked_idx
                ON plaik_sessions (revoked_at, id)
                WHERE revoked_at IS NOT NULL
            """,
        ),
    ),
    Migration(
        owner="core",
        version="0006-session-user-revocation-index",
        statements=(
            """
            CREATE INDEX plaik_sessions_active_user_idx
                ON plaik_sessions (user_id, id)
                WHERE revoked_at IS NULL
            """,
        ),
    ),
    POSTGRESQL_EVENT_OUTBOX_MIGRATION,
    POSTGRESQL_EVENT_OUTBOX_ENVELOPE_MIGRATION,
)

_POSTGRES_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,62}$")
_SIMPLE_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_SQLSTATE = re.compile(r"^[0-9A-Z]{5}$")
_ERROR_CLASS = re.compile(r"[^A-Za-z0-9_.-]")
_GLOBAL_COMMANDS = {
    "CHECKPOINT",
    "COPY",
    "DISCARD",
    "GRANT",
    "LISTEN",
    "LOAD",
    "NOTIFY",
    "REASSIGN",
    "RESET",
    "REVOKE",
    "SECURITY",
    "SET",
    "UNLISTEN",
}
_GLOBAL_CREATE_OBJECTS = {
    "ACCESS",
    "DATABASE",
    "EVENT",
    "EXTENSION",
    "FOREIGN",
    "LANGUAGE",
    "PUBLICATION",
    "ROLE",
    "SCHEMA",
    "SERVER",
    "SUBSCRIPTION",
    "TABLESPACE",
    "USER",
}
_GLOBAL_ALTER_OBJECTS = {
    "DATABASE",
    "DEFAULT",
    "EVENT",
    "EXTENSION",
    "FOREIGN",
    "LANGUAGE",
    "PUBLICATION",
    "ROLE",
    "SCHEMA",
    "SERVER",
    "SUBSCRIPTION",
    "SYSTEM",
    "TABLESPACE",
    "USER",
}
_GLOBAL_DROP_OBJECTS = _GLOBAL_CREATE_OBJECTS | {"OWNED"}

class PostgreSQLAdapterError(RuntimeError):
    """Base class for PostgreSQL adapter failures."""


class PostgreSQLDependencyError(PostgreSQLAdapterError):
    """The psycopg 3 runtime dependency is not installed."""


class PostgreSQLConfigurationError(PostgreSQLAdapterError):
    """Installer database configuration cannot create a safe connection."""


class PostgreSQLConnectionError(ConnectionError, PostgreSQLAdapterError):
    """A PostgreSQL connection failed without exposing its connection material."""


class PostgreSQLOwnershipError(MigrationError):
    """A migration owner does not have the required isolated schema/role."""


class PostgreSQLContextError(PostgreSQLAdapterError):
    """Persistent installation/store context is missing or has drifted."""


class PostgreSQLCommitUncertainError(MigrationError):
    """The driver lost the commit result and reconciliation was inconclusive."""


@dataclass(frozen=True, slots=True)
class PostgreSQLTimeouts:
    """Session safety timeouts applied by libpq before the first query."""

    statement_ms: int = 30_000
    lock_ms: int = 5_000
    idle_in_transaction_ms: int = 30_000

    def __post_init__(self) -> None:
        for name, value in (
            ("statement_ms", self.statement_ms),
            ("lock_ms", self.lock_ms),
            ("idle_in_transaction_ms", self.idle_in_transaction_ms),
        ):
            if not 1 <= value <= 3_600_000:
                raise ValueError(f"{name} must be between 1 and 3600000 milliseconds")

    @property
    def libpq_options(self) -> str:
        return " ".join(
            (
                f"-c statement_timeout={self.statement_ms}",
                f"-c lock_timeout={self.lock_ms}",
                "-c "
                f"idle_in_transaction_session_timeout={self.idle_in_transaction_ms}",
            )
        )


class PostgreSQLConnectionFactory:
    """Create psycopg 3 connections from validated config and a secret provider."""

    def __init__(
        self,
        configuration: InstallerConfiguration,
        secrets: SecretProvider | SecretProviderRegistry,
        *,
        timeouts: PostgreSQLTimeouts | None = None,
        application_name: str = "plaik-v2",
        connector: Callable[..., DatabaseConnection] | None = None,
        runtime: bool = False,
        checkpoint: bool = False,
    ) -> None:
        configuration = _validated_postgresql_configuration(configuration)
        if not application_name or len(application_name.encode("utf-8")) > 63:
            raise ValueError("PostgreSQL application_name must be 1-63 UTF-8 bytes")
        if any(ord(character) < 32 for character in application_name):
            raise ValueError("PostgreSQL application_name contains control characters")
        self._configuration = configuration
        self._secrets = secrets
        self._timeouts = timeouts or PostgreSQLTimeouts()
        self._application_name = application_name
        self._connector = connector
        if runtime and checkpoint:
            raise ValueError("PostgreSQL connection identity is ambiguous")
        self._runtime = runtime
        self._checkpoint = checkpoint

    def __call__(self) -> DatabaseConnection:
        database = self._configuration.database
        connector = self._connector or _load_psycopg_connector()
        try:
            password = self._resolve_password(database)
        except Exception as error:
            raise PostgreSQLConnectionError(
                "PostgreSQL credential resolution failed "
                f"({_safe_error_class(error)})"
            ) from None

        try:
            return connector(
                host=database.host,
                port=database.port,
                dbname=database.database,
                user=(
                    database.checkpoint_username
                    if self._checkpoint
                    else database.runtime_username if self._runtime else database.username
                ),
                password=password,
                sslmode=database.ssl_mode,
                connect_timeout=database.connect_timeout_seconds,
                application_name=self._application_name,
                target_session_attrs="read-write",
                options=self._timeouts.libpq_options,
                autocommit=False,
            )
        except Exception as error:
            raise PostgreSQLConnectionError(
                f"PostgreSQL connection failed ({_safe_error_class(error)})"
            ) from None
        finally:
            # Do not retain the resolved plaintext beyond the driver call.
            password = ""

    @property
    def configuration(self) -> InstallerConfiguration:
        """Return the revalidated immutable configuration used by this factory."""

        return self._configuration

    def _resolve_password(self, database: PostgreSQLDatabase) -> str:
        reference = (
            database.checkpoint_credential
            if self._checkpoint
            else database.runtime_credential if self._runtime else database.credential
        )
        if reference is None:
            raise PostgreSQLConfigurationError(
                "PostgreSQL runtime identity is not configured"
            )
        if isinstance(self._secrets, SecretProviderRegistry):
            value = self._secrets.resolve(reference)
        else:
            if self._secrets.name != reference.provider:
                raise PostgreSQLConfigurationError(
                    "configured PostgreSQL credential provider is unavailable"
                )
            value = self._secrets.read(reference.key, version=reference.version)
        return value.get_secret_value()

    def __repr__(self) -> str:
        database = self._configuration.database
        return (
            "PostgreSQLConnectionFactory("
            f"backend={database.backend.value!r}, ssl_mode={database.ssl_mode!r}, "
            f"credential={database.credential.redacted()!r})"
        )


@dataclass(frozen=True, slots=True)
class PostgreSQLOwnerScope:
    """Pre-provisioned NOLOGIN role and owned schema for one package owner."""

    owner: str
    schema: str
    role: str

    def __post_init__(self) -> None:
        if not OWNER_PATTERN.fullmatch(self.owner):
            raise ValueError("invalid PostgreSQL migration owner")
        _quote_identifier(self.schema)
        _quote_identifier(self.role)
        if self.owner == "core":
            if self.schema != CORE_SCHEMA:
                raise ValueError("Core migrations must use the protected Core schema")
        elif self.schema in {META_SCHEMA, CORE_SCHEMA, "public"}:
            raise ValueError("package scope cannot use a protected schema")
        else:
            expected_schema, expected_role = _package_scope_identifiers(self.owner)
            if self.schema != expected_schema or self.role != expected_role:
                raise ValueError("package scope must use canonical derived identifiers")

    @classmethod
    def for_package(cls, owner: str) -> "PostgreSQLOwnerScope":
        """Derive collision-resistant PostgreSQL identifiers from a package ID."""

        if not OWNER_PATTERN.fullmatch(owner) or owner == "core":
            raise ValueError("package owner must be a non-Core migration owner")
        schema, role = _package_scope_identifiers(owner)
        return cls(
            owner=owner,
            schema=schema,
            role=role,
        )


@dataclass(frozen=True, slots=True)
class PostgreSQLMigrationAttempt:
    event_id: int
    run_id: str
    owner: str
    version: str
    checksum: str
    event: str
    statement_ordinal: int | None
    sqlstate: str | None
    statement_fingerprint: str | None
    error_class: str | None
    recorded_at: str


@dataclass(frozen=True, slots=True)
class PostgreSQLBootstrapResult:
    preflight: DatabasePreflightResult
    migrations: MigrationRunResult


@dataclass(frozen=True, slots=True)
class _FailureEvidence:
    error_class: str
    sqlstate: str | None
    statement_ordinal: int | None
    statement_fingerprint: str | None

    @property
    def summary(self) -> str:
        parts = [self.error_class]
        if self.sqlstate is not None:
            parts.append(f"sqlstate={self.sqlstate}")
        if self.statement_ordinal is not None:
            parts.append(f"statement={self.statement_ordinal}")
        if self.statement_fingerprint is not None:
            parts.append(f"fingerprint={self.statement_fingerprint}")
        return "; ".join(parts)[:512]


class PostgreSQLMigrationRunner:
    """Run migrations under a session lock with durable, append-only evidence.

    Each migration is one PostgreSQL transaction.  A committed ``started`` event
    precedes it; the schema changes, authoritative ledger transition, and
    ``applied`` event then commit atomically. The advisory lock lives on a
    distinct connection unavailable to migration SQL. On rollback, the
    execution connection writes failed ledger state and safe evidence in a short
    separate transaction while that lock remains held. A process death leaves a
    start-only event, which the next lock holder classifies as interrupted.
    """

    def __init__(
        self,
        connect: ConnectionFactory,
        *,
        owner_scopes: Iterable[PostgreSQLOwnerScope] = (),
        lock_connect: ConnectionFactory | None = None,
        advisory_lock_key: int = MIGRATION_LOCK_KEY,
    ) -> None:
        if not -(2**63) <= advisory_lock_key < 2**63:
            raise ValueError("PostgreSQL advisory lock key must fit signed bigint")
        scope_batch = tuple(owner_scopes)
        scopes = {scope.owner: scope for scope in scope_batch}
        if len(scopes) != len(scope_batch):
            raise ValueError("duplicate PostgreSQL owner scope")
        if len({scope.schema for scope in scope_batch}) != len(scope_batch):
            raise ValueError("duplicate PostgreSQL owner schema")
        if len({scope.role for scope in scope_batch}) != len(scope_batch):
            raise ValueError("duplicate PostgreSQL owner role")
        if "core" in scopes:
            raise ValueError("Core owner scope is managed by the adapter")
        self.connect = connect
        self.lock_connect = lock_connect or connect
        self.owner_scopes: Mapping[str, PostgreSQLOwnerScope] = scopes
        self.advisory_lock_key = advisory_lock_key

    def apply(self, migrations: Iterable[Migration]) -> MigrationRunResult:
        batch = tuple(migrations)
        keys = [migration.key for migration in batch]
        if len(keys) != len(set(keys)):
            raise ValueError("migration batch contains duplicate owner/version keys")

        lock_connection = self.lock_connect()
        connection: DatabaseConnection | None = None
        locked = False
        completed = False
        applied: list[tuple[str, str]] = []
        skipped: list[tuple[str, str]] = []
        try:
            self._acquire_lock(lock_connection)
            locked = True
            connection = self.connect()
            self._require_distinct_execution_connection(lock_connection, connection)
            current_user = self._initialize_schema(connection)
            self._recover_interrupted_attempts(connection)

            for migration in batch:
                existing = self._entry(connection, migration.owner, migration.version)
                if existing is not None:
                    if existing.checksum != migration.checksum:
                        connection.rollback()
                        raise MigrationChecksumError(
                            f"checksum mismatch for {migration.owner}:{migration.version}"
                        )
                    if existing.status == MigrationStatus.APPLIED:
                        connection.rollback()
                        skipped.append(migration.key)
                        continue
                    if existing.status == MigrationStatus.APPLYING:
                        connection.rollback()
                        raise MigrationStateError(
                            "migration ledger contains an applying state after recovery: "
                            f"{migration.owner}:{migration.version}"
                        )
                connection.rollback()

                scope = self._scope_for(connection, migration.owner, current_user)
                run_id = uuid.uuid4()
                started_at = datetime.now(UTC)
                self._record_started(connection, run_id, migration, started_at)

                statement: str | None = None
                statement_ordinal: int | None = None
                try:
                    self._mark_applying(connection, migration, started_at)
                    self._enter_scope(connection, scope, current_user)
                    for statement_ordinal, statement in enumerate(
                        migration.statements, start=1
                    ):
                        _validate_postgresql_statement(statement)
                        _execute(connection, statement)
                    self._leave_scope(connection, scope, current_user)
                    finished_at = datetime.now(UTC)
                    self._mark_applied(connection, migration, finished_at)
                    self._insert_attempt(
                        connection,
                        run_id,
                        migration,
                        event="applied",
                        recorded_at=finished_at,
                    )
                    try:
                        connection.commit()
                    except Exception:
                        _safe_close(connection)
                        outcome = self._reconcile_commit(
                            lock_connection,
                            run_id,
                            migration,
                        )
                        if outcome is True:
                            connection = self.connect()
                            self._require_distinct_execution_connection(
                                lock_connection,
                                connection,
                            )
                            applied.append(migration.key)
                            continue
                        raise PostgreSQLCommitUncertainError(
                            "PostgreSQL migration commit outcome is uncertain; "
                            "inspect the ledger under a fresh advisory lock and retry"
                        ) from None
                    applied.append(migration.key)
                except PostgreSQLCommitUncertainError:
                    raise
                except Exception as error:
                    _safe_rollback(connection)
                    evidence = _failure_evidence(
                        error,
                        statement=statement,
                        statement_ordinal=statement_ordinal,
                    )
                    evidence_recorded = self._record_failure(
                        connection,
                        run_id,
                        migration,
                        started_at=started_at,
                        evidence=evidence,
                    )
                    raise MigrationApplyError(
                        migration,
                        evidence_recorded=evidence_recorded,
                    ) from None
            completed = True
        finally:
            if connection is not None:
                _safe_close(connection)
            if locked:
                try:
                    self._release_lock(lock_connection)
                except MigrationLockError:
                    if completed:
                        raise
            _safe_close(lock_connection)
        return MigrationRunResult(applied=tuple(applied), skipped=tuple(skipped))

    def ledger(self) -> tuple[MigrationLedgerEntry, ...]:
        lock_connection = self.lock_connect()
        connection: DatabaseConnection | None = None
        locked = False
        completed = False
        try:
            self._acquire_lock(lock_connection)
            locked = True
            connection = self.connect()
            self._require_distinct_execution_connection(lock_connection, connection)
            self._initialize_schema(connection)
            self._recover_interrupted_attempts(connection)
            rows = _fetchall(
                connection,
                f"""
                SELECT owner, version, checksum, status, started_at, finished_at, error
                FROM {_qualified(META_SCHEMA, LEDGER_TABLE)}
                ORDER BY owner, version
                """,
            )
            connection.rollback()
            result = tuple(
                MigrationLedgerEntry(
                    owner=row[0],
                    version=row[1],
                    checksum=row[2],
                    status=MigrationStatus(row[3]),
                    started_at=_timestamp_text(row[4]),
                    finished_at=_timestamp_text(row[5]) if row[5] is not None else None,
                    error=row[6],
                )
                for row in rows
            )
            completed = True
            return result
        finally:
            if connection is not None:
                _safe_close(connection)
            if locked:
                try:
                    self._release_lock(lock_connection)
                except MigrationLockError:
                    if completed:
                        raise
            _safe_close(lock_connection)

    def attempts(self) -> tuple[PostgreSQLMigrationAttempt, ...]:
        lock_connection = self.lock_connect()
        connection: DatabaseConnection | None = None
        locked = False
        completed = False
        try:
            self._acquire_lock(lock_connection)
            locked = True
            connection = self.connect()
            self._require_distinct_execution_connection(lock_connection, connection)
            self._initialize_schema(connection)
            self._recover_interrupted_attempts(connection)
            rows = _fetchall(
                connection,
                f"""
                SELECT event_id, run_id, owner, version, checksum, event,
                       statement_ordinal, sqlstate, statement_fingerprint,
                       error_class, recorded_at
                FROM {_qualified(META_SCHEMA, ATTEMPT_TABLE)}
                ORDER BY event_id
                """,
            )
            connection.rollback()
            result = tuple(
                PostgreSQLMigrationAttempt(
                    event_id=row[0],
                    run_id=str(row[1]),
                    owner=row[2],
                    version=row[3],
                    checksum=row[4],
                    event=row[5],
                    statement_ordinal=row[6],
                    sqlstate=row[7],
                    statement_fingerprint=row[8],
                    error_class=row[9],
                    recorded_at=_timestamp_text(row[10]),
                )
                for row in rows
            )
            completed = True
            return result
        finally:
            if connection is not None:
                _safe_close(connection)
            if locked:
                try:
                    self._release_lock(lock_connection)
                except MigrationLockError:
                    if completed:
                        raise
            _safe_close(lock_connection)

    def verify_owner_scopes(self) -> tuple[str, ...]:
        """Verify pre-provisioned package roles without executing package SQL."""

        lock_connection = self.lock_connect()
        connection: DatabaseConnection | None = None
        locked = False
        completed = False
        try:
            self._acquire_lock(lock_connection)
            locked = True
            connection = self.connect()
            self._require_distinct_execution_connection(lock_connection, connection)
            self._initialize_schema(connection)
            for scope in self.owner_scopes.values():
                self._verify_package_scope(connection, scope)
                connection.rollback()
            completed = True
            return tuple(sorted(self.owner_scopes))
        finally:
            if connection is not None:
                _safe_close(connection)
            if locked:
                try:
                    self._release_lock(lock_connection)
                except MigrationLockError:
                    if completed:
                        raise
            _safe_close(lock_connection)

    @staticmethod
    def _require_distinct_execution_connection(
        lock_connection: DatabaseConnection,
        execution_connection: DatabaseConnection,
    ) -> None:
        if execution_connection is lock_connection:
            raise MigrationLockError(
                "PostgreSQL lock and migration execution require distinct sessions"
            )

    def _acquire_lock(self, connection: DatabaseConnection) -> None:
        try:
            row = _fetchone(
                connection,
                "SELECT pg_try_advisory_lock(%s)",
                (self.advisory_lock_key,),
            )
            if row is None or row[0] is not True:
                connection.rollback()
                raise MigrationLockError("PostgreSQL migration lock is already held")
            connection.commit()
        except MigrationLockError:
            raise
        except Exception as error:
            _safe_rollback(connection)
            raise MigrationLockError(
                "PostgreSQL migration lock could not be acquired "
                f"({_safe_error_class(error)})"
            ) from None

    def _release_lock(self, connection: DatabaseConnection) -> None:
        _safe_rollback(connection)
        try:
            row = _fetchone(
                connection,
                "SELECT pg_advisory_unlock(%s)",
                (self.advisory_lock_key,),
            )
            if row is None or row[0] is not True:
                connection.rollback()
                raise MigrationLockError(
                    "PostgreSQL migration lock ownership was lost before release"
                )
            connection.commit()
        except MigrationLockError:
            raise
        except Exception as error:
            # Closing the owned session is the authoritative lock release fallback.
            _safe_rollback(connection)
            raise MigrationLockError(
                "PostgreSQL migration lock could not be released "
                f"({_safe_error_class(error)})"
            ) from None

    def _reconcile_commit(
        self,
        lock_connection: DatabaseConnection,
        run_id: uuid.UUID,
        migration: Migration,
    ) -> bool | None:
        """Resolve a lost commit acknowledgement on a fresh connection.

        The advisory lock lives on a separate session and remains held while
        this check runs. ``True`` means the ledger and applied event committed;
        ``False`` means no commit was visible and the start was classified as
        interrupted; ``None`` means even reconciliation was unavailable.
        """

        connection: DatabaseConnection | None = None
        try:
            connection = self.connect()
            self._require_distinct_execution_connection(lock_connection, connection)
            entry = self._entry(connection, migration.owner, migration.version)
            if (
                entry is not None
                and entry.status == MigrationStatus.APPLIED
                and entry.checksum == migration.checksum
            ):
                terminal = _fetchone(
                    connection,
                    f"""
                    SELECT 1
                    FROM {_qualified(META_SCHEMA, ATTEMPT_TABLE)}
                    WHERE run_id = %s AND owner = %s
                      AND version = %s AND checksum = %s
                      AND event = 'applied'
                    ORDER BY event_id DESC
                    LIMIT 1
                    """,
                    (
                        run_id,
                        migration.owner,
                        migration.version,
                        migration.checksum,
                    ),
                )
                connection.rollback()
                return terminal is not None
            connection.rollback()
            self._recover_interrupted_attempts(connection)
            return False
        except Exception:
            if connection is not None:
                _safe_rollback(connection)
            return None
        finally:
            if connection is not None:
                _safe_close(connection)

    def _initialize_schema(self, connection: DatabaseConnection) -> str:
        try:
            current_user_row = _fetchone(connection, "SELECT current_user")
            if current_user_row is None or not current_user_row[0]:
                raise PostgreSQLOwnershipError("PostgreSQL current role is unavailable")
            current_user = str(current_user_row[0])
            _quote_identifier(current_user)

            _execute(connection, f"CREATE SCHEMA IF NOT EXISTS {_quote_identifier(META_SCHEMA)}")
            _execute(connection, f"CREATE SCHEMA IF NOT EXISTS {_quote_identifier(CORE_SCHEMA)}")
            for schema in (META_SCHEMA, CORE_SCHEMA):
                owner_row = _fetchone(
                    connection,
                    """
                    SELECT pg_get_userbyid(nspowner)
                    FROM pg_namespace
                    WHERE nspname = %s
                    """,
                    (schema,),
                )
                if owner_row is None or owner_row[0] != current_user:
                    raise PostgreSQLOwnershipError(
                        f"protected PostgreSQL schema has unexpected owner: {schema}"
                    )
                _execute(
                    connection,
                    f"REVOKE ALL ON SCHEMA {_quote_identifier(schema)} FROM PUBLIC",
                )

            _execute(
                connection,
                f"""
                CREATE TABLE IF NOT EXISTS {_qualified(META_SCHEMA, LEDGER_TABLE)} (
                    owner TEXT NOT NULL,
                    version TEXT NOT NULL,
                    checksum CHAR(64) NOT NULL,
                    status TEXT NOT NULL
                        CHECK (status IN ('applying', 'applied', 'failed')),
                    started_at TIMESTAMPTZ NOT NULL,
                    finished_at TIMESTAMPTZ,
                    error TEXT,
                    sqlstate CHAR(5),
                    statement_ordinal INTEGER,
                    statement_fingerprint CHAR(64),
                    PRIMARY KEY (owner, version)
                )
                """,
            )
            _execute(
                connection,
                f"""
                CREATE TABLE IF NOT EXISTS {_qualified(META_SCHEMA, ATTEMPT_TABLE)} (
                    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    run_id UUID NOT NULL,
                    owner TEXT NOT NULL,
                    version TEXT NOT NULL,
                    checksum CHAR(64) NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event IN ('started', 'applied', 'failed', 'interrupted')),
                    statement_ordinal INTEGER,
                    sqlstate CHAR(5),
                    statement_fingerprint CHAR(64),
                    error_class TEXT,
                    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                    UNIQUE (run_id, owner, version, event)
                )
                """,
            )
            for table in (LEDGER_TABLE, ATTEMPT_TABLE):
                _execute(
                    connection,
                    f"REVOKE ALL ON TABLE {_qualified(META_SCHEMA, table)} FROM PUBLIC",
                )
            _execute(
                connection,
                f"""
                CREATE OR REPLACE FUNCTION
                    {_qualified(META_SCHEMA, "reject_attempt_mutation")}()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $plaik$
                BEGIN
                    RAISE EXCEPTION 'migration attempt journal is append-only'
                        USING ERRCODE = '55000';
                END;
                $plaik$
                """,
            )
            _execute(
                connection,
                f"""
                DROP TRIGGER IF EXISTS reject_attempt_mutation
                ON {_qualified(META_SCHEMA, ATTEMPT_TABLE)}
                """,
            )
            _execute(
                connection,
                f"""
                CREATE TRIGGER reject_attempt_mutation
                BEFORE UPDATE OR DELETE ON {_qualified(META_SCHEMA, ATTEMPT_TABLE)}
                FOR EACH ROW EXECUTE FUNCTION
                    {_qualified(META_SCHEMA, "reject_attempt_mutation")}()
                """,
            )
            _execute(
                connection,
                f"""
                REVOKE ALL ON FUNCTION
                    {_qualified(META_SCHEMA, "reject_attempt_mutation")}()
                FROM PUBLIC
                """,
            )
            connection.commit()
            return current_user
        except (PostgreSQLOwnershipError, ValueError):
            connection.rollback()
            raise
        except Exception as error:
            connection.rollback()
            raise MigrationError(
                "PostgreSQL migration metadata initialization failed "
                f"({_safe_error_class(error)})"
            ) from None

    def _recover_interrupted_attempts(self, connection: DatabaseConnection) -> None:
        try:
            _execute(
                connection,
                f"""
                INSERT INTO {_qualified(META_SCHEMA, ATTEMPT_TABLE)}
                    (run_id, owner, version, checksum, event, recorded_at)
                SELECT started.run_id, started.owner, started.version,
                       started.checksum, 'interrupted', clock_timestamp()
                FROM {_qualified(META_SCHEMA, ATTEMPT_TABLE)} AS started
                WHERE started.event = 'started'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM {_qualified(META_SCHEMA, ATTEMPT_TABLE)} AS terminal
                      WHERE terminal.run_id = started.run_id
                        AND terminal.owner = started.owner
                        AND terminal.version = started.version
                        AND terminal.event IN ('applied', 'failed', 'interrupted')
                  )
                ON CONFLICT (run_id, owner, version, event) DO NOTHING
                """,
            )
            connection.commit()
        except Exception as error:
            connection.rollback()
            raise MigrationError(
                "PostgreSQL interrupted-attempt recovery failed "
                f"({_safe_error_class(error)})"
            ) from None

    def _scope_for(
        self,
        connection: DatabaseConnection,
        owner: str,
        current_user: str,
    ) -> PostgreSQLOwnerScope:
        if owner == "core":
            return PostgreSQLOwnerScope(
                owner="core",
                schema=CORE_SCHEMA,
                role=current_user,
            )
        if owner not in self.owner_scopes:
            raise PostgreSQLOwnershipError(
                f"no isolated PostgreSQL owner scope is configured for {owner}"
            )
        raise PostgreSQLOwnershipError(
            "the PostgreSQL coordinator executes Core migrations only; package SQL "
            "requires a dedicated owner-authenticated execution adapter"
        )

    @staticmethod
    def _verify_package_scope(
        connection: DatabaseConnection,
        scope: PostgreSQLOwnerScope,
    ) -> None:
        row = _fetchone(
            connection,
            """
            SELECT namespace.nspname,
                   pg_get_userbyid(namespace.nspowner),
                   role.rolsuper,
                   role.rolinherit,
                   role.rolcreaterole,
                   role.rolcreatedb,
                   role.rolcanlogin,
                   role.rolreplication,
                   role.rolbypassrls,
                   pg_has_role(current_user, role.oid, 'SET'),
                   has_schema_privilege(role.oid, %s, 'USAGE'),
                   has_schema_privilege(role.oid, %s, 'USAGE'),
                   has_schema_privilege(role.oid, 'public', 'CREATE')
            FROM pg_roles AS role
            LEFT JOIN pg_namespace AS namespace ON namespace.nspname = %s
            WHERE role.rolname = %s
            """,
            (META_SCHEMA, CORE_SCHEMA, scope.schema, scope.role),
        )
        if row is None:
            raise PostgreSQLOwnershipError("PostgreSQL package owner role is missing")
        (
            schema,
            schema_owner,
            is_superuser,
            inherits,
            can_create_role,
            can_create_database,
            can_login,
            replicates,
            bypasses_rls,
            migrator_can_set_role,
            meta_usage,
            core_usage,
            public_create,
        ) = row
        if schema != scope.schema or schema_owner != scope.role:
            raise PostgreSQLOwnershipError(
                "PostgreSQL package schema is missing or has an unexpected owner"
            )
        if any(
            (
                is_superuser,
                inherits,
                can_create_role,
                can_create_database,
                can_login,
                replicates,
                bypasses_rls,
            )
        ):
            raise PostgreSQLOwnershipError(
                "PostgreSQL package owner role has unsafe attributes"
            )
        if not migrator_can_set_role:
            raise PostgreSQLOwnershipError(
                "PostgreSQL migrator cannot assume the package owner role"
            )
        if meta_usage or core_usage or public_create:
            raise PostgreSQLOwnershipError(
                "PostgreSQL package owner can access a protected schema"
            )
        foreign_schemas = _fetchall(
            connection,
            """
            SELECT nspname
            FROM pg_namespace
            WHERE nspname LIKE 'plaik_pkg_%'
              AND nspname <> %s
              AND has_schema_privilege(%s, nspname, 'USAGE')
            """,
            (scope.schema, scope.role),
        )
        if foreign_schemas:
            raise PostgreSQLOwnershipError(
                "PostgreSQL package owner can access another package schema"
            )
        outbound_roles = _fetchall(
            connection,
            """
            SELECT granted_role.rolname
            FROM pg_auth_members AS membership
            JOIN pg_roles AS member_role ON member_role.oid = membership.member
            JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
            WHERE member_role.rolname = %s
            """,
            (scope.role,),
        )
        if outbound_roles:
            raise PostgreSQLOwnershipError(
                "PostgreSQL package owner role has outbound role memberships"
            )

    @staticmethod
    def _enter_scope(
        connection: DatabaseConnection,
        scope: PostgreSQLOwnerScope,
        current_user: str,
    ) -> None:
        if scope.owner != "core" or scope.role != current_user:
            raise PostgreSQLOwnershipError(
                "package SQL cannot execute on the privileged coordinator session"
            )
        _execute(
            connection,
            "SET LOCAL search_path TO "
            f"{_quote_identifier(scope.schema)}, pg_temp",
        )

    @staticmethod
    def _leave_scope(
        connection: DatabaseConnection,
        scope: PostgreSQLOwnerScope,
        current_user: str,
    ) -> None:
        if scope.owner != "core" or scope.role != current_user:
            raise PostgreSQLOwnershipError(
                "migration scope changed before Core transaction completion"
            )

    @staticmethod
    def _entry(
        connection: DatabaseConnection,
        owner: str,
        version: str,
    ) -> MigrationLedgerEntry | None:
        row = _fetchone(
            connection,
            f"""
            SELECT owner, version, checksum, status, started_at, finished_at, error
            FROM {_qualified(META_SCHEMA, LEDGER_TABLE)}
            WHERE owner = %s AND version = %s
            """,
            (owner, version),
        )
        if row is None:
            return None
        try:
            status = MigrationStatus(row[3])
        except ValueError:
            raise MigrationStateError(
                f"invalid migration status for {owner}:{version}"
            ) from None
        return MigrationLedgerEntry(
            owner=row[0],
            version=row[1],
            checksum=row[2],
            status=status,
            started_at=_timestamp_text(row[4]),
            finished_at=_timestamp_text(row[5]) if row[5] is not None else None,
            error=row[6],
        )

    @staticmethod
    def _mark_applying(
        connection: DatabaseConnection,
        migration: Migration,
        started_at: datetime,
    ) -> None:
        _execute(
            connection,
            f"""
            INSERT INTO {_qualified(META_SCHEMA, LEDGER_TABLE)}
                (owner, version, checksum, status, started_at, finished_at,
                 error, sqlstate, statement_ordinal, statement_fingerprint)
            VALUES (%s, %s, %s, 'applying', %s, NULL, NULL, NULL, NULL, NULL)
            ON CONFLICT (owner, version) DO UPDATE
            SET status = 'applying', started_at = EXCLUDED.started_at,
                finished_at = NULL, error = NULL, sqlstate = NULL,
                statement_ordinal = NULL, statement_fingerprint = NULL
            """,
            (
                migration.owner,
                migration.version,
                migration.checksum,
                started_at,
            ),
        )

    @staticmethod
    def _mark_applied(
        connection: DatabaseConnection,
        migration: Migration,
        finished_at: datetime,
    ) -> None:
        _execute(
            connection,
            f"""
            UPDATE {_qualified(META_SCHEMA, LEDGER_TABLE)}
            SET status = 'applied', finished_at = %s, error = NULL,
                sqlstate = NULL, statement_ordinal = NULL,
                statement_fingerprint = NULL
            WHERE owner = %s AND version = %s
            """,
            (finished_at, migration.owner, migration.version),
        )

    def _record_started(
        self,
        connection: DatabaseConnection,
        run_id: uuid.UUID,
        migration: Migration,
        started_at: datetime,
    ) -> None:
        try:
            self._insert_attempt(
                connection,
                run_id,
                migration,
                event="started",
                recorded_at=started_at,
            )
            connection.commit()
        except Exception as error:
            connection.rollback()
            raise MigrationError(
                "PostgreSQL migration start evidence could not be recorded "
                f"({_safe_error_class(error)})"
            ) from None

    def _record_failure(
        self,
        connection: DatabaseConnection,
        run_id: uuid.UUID,
        migration: Migration,
        *,
        started_at: datetime,
        evidence: _FailureEvidence,
    ) -> bool:
        try:
            existing = self._entry(connection, migration.owner, migration.version)
            if existing is not None and existing.status == MigrationStatus.APPLIED:
                connection.rollback()
                return False
            _execute(
                connection,
                f"""
                INSERT INTO {_qualified(META_SCHEMA, LEDGER_TABLE)}
                    (owner, version, checksum, status, started_at, finished_at,
                     error, sqlstate, statement_ordinal, statement_fingerprint)
                VALUES (%s, %s, %s, 'failed', %s, %s, %s, %s, %s, %s)
                ON CONFLICT (owner, version) DO UPDATE
                SET checksum = EXCLUDED.checksum, status = 'failed',
                    started_at = EXCLUDED.started_at,
                    finished_at = EXCLUDED.finished_at,
                    error = EXCLUDED.error, sqlstate = EXCLUDED.sqlstate,
                    statement_ordinal = EXCLUDED.statement_ordinal,
                    statement_fingerprint = EXCLUDED.statement_fingerprint
                """,
                (
                    migration.owner,
                    migration.version,
                    migration.checksum,
                    started_at,
                    datetime.now(UTC),
                    evidence.summary,
                    evidence.sqlstate,
                    evidence.statement_ordinal,
                    evidence.statement_fingerprint,
                ),
            )
            self._insert_attempt(
                connection,
                run_id,
                migration,
                event="failed",
                recorded_at=datetime.now(UTC),
                evidence=evidence,
            )
            connection.commit()
            return True
        except Exception:
            _safe_rollback(connection)
            return False

    @staticmethod
    def _insert_attempt(
        connection: DatabaseConnection,
        run_id: uuid.UUID,
        migration: Migration,
        *,
        event: str,
        recorded_at: datetime,
        evidence: _FailureEvidence | None = None,
    ) -> None:
        _execute(
            connection,
            f"""
            INSERT INTO {_qualified(META_SCHEMA, ATTEMPT_TABLE)}
                (run_id, owner, version, checksum, event, statement_ordinal,
                 sqlstate, statement_fingerprint, error_class, recorded_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                run_id,
                migration.owner,
                migration.version,
                migration.checksum,
                event,
                evidence.statement_ordinal if evidence else None,
                evidence.sqlstate if evidence else None,
                evidence.statement_fingerprint if evidence else None,
                evidence.error_class if evidence else None,
                recorded_at,
            ),
        )


class PostgreSQLAdapter:
    """Composition-root facade for PostgreSQL preflight and Core bootstrap."""

    def __init__(
        self,
        configuration: InstallerConfiguration,
        secrets: SecretProvider | SecretProviderRegistry,
        *,
        timeouts: PostgreSQLTimeouts | None = None,
        owner_scopes: Iterable[PostgreSQLOwnerScope] = (),
        connector: Callable[..., DatabaseConnection] | None = None,
    ) -> None:
        self.connect = PostgreSQLConnectionFactory(
            configuration,
            secrets,
            timeouts=timeouts,
            connector=connector,
        )
        self.runtime_connect = PostgreSQLConnectionFactory(
            configuration,
            secrets,
            timeouts=timeouts,
            connector=connector,
            runtime=(configuration.database.runtime_username is not None),
            application_name="plaik-v2-runtime",
        )
        self.checkpoint_connect = PostgreSQLConnectionFactory(
            configuration,
            secrets,
            timeouts=timeouts,
            connector=connector,
            checkpoint=(configuration.database.checkpoint_username is not None),
            application_name="plaik-v2-checkpoint",
        )
        self.configuration = self.connect.configuration
        self.migrations = PostgreSQLMigrationRunner(
            self.connect,
            owner_scopes=owner_scopes,
        )

    def preflight(self) -> DatabasePreflightResult:
        return preflight_connection(self.connect)

    def migrate_core(self) -> MigrationRunResult:
        return self.migrations.apply(POSTGRESQL_CORE_MIGRATIONS)

    def initialize_context(self) -> None:
        initialize_postgresql_context(self.connect, self.configuration)

    def verify_context(self) -> None:
        verify_postgresql_context(self.connect, self.configuration)

    def verify_owner_scopes(self) -> tuple[str, ...]:
        return self.migrations.verify_owner_scopes()

    def bootstrap_core(self) -> PostgreSQLBootstrapResult:
        preflight = self.preflight()
        migrations = self.migrate_core()
        self.initialize_context()
        self.verify_context()
        self.grant_restricted_identities()
        return PostgreSQLBootstrapResult(preflight=preflight, migrations=migrations)

    def grant_restricted_identities(self) -> None:
        """Grant runtime Core DML and keep plaik_meta off runtime/checkpoint."""

        database = self.configuration.database
        if not isinstance(database, PostgreSQLDatabase):
            return
        if database.runtime_username is None or database.checkpoint_username is None:
            return
        from .postgresql_provision import (
            PostgreSQLProvisionError,
            restricted_identity_grants,
        )

        try:
            statements = restricted_identity_grants(
                database.username,
                database.runtime_username,
                database.checkpoint_username,
            )
        except PostgreSQLProvisionError as error:
            raise PostgreSQLAdapterError(str(error)) from None
        connection = self.connect()
        try:
            for statement in statements:
                _execute(connection, statement)
            connection.commit()
        except PostgreSQLAdapterError:
            connection.rollback()
            raise
        except Exception as error:
            connection.rollback()
            raise PostgreSQLAdapterError(
                "PostgreSQL restricted identity grants failed "
                f"({_safe_error_class(error)})"
            ) from None
        finally:
            _safe_close(connection)


def initialize_postgresql_context(
    connect: ConnectionFactory,
    configuration: InstallerConfiguration,
) -> None:
    """Seed immutable installation/group/store context in one transaction."""

    configuration = _validated_postgresql_configuration(configuration)
    connection = connect()
    try:
        _execute(connection, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        _execute(
            connection,
            f"SET LOCAL search_path TO {_quote_identifier(CORE_SCHEMA)}, pg_temp",
        )
        _insert_or_verify_context(
            connection,
            "plaik_installations",
            ("id", "profile", "locale", "timezone", "public_url", "config_digest"),
            (
                configuration.installation_id,
                configuration.profile.value,
                configuration.locale,
                configuration.timezone,
                str(configuration.public_url),
                configuration.fingerprint(),
            ),
        )
        _insert_or_verify_context(
            connection,
            "plaik_store_groups",
            ("id", "installation_id"),
            (configuration.group_id, configuration.installation_id),
        )
        _insert_or_verify_context(
            connection,
            "plaik_stores",
            ("id", "installation_id", "group_id"),
            (
                configuration.store_id,
                configuration.installation_id,
                configuration.group_id,
            ),
        )
        connection.commit()
    except PostgreSQLContextError:
        connection.rollback()
        raise
    except Exception as error:
        connection.rollback()
        raise PostgreSQLContextError(
            "PostgreSQL Platform context initialization failed "
            f"({_safe_error_class(error)})"
        ) from None
    finally:
        _safe_close(connection)


def verify_postgresql_context(
    connect: ConnectionFactory,
    configuration: InstallerConfiguration,
) -> None:
    """Verify immutable PostgreSQL context in a read-only transaction."""

    configuration = _validated_postgresql_configuration(configuration)
    connection = connect()
    try:
        _execute(connection, "SET TRANSACTION READ ONLY")
        installation = _fetchone(
            connection,
            f"""
            SELECT id, profile, locale, timezone, public_url, config_digest
            FROM {_qualified(CORE_SCHEMA, "plaik_installations")}
            WHERE id = %s
            """,
            (configuration.installation_id,),
        )
        group = _fetchone(
            connection,
            f"""
            SELECT id, installation_id
            FROM {_qualified(CORE_SCHEMA, "plaik_store_groups")}
            WHERE id = %s
            """,
            (configuration.group_id,),
        )
        store = _fetchone(
            connection,
            f"""
            SELECT id, installation_id, group_id
            FROM {_qualified(CORE_SCHEMA, "plaik_stores")}
            WHERE id = %s
            """,
            (configuration.store_id,),
        )
        expected_installation = (
            configuration.installation_id,
            configuration.profile.value,
            configuration.locale,
            configuration.timezone,
            str(configuration.public_url),
            configuration.fingerprint(),
        )
        if installation != expected_installation:
            raise PostgreSQLContextError(
                "PostgreSQL Platform installation configuration drift detected"
            )
        if group != (configuration.group_id, configuration.installation_id):
            raise PostgreSQLContextError(
                "PostgreSQL Platform store-group context drift detected"
            )
        if store != (
            configuration.store_id,
            configuration.installation_id,
            configuration.group_id,
        ):
            raise PostgreSQLContextError(
                "PostgreSQL Platform store context drift detected"
            )
        connection.rollback()
    except PostgreSQLContextError:
        connection.rollback()
        raise
    except Exception as error:
        connection.rollback()
        raise PostgreSQLContextError(
            "PostgreSQL Platform context verification failed "
            f"({_safe_error_class(error)})"
        ) from None
    finally:
        _safe_close(connection)


def _insert_or_verify_context(
    connection: DatabaseConnection,
    table: str,
    columns: tuple[str, ...],
    values: tuple[str, ...],
) -> None:
    if not _SIMPLE_IDENTIFIER.fullmatch(table):
        raise ValueError("invalid Core context table")
    for column in columns:
        if not _SIMPLE_IDENTIFIER.fullmatch(column):
            raise ValueError("invalid Core context column")
    placeholders = ", ".join("%s" for _ in columns)
    column_list = ", ".join(_quote_identifier(column) for column in columns)
    _execute(
        connection,
        f"""
        INSERT INTO {_quote_identifier(table)} ({column_list})
        VALUES ({placeholders})
        ON CONFLICT (id) DO NOTHING
        """,
        values,
    )
    selected = _fetchone(
        connection,
        f"SELECT {column_list} FROM {_quote_identifier(table)} WHERE id = %s",
        (values[0],),
    )
    if selected != values:
        raise PostgreSQLContextError(
            f"immutable PostgreSQL Platform context drift detected in {table}"
        )


def _validate_postgresql_statement(statement: str) -> None:
    """Apply a PostgreSQL command allowlist in addition to role isolation."""

    executable = _erase_sql_literals_and_comments(statement).strip().rstrip(";").strip()
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_$]*", executable)
    if not tokens:
        raise MigrationError("PostgreSQL migration contains no executable command")
    first = tokens[0].upper()
    second = tokens[1].upper() if len(tokens) > 1 else ""
    if first in _GLOBAL_COMMANDS:
        raise MigrationError(f"PostgreSQL migration command is forbidden: {first}")
    if first == "CREATE" and second in _GLOBAL_CREATE_OBJECTS:
        raise MigrationError(f"PostgreSQL migration object is forbidden: {second}")
    if first == "ALTER" and second in _GLOBAL_ALTER_OBJECTS:
        raise MigrationError(f"PostgreSQL migration object is forbidden: {second}")
    if first == "DROP" and second in _GLOBAL_DROP_OBJECTS:
        raise MigrationError(f"PostgreSQL migration object is forbidden: {second}")


def _failure_evidence(
    error: Exception,
    *,
    statement: str | None,
    statement_ordinal: int | None,
) -> _FailureEvidence:
    sqlstate = getattr(error, "sqlstate", None)
    if sqlstate is None:
        diagnostic = getattr(error, "diag", None)
        sqlstate = getattr(diagnostic, "sqlstate", None)
    if not isinstance(sqlstate, str) or not _SQLSTATE.fullmatch(sqlstate.upper()):
        sqlstate = None
    else:
        sqlstate = sqlstate.upper()
    fingerprint = None
    if statement is not None:
        fingerprint = hashlib.sha256(statement.encode("utf-8")).hexdigest()
    return _FailureEvidence(
        error_class=_safe_error_class(error),
        sqlstate=sqlstate,
        statement_ordinal=statement_ordinal,
        statement_fingerprint=fingerprint,
    )


def _load_psycopg_connector() -> Callable[..., DatabaseConnection]:
    try:
        module = importlib.import_module("psycopg")
    except (ImportError, OSError) as error:
        raise PostgreSQLDependencyError(
            "PostgreSQL support requires a working psycopg 3 installation "
            f"({_safe_error_class(error)}; install psycopg[binary]>=3.2,<4)"
        ) from None
    connector = getattr(module, "connect", None)
    if not callable(connector):
        raise PostgreSQLDependencyError("installed psycopg module has no connect API")
    return connector


def _validated_postgresql_configuration(
    configuration: InstallerConfiguration,
) -> InstallerConfiguration:
    try:
        validated = InstallerConfiguration.model_validate(
            configuration.model_dump(mode="json")
        )
    except Exception as error:
        raise PostgreSQLConfigurationError(
            "invalid PostgreSQL installer configuration "
            f"({_safe_error_class(error)})"
        ) from None
    if not isinstance(validated.database, PostgreSQLDatabase):
        raise PostgreSQLConfigurationError(
            "PostgreSQL adapter requires PostgreSQL installer configuration"
        )
    return validated


def _safe_error_class(error: BaseException) -> str:
    value = f"{type(error).__module__}.{type(error).__name__}"
    return _ERROR_CLASS.sub("_", value)[:128]


def _package_scope_identifiers(owner: str) -> tuple[str, str]:
    if not OWNER_PATTERN.fullmatch(owner) or owner == "core":
        raise ValueError("package owner must be a non-Core migration owner")
    slug = owner.replace("-", "_")[:30]
    digest = hashlib.sha256(owner.encode("ascii")).hexdigest()[:16]
    return (
        f"plaik_pkg_{slug}_{digest}",
        f"plaik_owner_{slug}_{digest}",
    )


def _quote_identifier(identifier: str) -> str:
    if not isinstance(identifier, str) or not _POSTGRES_IDENTIFIER.fullmatch(identifier):
        raise ValueError("invalid PostgreSQL identifier")
    if len(identifier.encode("utf-8")) > 63:
        raise ValueError("PostgreSQL identifier exceeds 63 bytes")
    return '"' + identifier.replace('"', '""') + '"'


def _qualified(schema: str, name: str) -> str:
    return f"{_quote_identifier(schema)}.{_quote_identifier(name)}"


def _execute(
    connection: DatabaseConnection,
    operation: str,
    parameters: tuple[Any, ...] = (),
) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute(operation, parameters)
    finally:
        cursor.close()


def _fetchone(
    connection: DatabaseConnection,
    operation: str,
    parameters: tuple[Any, ...] = (),
) -> Any:
    cursor = connection.cursor()
    try:
        cursor.execute(operation, parameters)
        return cursor.fetchone()
    finally:
        cursor.close()


def _fetchall(
    connection: DatabaseConnection,
    operation: str,
    parameters: tuple[Any, ...] = (),
) -> list[Any]:
    cursor = connection.cursor()
    try:
        cursor.execute(operation, parameters)
        return list(cursor.fetchall())
    finally:
        cursor.close()


def _timestamp_text(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
    return str(value)


def _safe_rollback(connection: DatabaseConnection) -> None:
    try:
        connection.rollback()
    except Exception:
        pass


def _safe_close(connection: DatabaseConnection) -> None:
    try:
        connection.close()
    except Exception:
        pass
