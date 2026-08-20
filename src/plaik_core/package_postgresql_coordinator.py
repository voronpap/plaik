"""PostgreSQL participant for crash-atomic package SQL lifecycle."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from plaik_contracts import PackageManifest

from .database import ConnectionFactory, DatabaseConnection
from .migrations import Migration, MigrationChecksumError, MigrationStateError, MigrationStatus
from .package_migrations import (
    OwnerConnectionFactory,
    PackageMigrationError,
    load_package_migrations,
    validate_package_postgresql_statement,
)
from .package_prepared_transactions import (
    finish_package_transaction,
    inspect_package_transaction,
    package_prepared_transaction,
    prepare_package_transaction,
)
from .package_sql_recovery import (
    PackageMigrationEvidence,
    PackageSQLParticipantEvidence,
    PackageSQLParticipantPhase,
    PackageSQLParticipantRecord,
)
from .postgresql import (
    ATTEMPT_TABLE,
    CORE_SCHEMA,
    LEDGER_TABLE,
    META_SCHEMA,
    MIGRATION_LOCK_KEY,
    PostgreSQLMigrationRunner,
    PostgreSQLOwnerScope,
    PostgreSQLOwnershipError,
    _execute,
    _fetchall,
    _fetchone,
    _qualified,
    _quote_identifier,
    _safe_close,
    _safe_rollback,
)


_RUN_NAMESPACE = uuid.UUID("8ba9471b-555c-4df5-933d-70738e937b77")


class PackagePostgreSQLPreparedCoordinator:
    """Execute package SQL as one restricted-owner prepared transaction."""

    def __init__(
        self,
        coordinator_connect: ConnectionFactory,
        owner_connect: OwnerConnectionFactory,
        *,
        lock_connect: ConnectionFactory | None = None,
        advisory_lock_key: int = MIGRATION_LOCK_KEY,
    ) -> None:
        self.coordinator_connect = coordinator_connect
        self.owner_connect = owner_connect
        self.lock_connect = lock_connect or coordinator_connect
        self.runner = PostgreSQLMigrationRunner(
            coordinator_connect,
            lock_connect=self.lock_connect,
            advisory_lock_key=advisory_lock_key,
        )

    def drop_owner(self, package_id: str) -> None:
        from .package_owner_identity import drop_package_owner_login

        drop_package_owner_login(
            migrator_connect=self.coordinator_connect,
            package_id=package_id,
        )

    def drop_orphans(self, installed_package_ids: tuple[str, ...]) -> tuple[str, ...]:
        from .package_owner_identity import drop_orphaned_package_owners

        return drop_orphaned_package_owners(
            migrator_connect=self.coordinator_connect,
            installed_package_ids=installed_package_ids,
        )

    def plan(
        self,
        operation_id: str,
        package_root: Path,
        manifest: PackageManifest,
        artifact_sha256: str,
    ) -> PackageSQLParticipantRecord:
        migrations = load_package_migrations(package_root, manifest)
        if not migrations:
            raise PackageMigrationError("package SQL coordinator requires migrations")
        participant = package_prepared_transaction(
            operation_id, manifest.id, artifact_sha256
        )
        return PackageSQLParticipantRecord.from_evidence(
            PackageSQLParticipantEvidence(
                participant=participant,
                migrations=tuple(
                    PackageMigrationEvidence(m.owner, m.version, m.checksum)
                    for m in migrations
                ),
                phase=PackageSQLParticipantPhase.PREPARING,
            )
        )

    def prepare(
        self,
        record: PackageSQLParticipantRecord,
        package_root: Path,
        manifest: PackageManifest,
    ) -> None:
        evidence = record.to_evidence()
        if record.phase != PackageSQLParticipantPhase.PREPARING:
            raise PackageMigrationError("package SQL participant is not preparing")
        migrations = self._bound_migrations(record, package_root, manifest)
        scope = PostgreSQLOwnerScope.for_package(record.package_id)
        lock_connection = self.lock_connect()
        coordinator: DatabaseConnection | None = None
        owner: DatabaseConnection | None = None
        locked = False
        prepared = False
        pending: list[Migration] = []
        try:
            self.runner._acquire_lock(lock_connection)
            locked = True
            coordinator = self.coordinator_connect()
            self.runner._require_distinct_execution_connection(lock_connection, coordinator)
            coordinator_user = self.runner._initialize_schema(coordinator)
            if coordinator_user == scope.role:
                raise PostgreSQLOwnershipError(
                    "package SQL coordinator must not authenticate as package owner"
                )

            owner = self.owner_connect(record.package_id)
            self._require_owner_session(
                owner,
                scope=scope,
                coordinator=coordinator,
                lock_connection=lock_connection,
            )
            _execute(
                owner,
                "SET LOCAL search_path TO "
                f"{_quote_identifier(scope.schema)}, pg_temp",
            )
            for migration in migrations:
                entry = self.runner._entry(
                    coordinator, migration.owner, migration.version
                )
                if entry is not None and entry.checksum != migration.checksum:
                    raise MigrationChecksumError(
                        f"checksum mismatch for {migration.owner}:{migration.version}"
                    )
                if entry is not None and entry.status == MigrationStatus.APPLIED:
                    continue
                if entry is not None and entry.status == MigrationStatus.APPLYING:
                    raise MigrationStateError(
                        "package migration ledger still contains applying state: "
                        f"{migration.owner}:{migration.version}"
                    )
                pending.append(migration)
                for statement in migration.statements:
                    validate_package_postgresql_statement(statement, scope=scope)
                    _execute(owner, statement)

            prepare_package_transaction(owner, evidence.participant)
            prepared = True

            started_at = datetime.now(UTC)
            for migration in pending:
                self.runner._record_started(
                    coordinator,
                    self._run_id(record, migration),
                    migration,
                    started_at,
                )
            for migration in pending:
                self.runner._mark_applying(coordinator, migration, started_at)
            coordinator.commit()
        except Exception:
            if prepared and owner is not None:
                try:
                    # PREPARE ends the transaction, so this same connection can
                    # safely switch to autocommit without an inspection query.
                    finish_package_transaction(owner, evidence.participant, commit=False)
                    prepared = False
                except Exception:
                    pass
            if coordinator is not None:
                _safe_rollback(coordinator)
            if not prepared:
                try:
                    self._mark_rolled_back(record)
                except Exception:
                    pass
            raise
        finally:
            if owner is not None:
                _safe_close(owner)
            if coordinator is not None:
                _safe_close(coordinator)
            if locked:
                self.runner._release_lock(lock_connection)
            _safe_close(lock_connection)

    def inspect(self, record: PackageSQLParticipantRecord) -> bool:
        connection = self.coordinator_connect()
        try:
            return inspect_package_transaction(
                connection, record.to_evidence().participant
            )
        finally:
            _safe_close(connection)

    def finish(self, record: PackageSQLParticipantRecord, *, commit: bool) -> None:
        # The caller already selected this action from a fresh pg_prepared_xacts
        # inspection. Do not query on this owner connection before the utility
        # command: psycopg would open a transaction and block autocommit.
        owner = self.owner_connect(record.package_id)
        try:
            finish_package_transaction(
                owner,
                record.to_evidence().participant,
                commit=commit,
            )
        finally:
            _safe_close(owner)
        if commit:
            self._mark_applied(record)
        else:
            self._mark_rolled_back(record)

    def verify_finished(self, record: PackageSQLParticipantRecord) -> None:
        if self.inspect(record):
            raise PackageMigrationError("finished package SQL participant is still prepared")
        self._mark_applied(record)

    def verify_rolled_back(self, record: PackageSQLParticipantRecord) -> None:
        if self.inspect(record):
            raise PackageMigrationError(
                "rolled-back package SQL participant is still prepared"
            )
        self._mark_rolled_back(record)

    @contextmanager
    def _metadata_connection(self) -> Iterator[DatabaseConnection]:
        lock_connection = self.lock_connect()
        coordinator: DatabaseConnection | None = None
        locked = False
        try:
            self.runner._acquire_lock(lock_connection)
            locked = True
            coordinator = self.coordinator_connect()
            self.runner._require_distinct_execution_connection(lock_connection, coordinator)
            self.runner._initialize_schema(coordinator)
            yield coordinator
        finally:
            if coordinator is not None:
                _safe_close(coordinator)
            if locked:
                self.runner._release_lock(lock_connection)
            _safe_close(lock_connection)

    def _mark_applied(self, record: PackageSQLParticipantRecord) -> None:
        with self._metadata_connection() as coordinator:
            now = datetime.now(UTC)
            for migration in record.migrations:
                entry = self.runner._entry(
                    coordinator, migration.owner, migration.version
                )
                if entry is None:
                    raise MigrationStateError(
                        "committed package migration has no applying ledger evidence: "
                        f"{migration.owner}:{migration.version}"
                    )
                if entry.checksum != migration.checksum:
                    raise MigrationChecksumError(
                        f"checksum mismatch for {migration.owner}:{migration.version}"
                    )
                if entry.status == MigrationStatus.FAILED:
                    raise MigrationStateError(
                        "committed package migration conflicts with failed ledger state: "
                        f"{migration.owner}:{migration.version}"
                    )
                if entry.status == MigrationStatus.APPLIED:
                    continue
                _execute(
                    coordinator,
                    f"""
                    UPDATE {_qualified(META_SCHEMA, LEDGER_TABLE)}
                    SET status = 'applied', finished_at = %s, error = NULL,
                        sqlstate = NULL, statement_ordinal = NULL,
                        statement_fingerprint = NULL
                    WHERE owner = %s AND version = %s AND checksum = %s
                    """,
                    (now, migration.owner, migration.version, migration.checksum),
                )
                self._insert_terminal_attempt(
                    coordinator, record, migration, event="applied", now=now
                )
            coordinator.commit()

    def _mark_rolled_back(self, record: PackageSQLParticipantRecord) -> None:
        with self._metadata_connection() as coordinator:
            now = datetime.now(UTC)
            for migration in record.migrations:
                entry = self.runner._entry(
                    coordinator, migration.owner, migration.version
                )
                if entry is None:
                    continue
                if entry.checksum != migration.checksum:
                    raise MigrationChecksumError(
                        f"checksum mismatch for {migration.owner}:{migration.version}"
                    )
                if entry.status == MigrationStatus.APPLIED:
                    continue
                _execute(
                    coordinator,
                    f"""
                    UPDATE {_qualified(META_SCHEMA, LEDGER_TABLE)}
                    SET status = 'failed', finished_at = %s,
                        error = 'package transaction rolled back',
                        sqlstate = NULL, statement_ordinal = NULL,
                        statement_fingerprint = NULL
                    WHERE owner = %s AND version = %s AND checksum = %s
                    """,
                    (now, migration.owner, migration.version, migration.checksum),
                )
                self._insert_terminal_attempt(
                    coordinator,
                    record,
                    migration,
                    event="failed",
                    now=now,
                    error_class="PackageTransactionRolledBack",
                )
            coordinator.commit()

    def _insert_terminal_attempt(
        self,
        coordinator: DatabaseConnection,
        record: PackageSQLParticipantRecord,
        migration,
        *,
        event: str,
        now: datetime,
        error_class: str | None = None,
    ) -> None:
        _execute(
            coordinator,
            f"""
            INSERT INTO {_qualified(META_SCHEMA, ATTEMPT_TABLE)}
                (run_id, owner, version, checksum, event, error_class, recorded_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (run_id, owner, version, event) DO NOTHING
            """,
            (
                self._run_id(record, migration),
                migration.owner,
                migration.version,
                migration.checksum,
                event,
                error_class,
                now,
            ),
        )

    @staticmethod
    def _require_owner_session(
        owner_connection: DatabaseConnection,
        *,
        scope: PostgreSQLOwnerScope,
        coordinator: DatabaseConnection,
        lock_connection: DatabaseConnection,
    ) -> None:
        if owner_connection is coordinator or owner_connection is lock_connection:
            raise PostgreSQLOwnershipError(
                "package SQL must use a distinct owner-authenticated connection"
            )
        row = _fetchone(owner_connection, "SELECT current_user, session_user")
        if row is None or tuple(row) != (scope.role, scope.role):
            raise PostgreSQLOwnershipError(
                "package migration connection is not authenticated as package owner"
            )
        attrs = _fetchone(
            owner_connection,
            """
            SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
                   rolreplication, rolbypassrls,
                   has_schema_privilege(current_user, %s, 'USAGE'),
                   has_schema_privilege(current_user, %s, 'USAGE'),
                   has_schema_privilege(current_user, 'public', 'CREATE')
            FROM pg_roles WHERE rolname = current_user
            """,
            (META_SCHEMA, CORE_SCHEMA),
        )
        if attrs is None:
            raise PostgreSQLOwnershipError("package owner role attributes are unavailable")
        unsafe = (*attrs[:4], attrs[5], attrs[6])
        if any(unsafe) or attrs[4] is not True:
            raise PostgreSQLOwnershipError(
                "package owner session has unsafe login or privilege attributes"
            )
        if any(attrs[7:10]):
            raise PostgreSQLOwnershipError(
                "package owner session can access a protected schema"
            )
        schema = _fetchone(
            owner_connection,
            """
            SELECT namespace.nspname, pg_get_userbyid(namespace.nspowner),
                   has_schema_privilege(current_user, namespace.nspname, 'USAGE'),
                   has_schema_privilege(current_user, namespace.nspname, 'CREATE')
            FROM pg_namespace AS namespace WHERE namespace.nspname = %s
            """,
            (scope.schema,),
        )
        if schema is None or tuple(schema) != (scope.schema, scope.role, True, True):
            raise PostgreSQLOwnershipError(
                "package owner schema has unsafe ownership or privileges"
            )
        foreign_schemas = _fetchall(
            owner_connection,
            """
            SELECT namespace.nspname
            FROM pg_namespace AS namespace
            WHERE namespace.nspname LIKE 'plaik_pkg_%%'
              AND namespace.nspname <> %s
              AND has_schema_privilege(current_user, namespace.nspname, 'USAGE')
            """,
            (scope.schema,),
        )
        if foreign_schemas:
            raise PostgreSQLOwnershipError(
                "package owner session can access another package schema"
            )
        memberships = _fetchall(
            owner_connection,
            """
            SELECT granted_role.rolname
            FROM pg_auth_members AS membership
            JOIN pg_roles AS member_role ON member_role.oid = membership.member
            JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
            WHERE member_role.rolname = current_user
            """,
        )
        if memberships:
            raise PostgreSQLOwnershipError(
                "package owner role has outbound role memberships"
            )
        inbound = _fetchall(
            owner_connection,
            """
            SELECT member_role.rolname
            FROM pg_auth_members AS membership
            JOIN pg_roles AS member_role ON member_role.oid = membership.member
            JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
            WHERE granted_role.rolname = current_user
            """,
        )
        if inbound:
            raise PostgreSQLOwnershipError(
                "package owner role has inbound role memberships"
            )

    def _bound_migrations(
        self,
        record: PackageSQLParticipantRecord,
        package_root: Path,
        manifest: PackageManifest,
    ) -> tuple[Migration, ...]:
        if manifest.id != record.package_id:
            raise PackageMigrationError("package SQL manifest identity changed")
        migrations = load_package_migrations(package_root, manifest)
        actual = tuple((m.owner, m.version, m.checksum) for m in migrations)
        expected = tuple((m.owner, m.version, m.checksum) for m in record.migrations)
        if actual != expected:
            raise PackageMigrationError(
                "package SQL migration evidence no longer matches staged artifact"
            )
        return migrations

    @staticmethod
    def _run_id(record: PackageSQLParticipantRecord, migration) -> uuid.UUID:
        return uuid.uuid5(
            _RUN_NAMESPACE,
            "\0".join(
                (
                    record.operation_id,
                    record.package_id,
                    migration.owner,
                    migration.version,
                    migration.checksum,
                )
            ),
        )
