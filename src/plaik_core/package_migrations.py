"""Owner-authenticated PostgreSQL package migration executor.

Package SQL never runs on the privileged migrator/coordinator session. The
coordinator owns the advisory lock and append-only ledger; a separately
authenticated package-owner connection executes statements after a conservative
lexical policy check. Crash recovery reuses the Core interrupted-attempt
protocol, while production package composition remains gated separately.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

from plaik_contracts import PackageManifest

from .database import ConnectionFactory, DatabaseConnection
from .migrations import (
    Migration,
    MigrationApplyError,
    MigrationChecksumError,
    MigrationError,
    MigrationLockError,
    MigrationRunResult,
    MigrationStateError,
    MigrationStatus,
    _erase_sql_literals_and_comments,
)
from .postgresql import (
    CORE_SCHEMA,
    META_SCHEMA,
    MIGRATION_LOCK_KEY,
    PostgreSQLCommitUncertainError,
    PostgreSQLMigrationRunner,
    PostgreSQLOwnerScope,
    PostgreSQLOwnershipError,
    _execute,
    _failure_evidence,
    _fetchall,
    _fetchone,
    _quote_identifier,
    _safe_close,
    _safe_rollback,
    _validate_postgresql_statement,
)


OwnerConnectionFactory = Callable[[str], DatabaseConnection]

_PACKAGE_FORBIDDEN_TOKENS = frozenset(
    {
        "AUTHORIZATION",
        "BYPASSRLS",
        "CREATEDB",
        "CREATEROLE",
        "PASSWORD",
        "REPLICATION",
        "SESSION_USER",
        "SUPERUSER",
    }
)
_PACKAGE_RESERVED_RELATIONS = frozenset({"PLAIK_SETTINGS_REGISTRY"})
_PACKAGE_TRANSACTION_CONTROL = re.compile(
    r"^(?:BEGIN\b|START\s+TRANSACTION\b|COMMIT\b|END\b|ROLLBACK\b|ABORT\b|"
    r"SAVEPOINT\b|RELEASE\s+(?:SAVEPOINT\s+)?|PREPARE\s+TRANSACTION\b)"
)
_DOLLAR_QUOTE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$")


class PackageMigrationError(MigrationError):
    """A package migration declaration or execution was rejected."""


class PackagePostgreSQLMigrationExecutor:
    """Apply package-owned migrations on an owner-authenticated session.

    ``coordinator_connect`` must authenticate as the migrator and may write the
    protected meta ledger. ``owner_connect(package_id)`` must return a distinct
    connection already authenticated as that package's LOGIN owner role; it must
    not be able to become the migrator.
    """

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
        self.advisory_lock_key = advisory_lock_key
        self._coordinator = PostgreSQLMigrationRunner(
            coordinator_connect,
            lock_connect=self.lock_connect,
            advisory_lock_key=advisory_lock_key,
        )

    def apply(self, migrations: Iterable[Migration]) -> MigrationRunResult:
        batch = tuple(migrations)
        if not batch:
            return MigrationRunResult(applied=(), skipped=())
        owners = {migration.owner for migration in batch}
        if "core" in owners:
            raise PackageMigrationError(
                "package executor refuses Core migrations; use the Core runner"
            )
        if len(owners) != 1:
            raise PackageMigrationError(
                "package migration batch must target exactly one package owner"
            )
        owner = next(iter(owners))
        scope = PostgreSQLOwnerScope.for_package(owner)
        keys = [migration.key for migration in batch]
        if len(keys) != len(set(keys)):
            raise ValueError("migration batch contains duplicate owner/version keys")

        lock_connection = self.lock_connect()
        coordinator: DatabaseConnection | None = None
        locked = False
        completed = False
        applied: list[tuple[str, str]] = []
        skipped: list[tuple[str, str]] = []
        try:
            self._coordinator._acquire_lock(lock_connection)
            locked = True
            coordinator = self.coordinator_connect()
            self._coordinator._require_distinct_execution_connection(
                lock_connection,
                coordinator,
            )
            current_user = self._coordinator._initialize_schema(coordinator)
            if current_user == scope.role:
                raise PostgreSQLOwnershipError(
                    "package executor coordinator must not authenticate as the package owner"
                )
            self._coordinator._recover_interrupted_attempts(coordinator)

            for migration in batch:
                existing = self._coordinator._entry(
                    coordinator, migration.owner, migration.version
                )
                if existing is not None:
                    if existing.checksum != migration.checksum:
                        coordinator.rollback()
                        raise MigrationChecksumError(
                            f"checksum mismatch for {migration.owner}:{migration.version}"
                        )
                    if existing.status == MigrationStatus.APPLIED:
                        coordinator.rollback()
                        skipped.append(migration.key)
                        continue
                    if existing.status == MigrationStatus.APPLYING:
                        coordinator.rollback()
                        raise MigrationStateError(
                            "migration ledger contains an applying state after recovery: "
                            f"{migration.owner}:{migration.version}"
                        )
                coordinator.rollback()

                run_id = uuid.uuid4()
                started_at = datetime.now(UTC)
                self._coordinator._record_started(
                    coordinator, run_id, migration, started_at
                )

                statement: str | None = None
                statement_ordinal: int | None = None
                owner_connection: DatabaseConnection | None = None
                try:
                    self._coordinator._mark_applying(coordinator, migration, started_at)
                    # Keep ledger applying row uncommitted until package SQL
                    # and applied evidence can share the coordinator commit,
                    # matching Core atomicity for the terminal decision.
                    owner_connection = self.owner_connect(owner)
                    self._require_owner_session(
                        owner_connection,
                        scope=scope,
                        coordinator=coordinator,
                        lock_connection=lock_connection,
                    )
                    self._prepare_owner_search_path(owner_connection, scope)
                    for statement_ordinal, statement in enumerate(
                        migration.statements, start=1
                    ):
                        validate_package_postgresql_statement(statement, scope=scope)
                        _execute(owner_connection, statement)
                    owner_connection.commit()
                    finished_at = datetime.now(UTC)
                    self._coordinator._mark_applied(coordinator, migration, finished_at)
                    self._coordinator._insert_attempt(
                        coordinator,
                        run_id,
                        migration,
                        event="applied",
                        recorded_at=finished_at,
                    )
                    try:
                        coordinator.commit()
                    except Exception:
                        _safe_close(coordinator)
                        outcome = self._coordinator._reconcile_commit(
                            lock_connection,
                            run_id,
                            migration,
                        )
                        if outcome is True:
                            coordinator = self.coordinator_connect()
                            self._coordinator._require_distinct_execution_connection(
                                lock_connection,
                                coordinator,
                            )
                            applied.append(migration.key)
                            continue
                        raise PostgreSQLCommitUncertainError(
                            "PostgreSQL package migration commit outcome is uncertain; "
                            "inspect the ledger under a fresh advisory lock and retry"
                        ) from None
                    applied.append(migration.key)
                except PostgreSQLCommitUncertainError:
                    raise
                except Exception as error:
                    if owner_connection is not None:
                        _safe_rollback(owner_connection)
                    _safe_rollback(coordinator)
                    evidence = _failure_evidence(
                        error,
                        statement=statement,
                        statement_ordinal=statement_ordinal,
                    )
                    evidence_recorded = self._coordinator._record_failure(
                        coordinator,
                        run_id,
                        migration,
                        started_at=started_at,
                        evidence=evidence,
                    )
                    raise MigrationApplyError(
                        migration,
                        evidence_recorded=evidence_recorded,
                    ) from None
                finally:
                    if owner_connection is not None:
                        _safe_close(owner_connection)
            completed = True
        finally:
            if coordinator is not None:
                _safe_close(coordinator)
            if locked:
                try:
                    self._coordinator._release_lock(lock_connection)
                except MigrationLockError:
                    if completed:
                        raise
            _safe_close(lock_connection)
        return MigrationRunResult(applied=tuple(applied), skipped=tuple(skipped))

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
        if row is None:
            raise PostgreSQLOwnershipError("package owner session identity is unavailable")
        current_user, session_user = row
        if current_user != scope.role or session_user != scope.role:
            raise PostgreSQLOwnershipError(
                "package migration connection is not authenticated as the package owner"
            )
        attrs = _fetchone(
            owner_connection,
            """
            SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
                   rolreplication, rolbypassrls,
                   has_schema_privilege(current_user, %s, 'USAGE'),
                   has_schema_privilege(current_user, %s, 'USAGE'),
                   has_schema_privilege(current_user, 'public', 'CREATE')
            FROM pg_roles
            WHERE rolname = current_user
            """,
            (META_SCHEMA, CORE_SCHEMA),
        )
        if attrs is None:
            raise PostgreSQLOwnershipError("package owner role attributes are unavailable")
        (
            is_super,
            inherits,
            can_create_role,
            can_create_database,
            can_login,
            replicates,
            bypasses_rls,
            meta_usage,
            core_usage,
            public_create,
        ) = attrs
        if any(
            (
                is_super,
                inherits,
                can_create_role,
                can_create_database,
                replicates,
                bypasses_rls,
            )
        ) or not can_login:
            raise PostgreSQLOwnershipError(
                "package owner session has unsafe login or privilege attributes"
            )
        if meta_usage or core_usage or public_create:
            raise PostgreSQLOwnershipError(
                "package owner session can access a protected schema"
            )

        schema = _fetchone(
            owner_connection,
            """
            SELECT namespace.nspname,
                   pg_get_userbyid(namespace.nspowner),
                   has_schema_privilege(current_user, namespace.nspname, 'USAGE'),
                   has_schema_privilege(current_user, namespace.nspname, 'CREATE')
            FROM pg_namespace AS namespace
            WHERE namespace.nspname = %s
            """,
            (scope.schema,),
        )
        if schema is None:
            raise PostgreSQLOwnershipError("package owner schema is missing")
        schema_name, schema_owner, own_usage, own_create = schema
        if (
            schema_name != scope.schema
            or schema_owner != scope.role
            or not own_usage
            or not own_create
        ):
            raise PostgreSQLOwnershipError(
                "package owner schema has unsafe ownership or privileges"
            )

        foreign_schemas = _fetchall(
            owner_connection,
            """
            SELECT namespace.nspname
            FROM pg_namespace AS namespace
            WHERE namespace.nspname LIKE 'plaik_pkg_%'
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

    @staticmethod
    def _prepare_owner_search_path(
        owner_connection: DatabaseConnection,
        scope: PostgreSQLOwnerScope,
    ) -> None:
        _execute(
            owner_connection,
            "SET LOCAL search_path TO "
            f"{_quote_identifier(scope.schema)}, pg_temp",
        )


def _references_protected_schema(statement: str) -> str | None:
    lowered = statement.lower()
    for name in (META_SCHEMA, CORE_SCHEMA, "public"):
        if re.search(rf'"{re.escape(name)}"\s*\.', lowered):
            return name
        if re.search(rf"\b{re.escape(name)}\s*\.", lowered):
            return name
    return None


def validate_package_postgresql_statement(
    statement: str,
    *,
    scope: PostgreSQLOwnerScope,
) -> None:
    """Reject privilege-escalation and cross-schema SQL for package owners."""

    _validate_postgresql_statement(statement)
    blocked = _references_protected_schema(statement)
    if blocked is not None:
        raise MigrationError(
            f"PostgreSQL package migration must not reference {blocked}"
        )
    executable = _erase_sql_literals_and_comments(statement).upper()
    if _PACKAGE_TRANSACTION_CONTROL.match(executable.lstrip()):
        raise MigrationError(
            "PostgreSQL package migration must not control transaction boundaries"
        )
    tokens = set(re.findall(r"[A-Z_][A-Z0-9_$]*", executable))
    forbidden = tokens & _PACKAGE_FORBIDDEN_TOKENS
    if forbidden:
        raise MigrationError(
            "PostgreSQL package migration command is forbidden: "
            + ",".join(sorted(forbidden))
        )
    reserved = tokens & _PACKAGE_RESERVED_RELATIONS
    if reserved:
        raise MigrationError(
            "PostgreSQL package migration must not reference "
            + ",".join(sorted(name.lower() for name in reserved))
        )
    # Reject explicit references to protected schemas / other package schemas.
    protected = (META_SCHEMA.upper(), CORE_SCHEMA.upper(), "PUBLIC")
    for name in protected:
        if re.search(rf"(?<![A-Z0-9_]){re.escape(name)}(?![A-Z0-9_])", executable):
            raise MigrationError(
                f"PostgreSQL package migration must not reference {name.lower()}"
            )
    other_pkg = re.search(r"PLAIK_PKG_[A-Z0-9_]+", executable)
    if other_pkg and other_pkg.group(0).lower() != scope.schema:
        raise MigrationError(
            "PostgreSQL package migration must not reference another package schema"
        )


def load_package_migrations(
    staging: Path,
    manifest: PackageManifest,
) -> tuple[Migration, ...]:
    """Build checksummed Migration objects from declared artifact SQL files."""

    if not manifest.migrations:
        return ()
    loaded: list[Migration] = []
    root = staging.resolve()
    for declaration in manifest.migrations:
        path = (staging / declaration.path).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise PackageMigrationError(
                f"migration path escapes package root: {declaration.path}"
            ) from error
        if not path.is_file() or path.is_symlink():
            raise PackageMigrationError(
                f"declared migration file is missing: {declaration.path}"
            )
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as error:
            raise PackageMigrationError(
                f"declared migration file is unreadable: {declaration.path}"
            ) from error
        statements = split_package_sql_statements(text)
        if not statements:
            raise PackageMigrationError(
                f"migration file contains no statements: {declaration.path}"
            )
        loaded.append(
            Migration(
                owner=manifest.id,
                version=declaration.version,
                statements=statements,
            )
        )
    return tuple(loaded)


def split_package_sql_statements(script: str) -> tuple[str, ...]:
    """Split PostgreSQL package SQL on semicolons outside lexical containers."""

    if not isinstance(script, str) or not script.strip():
        return ()
    parts: list[str] = []
    buffer: list[str] = []
    in_single = False
    in_double = False
    in_line_comment = False
    block_comment_depth = 0
    dollar_delimiter: str | None = None
    index = 0
    length = len(script)
    while index < length:
        char = script[index]
        nxt = script[index + 1] if index + 1 < length else ""

        if in_line_comment:
            buffer.append(char)
            if char == "\n":
                in_line_comment = False
            index += 1
            continue

        if block_comment_depth:
            if char == "/" and nxt == "*":
                buffer.extend(("/", "*"))
                block_comment_depth += 1
                index += 2
                continue
            if char == "*" and nxt == "/":
                buffer.extend(("*", "/"))
                block_comment_depth -= 1
                index += 2
                continue
            buffer.append(char)
            index += 1
            continue

        if dollar_delimiter is not None:
            if script.startswith(dollar_delimiter, index):
                buffer.append(dollar_delimiter)
                index += len(dollar_delimiter)
                dollar_delimiter = None
                continue
            buffer.append(char)
            index += 1
            continue

        if in_single:
            buffer.append(char)
            if char == "'" and nxt == "'":
                buffer.append(nxt)
                index += 2
                continue
            if char == "'":
                in_single = False
            index += 1
            continue

        if in_double:
            buffer.append(char)
            if char == '"' and nxt == '"':
                buffer.append(nxt)
                index += 2
                continue
            if char == '"':
                in_double = False
            index += 1
            continue

        if char == "-" and nxt == "-":
            buffer.extend(("-", "-"))
            in_line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            buffer.extend(("/", "*"))
            block_comment_depth = 1
            index += 2
            continue
        if char == "'":
            buffer.append(char)
            in_single = True
            index += 1
            continue
        if char == '"':
            buffer.append(char)
            in_double = True
            index += 1
            continue
        if char == "$":
            match = _DOLLAR_QUOTE.match(script, index)
            if match is not None:
                dollar_delimiter = match.group(0)
                buffer.append(dollar_delimiter)
                index = match.end()
                continue
        if char == ";":
            statement = "".join(buffer).strip()
            if statement:
                parts.append(statement)
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1

    trailing = "".join(buffer).strip()
    if trailing:
        parts.append(trailing)
    return tuple(parts)