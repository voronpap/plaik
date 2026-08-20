"""LOGIN package-owner identity for crash-atomic PostgreSQL package SQL.

Live package SQL authenticates as the canonical per-package LOGIN role. The
migrator never executes package statements and never ``SET ROLE``s into the
owner. Owner passwords live in the secret provider, never in Git or installer
configuration.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from plaik_contracts import SecretReference

from .database import ConnectionFactory, DatabaseConnection
from .postgresql import (
    CORE_SCHEMA,
    META_SCHEMA,
    PostgreSQLConnectionError,
    PostgreSQLOwnerScope,
    PostgreSQLOwnershipError,
    _execute,
    _fetchall,
    _fetchone,
    _quote_identifier,
    _safe_close,
    _safe_rollback,
)
from .postgresql_provision import PASSWORD
from .secret_store import (
    SecretNotFoundError,
    SecretProvider,
    SecretProviderRegistry,
    SecretStoreError,
)


OwnerConnectAs = Callable[[str, str], DatabaseConnection]
SecretProviders = SecretProvider | SecretProviderRegistry

_UNDEFINED_FUNCTION = "42883"
_UNDEFINED_SCHEMA = "3F000"
_OWNER_ROLE = re.compile(r"^plaik_owner_[a-z0-9_]+$")
_OWNER_SCHEMA = re.compile(r"^plaik_pkg_[a-z0-9_]+$")
_CONTROL_MISSING = frozenset({_UNDEFINED_FUNCTION, _UNDEFINED_SCHEMA})


def package_owner_secret_reference(package_id: str) -> SecretReference:
    """Return the local secret pointer for one package owner LOGIN role."""

    PostgreSQLOwnerScope.for_package(package_id)
    return SecretReference(
        provider="local",
        key=f"postgresql/package-owner/{package_id}",
        version="v1",
    )


def connect_package_owner(
    *,
    migrator_connect: ConnectionFactory,
    owner_connect_as: OwnerConnectAs,
    secrets: SecretProviders,
    database_name: str,
    package_id: str,
) -> DatabaseConnection:
    """Provision the LOGIN owner if needed, then open a distinct owner session."""

    scope = PostgreSQLOwnerScope.for_package(package_id)
    _require_canonical_owner_scope(scope)
    _quote_identifier(database_name)
    password = _resolve_owner_secret(secrets, package_id, migrator_connect, scope)
    migrator = migrator_connect()
    try:
        _ensure_package_owner_login(
            migrator,
            scope=scope,
            database_name=database_name,
            password=password,
        )
        migrator.commit()
    except Exception:
        _safe_rollback(migrator)
        raise
    finally:
        _safe_close(migrator)
    try:
        return owner_connect_as(scope.role, password)
    except PostgreSQLConnectionError as error:
        raise PostgreSQLOwnershipError(
            "package owner LOGIN connection failed"
        ) from error
    finally:
        password = ""


def _require_canonical_owner_scope(scope: PostgreSQLOwnerScope) -> None:
    role_key = scope.role.removeprefix("plaik_owner_")
    schema_key = scope.schema.removeprefix("plaik_pkg_")
    if (
        role_key != schema_key
        or not role_key
        or _OWNER_ROLE.fullmatch(scope.role) is None
        or _OWNER_SCHEMA.fullmatch(scope.schema) is None
    ):
        raise PostgreSQLOwnershipError("package owner scope is not canonical")


def _reject_unsafe_owner_grants(
    connection: DatabaseConnection,
    scope: PostgreSQLOwnerScope,
) -> None:
    protected = _fetchone(
        connection,
        """
        SELECT has_schema_privilege(%s, %s, 'USAGE'),
               has_schema_privilege(%s, %s, 'USAGE'),
               has_schema_privilege(%s, 'public', 'CREATE')
        """,
        (scope.role, META_SCHEMA, scope.role, CORE_SCHEMA, scope.role),
    )
    if protected is None or any(protected):
        raise PostgreSQLOwnershipError(
            "package owner session can access a protected schema"
        )
    foreign = _fetchall(
        connection,
        """
        SELECT nspname
        FROM pg_namespace
        WHERE nspname LIKE 'plaik_pkg_%%'
          AND nspname <> %s
          AND has_schema_privilege(%s, nspname, 'USAGE')
        """,
        (scope.schema, scope.role),
    )
    if foreign:
        raise PostgreSQLOwnershipError(
            "package owner session can access another package schema"
        )
    memberships = _fetchall(
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
    if memberships:
        raise PostgreSQLOwnershipError(
            "package owner role has outbound role memberships"
        )
    inbound = _fetchall(
        connection,
        """
        SELECT member_role.rolname
        FROM pg_auth_members AS membership
        JOIN pg_roles AS member_role ON member_role.oid = membership.member
        JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
        WHERE granted_role.rolname = %s
        """,
        (scope.role,),
    )
    if inbound:
        raise PostgreSQLOwnershipError(
            "package owner role has inbound role memberships"
        )


def _resolve_owner_secret(
    secrets: SecretProviders,
    package_id: str,
    migrator_connect: ConnectionFactory,
    scope: PostgreSQLOwnerScope,
) -> str:
    reference = package_owner_secret_reference(package_id)
    try:
        value = _read_secret(secrets, reference)
    except SecretNotFoundError:
        if _role_exists(migrator_connect, scope.role):
            raise PostgreSQLOwnershipError(
                "package owner secret is missing for an existing LOGIN role"
            ) from None
        value = _generate_owner_secret(secrets, reference)
    if PASSWORD.fullmatch(value) is None:
        raise PostgreSQLOwnershipError(
            "package owner secret does not meet the password contract"
        )
    return value


def _generate_owner_secret(
    secrets: SecretProviders,
    reference: SecretReference,
) -> str:
    if isinstance(secrets, SecretProviderRegistry):
        return secrets.generate_if_missing(
            reference, entropy_bytes=32
        ).get_secret_value()
    if secrets.name != reference.provider:
        raise SecretStoreError("package owner secret provider is unavailable")
    return secrets.generate_if_missing(
        reference.key,
        version=reference.version,
        entropy_bytes=32,
    ).get_secret_value()


def _read_secret(secrets: SecretProviders, reference: SecretReference) -> str:
    if isinstance(secrets, SecretProviderRegistry):
        return secrets.resolve(reference).get_secret_value()
    if secrets.name != reference.provider:
        raise SecretStoreError("package owner secret provider is unavailable")
    return secrets.read(reference.key, version=reference.version).get_secret_value()


def _role_exists(migrator_connect: ConnectionFactory, role: str) -> bool:
    connection = migrator_connect()
    try:
        row = _fetchone(
            connection,
            "SELECT 1 FROM pg_roles WHERE rolname = %s",
            (role,),
        )
        connection.rollback()
        return row is not None
    finally:
        _safe_close(connection)


def _ensure_package_owner_login(
    connection: DatabaseConnection,
    *,
    scope: PostgreSQLOwnerScope,
    database_name: str,
    password: str,
) -> None:
    try:
        _execute(
            connection,
            "SELECT plaik_control.ensure_package_owner_login(%s, %s, %s)",
            (scope.role, scope.schema, password),
        )
        return
    except Exception as error:
        if _sqlstate(error) not in _CONTROL_MISSING:
            raise PostgreSQLOwnershipError(
                "package owner LOGIN role could not be provisioned"
            ) from None
        _safe_rollback(connection)
    if not _current_user_can_create_role(connection):
        raise PostgreSQLOwnershipError(
            "package owner LOGIN control function is not installed"
        )
    _provision_owner_inline(
        connection,
        scope=scope,
        database_name=database_name,
        password=password,
    )


def _current_user_can_create_role(connection: DatabaseConnection) -> bool:
    row = _fetchone(
        connection,
        """
        SELECT rolsuper, rolcreaterole
        FROM pg_roles WHERE rolname = current_user
        """,
    )
    return row is not None and True in (row[0], row[1])


def _provision_owner_inline(
    connection: DatabaseConnection,
    *,
    scope: PostgreSQLOwnerScope,
    database_name: str,
    password: str,
) -> None:
    if _OWNER_ROLE.fullmatch(scope.role) is None:
        raise PostgreSQLOwnershipError("invalid package owner role")
    if _OWNER_SCHEMA.fullmatch(scope.schema) is None:
        raise PostgreSQLOwnershipError("invalid package schema")
    _require_canonical_owner_scope(scope)
    if PASSWORD.fullmatch(password) is None:
        raise PostgreSQLOwnershipError(
            "package owner secret does not meet the password contract"
        )

    role_sql = _quote_identifier(scope.role)
    schema_sql = _quote_identifier(scope.schema)
    database_sql = _quote_identifier(database_name)
    existing = _fetchone(
        connection,
        """
        SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
               rolreplication, rolbypassrls
        FROM pg_roles WHERE rolname = %s
        """,
        (scope.role,),
    )
    if existing is None:
        _create_owner_role(connection, scope.role, password)
    else:
        unsafe = (*existing[:4], existing[5], existing[6])
        if any(unsafe) or existing[4] is not True:
            raise PostgreSQLOwnershipError(
                "package owner role has unsafe login or privilege attributes"
            )

    namespace = _fetchone(
        connection,
        """
        SELECT pg_get_userbyid(nspowner)
        FROM pg_namespace WHERE nspname = %s
        """,
        (scope.schema,),
    )
    if namespace is None:
        _execute(
            connection,
            f"CREATE SCHEMA {schema_sql} AUTHORIZATION {role_sql}",
        )
    elif namespace[0] != scope.role:
        raise PostgreSQLOwnershipError(
            "package owner schema has unexpected owner"
        )
    _execute(connection, f"REVOKE ALL ON SCHEMA {schema_sql} FROM PUBLIC")
    _execute(
        connection,
        f"GRANT CONNECT ON DATABASE {database_sql} TO {role_sql}",
    )
    _execute(
        connection,
        f"REVOKE CREATE ON SCHEMA public FROM {role_sql}",
    )
    _reject_unsafe_owner_grants(connection, scope)


def _create_owner_role(
    connection: DatabaseConnection, role: str, password: str
) -> None:
    """Create the LOGIN owner without putting the password in client SQL text."""

    if _OWNER_ROLE.fullmatch(role) is None:
        raise PostgreSQLOwnershipError("invalid package owner role")
    _execute(
        connection,
        "CREATE TEMP TABLE plaik_owner_secret (password text) ON COMMIT DROP",
    )
    _execute(
        connection,
        "INSERT INTO plaik_owner_secret (password) VALUES (%s)",
        (password,),
    )
    _execute(
        connection,
        f"""
        DO $plaik$
        DECLARE
            secret text;
        BEGIN
            SELECT password INTO STRICT secret FROM plaik_owner_secret;
            EXECUTE format(
                'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB '
                'NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5 '
                'PASSWORD %L',
                '{role}',
                secret
            );
        END
        $plaik$;
        """,
    )


def _sqlstate(error: BaseException) -> str | None:
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        state = getattr(current, "sqlstate", None)
        if state is None:
            state = getattr(current, "pgcode", None)
        if state is None:
            diagnostic = getattr(current, "diag", None)
            state = getattr(diagnostic, "sqlstate", None)
        if isinstance(state, str) and state:
            return state
        current = current.__cause__
    return None
