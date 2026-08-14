"""Fail-closed privilege guard for PostgreSQL integrity-checkpoint sessions."""

from __future__ import annotations

from .database import DatabaseConnection
from .postgresql import CORE_SCHEMA, _fetchall, _fetchone


class PostgreSQLCheckpointRoleError(RuntimeError):
    """The checkpoint connection has authority outside its narrow contract."""


def require_restricted_checkpoint_role(connection: DatabaseConnection) -> str:
    """Require a dedicated LOGIN role with checkpoint-only database authority."""

    identity = _fetchone(connection, "SELECT current_user, session_user")
    if identity is None:
        raise PostgreSQLCheckpointRoleError("checkpoint role identity is unavailable")
    current_user, session_user = identity
    if not current_user or current_user != session_user:
        raise PostgreSQLCheckpointRoleError(
            "checkpoint connection must authenticate directly as its restricted role"
        )

    attrs = _fetchone(
        connection,
        """
        SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
               rolreplication, rolbypassrls,
               has_schema_privilege(current_user, %s, 'USAGE'),
               has_schema_privilege(current_user, 'public', 'CREATE')
        FROM pg_roles
        WHERE rolname = current_user
        """,
        (CORE_SCHEMA,),
    )
    if attrs is None:
        raise PostgreSQLCheckpointRoleError("checkpoint role attributes are unavailable")
    (
        is_super,
        inherits,
        can_create_role,
        can_create_database,
        can_login,
        replicates,
        bypasses_rls,
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
        raise PostgreSQLCheckpointRoleError("checkpoint role has unsafe attributes")
    if not core_usage or public_create:
        raise PostgreSQLCheckpointRoleError("checkpoint role schema privileges are unsafe")

    memberships = _fetchall(
        connection,
        """
        SELECT granted_role.rolname
        FROM pg_auth_members AS membership
        JOIN pg_roles AS member_role ON member_role.oid = membership.member
        JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
        WHERE member_role.rolname = current_user
        """,
    )
    if memberships:
        raise PostgreSQLCheckpointRoleError(
            "checkpoint role must not inherit authority through memberships"
        )

    allowed = _fetchone(
        connection,
        """
        SELECT
          has_table_privilege(current_user, %s, 'SELECT'),
          has_table_privilege(current_user, %s, 'INSERT'),
          has_table_privilege(current_user, %s, 'UPDATE'),
          has_table_privilege(current_user, %s, 'DELETE'),
          has_table_privilege(current_user, %s, 'TRUNCATE'),
          has_table_privilege(current_user, %s, 'REFERENCES'),
          has_table_privilege(current_user, %s, 'TRIGGER')
        """,
        tuple(
            f"{CORE_SCHEMA}.plaik_integrity_checkpoints"
            for _ in range(7)
        ),
    )
    if allowed is None:
        raise PostgreSQLCheckpointRoleError("checkpoint table privileges are unavailable")
    select_ok, insert_ok, update_ok, delete_ok, truncate_ok, refs_ok, trigger_ok = allowed
    if not select_ok or not insert_ok or any(
        (update_ok, delete_ok, truncate_ok, refs_ok, trigger_ok)
    ):
        raise PostgreSQLCheckpointRoleError(
            "checkpoint role must have only SELECT and INSERT on checkpoint history"
        )

    foreign = _fetchall(
        connection,
        """
        SELECT table_name
        FROM information_schema.role_table_grants
        WHERE grantee = current_user
          AND table_schema = %s
          AND table_name <> 'plaik_integrity_checkpoints'
        """,
        (CORE_SCHEMA,),
    )
    if foreign:
        raise PostgreSQLCheckpointRoleError(
            "checkpoint role has authority over unrelated Core tables"
        )
    return str(current_user)
