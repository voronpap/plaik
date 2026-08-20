"""Provision an empty local PostgreSQL database for PLAIK setup.

This is a privileged installer action. It only runs through the local
``postgres`` operating-system user on a loopback cluster. It never restores
dumps, never drops occupied databases and never logs passwords.
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
from collections.abc import Callable

from .host_inventory import HostInventory, PostgreSQLListener
from .privileged_peer import (
    CREATEDB,
    PSQL,
    RUNUSER,
    TRUSTED_PATH,
    peer_subprocess_env,
)

ProvisionRunner = Callable[..., tuple[int, str]]


IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{2,62}$")
PASSWORD = re.compile(r"^[A-Za-z0-9_-]{43,256}$")


class PostgreSQLProvisionError(RuntimeError):
    """Local PostgreSQL provisioning failed without exposing secrets."""


def literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def generate_role_secret() -> str:
    """Return a provision-grade secret that never needs an operator-chosen password."""

    value = secrets.token_urlsafe(32)
    if PASSWORD.fullmatch(value) is None:
        raise PostgreSQLProvisionError("generated PostgreSQL secret is invalid")
    return value


def _default_runner(command: list[str], input_text: str | None = None) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            input=input_text,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=peer_subprocess_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    return completed.returncode, completed.stdout or completed.stderr


def _run(
    runner: ProvisionRunner | None,
    command: list[str],
    input_text: str | None = None,
) -> tuple[int, str]:
    execute = runner or _default_runner
    try:
        return execute(command, input_text)
    except TypeError:
        if input_text is not None:
            raise PostgreSQLProvisionError(
                "PostgreSQL provision runner cannot accept stdin"
            ) from None
        return execute(command)


def provisionable_listener(
    inventory: HostInventory, port: int
) -> PostgreSQLListener | None:
    for listener in inventory.listeners:
        if (
            listener.port == port
            and listener.host in {"127.0.0.1", "::1"}
            and listener.process == "postgres"
        ):
            return listener
    return None


def occupied_database(inventory: HostInventory, port: int, name: str) -> bool:
    return any(
        item.port == port
        and item.name == name
        and item.inspectable
        and item.application_tables not in {None, 0}
        for item in inventory.databases
    )


def database_exists(inventory: HostInventory, port: int, name: str) -> bool:
    return any(
        item.port == port and item.name == name and item.inspectable
        for item in inventory.databases
    )


def provision_local_postgresql(
    *,
    port: int,
    database: str,
    migrator_role: str,
    runtime_role: str,
    checkpoint_role: str,
    migrator_password: str,
    runtime_password: str,
    checkpoint_password: str,
    inventory: HostInventory,
    runner: ProvisionRunner | None = None,
) -> None:
    if provisionable_listener(inventory, port) is None:
        raise PostgreSQLProvisionError(
            "cannot create a database on a listener without local postgres peer access"
        )
    identifiers = (database, migrator_role, runtime_role, checkpoint_role)
    if any(IDENTIFIER.fullmatch(value) is None for value in identifiers):
        raise PostgreSQLProvisionError("invalid PostgreSQL identifier")
    if len(set(identifiers)) != len(identifiers):
        raise PostgreSQLProvisionError(
            "PostgreSQL database and roles must be distinct"
        )
    passwords = (migrator_password, runtime_password, checkpoint_password)
    if any(PASSWORD.fullmatch(value) is None for value in passwords):
        raise PostgreSQLProvisionError("PostgreSQL password does not meet the secret contract")
    if occupied_database(inventory, port, database):
        raise PostgreSQLProvisionError(
            "refusing to create over an occupied PostgreSQL database"
        )
    if database_exists(inventory, port, database):
        raise PostgreSQLProvisionError(
            "database already exists; choose use-detected or another name"
        )
    existing_roles = _existing_roles(
        runner,
        port,
        (migrator_role, runtime_role, checkpoint_role),
    )
    if existing_roles:
        raise PostgreSQLProvisionError(
            "refusing to reuse existing PostgreSQL roles"
        )
    created_roles: list[str] = []
    created_database = False
    try:
        for role, password, limit in zip(
            (migrator_role, runtime_role, checkpoint_role),
            passwords,
            (5, 30, 5),
            strict=True,
        ):
            _psql(
                runner,
                port,
                "postgres",
                (
                    f"CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                    f"NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {limit} "
                    f"PASSWORD {literal(password)};"
                ),
            )
            created_roles.append(role)
        createdb = _run(
            runner,
            [
                RUNUSER,
                "-u",
                "postgres",
                "--",
                CREATEDB,
                "--username=postgres",
                "--no-password",
                "--port",
                str(port),
                "--owner",
                migrator_role,
                database,
            ],
        )
        if createdb[0] != 0:
            raise PostgreSQLProvisionError("PostgreSQL database creation failed")
        created_database = True
        grant_sql = (
            f"REVOKE ALL ON DATABASE {database} FROM PUBLIC;\n"
            f"GRANT CONNECT ON DATABASE {database} TO {migrator_role}, "
            f"{runtime_role}, {checkpoint_role};\n"
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
        )
        _psql(runner, port, database, grant_sql)
        apply_package_owner_control(
            port=port,
            database=database,
            migrator_role=migrator_role,
            inventory=inventory,
            runner=runner,
        )
    except Exception as error:
        try:
            _drop_created_resources(
                runner,
                port,
                database,
                created_roles=tuple(created_roles),
                created_database=created_database,
            )
        except Exception:
            raise PostgreSQLProvisionError(
                "PostgreSQL provision failed and leftover roles/database could not be removed"
            ) from error
        if isinstance(error, PostgreSQLProvisionError):
            raise
        raise PostgreSQLProvisionError("PostgreSQL provision failed") from error


def package_owner_control_sql(migrator_role: str) -> str:
    """Return postgres-owned SQL that lets the migrator provision LOGIN owners.

    The function is SECURITY DEFINER so the migrator can stay NOCREATEROLE. It
    only accepts one canonical ``plaik_owner_*`` / ``plaik_pkg_*`` pair. Create,
    PUBLIC revoke and migrator GRANT stay in one transaction so a crash cannot
    leave EXECUTE granted to PUBLIC.
    """

    if IDENTIFIER.fullmatch(migrator_role) is None:
        raise PostgreSQLProvisionError("invalid PostgreSQL identifier")
    return f"""
BEGIN;
CREATE SCHEMA IF NOT EXISTS plaik_control;
REVOKE ALL ON SCHEMA plaik_control FROM PUBLIC;
GRANT USAGE ON SCHEMA plaik_control TO {migrator_role};
CREATE OR REPLACE FUNCTION plaik_control.ensure_package_owner_login(
    p_role name,
    p_schema name,
    p_password text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $plaik_ensure$
DECLARE
    role_name text := p_role::text;
    schema_name text := p_schema::text;
    database_name text := current_database();
    scope_key text;
BEGIN
    IF role_name !~ '^plaik_owner_[a-z0-9_]+$' OR char_length(role_name) > 63 THEN
        RAISE EXCEPTION 'invalid package owner role';
    END IF;
    IF schema_name !~ '^plaik_pkg_[a-z0-9_]+$' OR char_length(schema_name) > 63 THEN
        RAISE EXCEPTION 'invalid package schema';
    END IF;
    scope_key := substring(role_name from '^plaik_owner_(.*)$');
    IF scope_key IS NULL
        OR scope_key IS DISTINCT FROM substring(schema_name from '^plaik_pkg_(.*)$') THEN
        RAISE EXCEPTION 'package owner scope is not canonical';
    END IF;
    IF p_password IS NULL OR char_length(p_password) < 43
        OR char_length(p_password) > 256 THEN
        RAISE EXCEPTION 'invalid package owner secret';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = role_name
          AND (
              rolsuper OR rolinherit OR rolcreaterole OR rolcreatedb
              OR rolreplication OR rolbypassrls OR NOT rolcanlogin
          )
    ) THEN
        RAISE EXCEPTION 'package owner role has unsafe attributes';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
        EXECUTE format(
            'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB '
            'NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5 '
            'PASSWORD %L',
            role_name,
            p_password
        );
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_namespace
        WHERE nspname = schema_name
          AND pg_get_userbyid(nspowner) <> role_name
    ) THEN
        RAISE EXCEPTION 'package schema has unexpected owner';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = schema_name) THEN
        EXECUTE format('CREATE SCHEMA %I AUTHORIZATION %I', schema_name, role_name);
    END IF;
    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', schema_name);
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', database_name, role_name);
    EXECUTE format('REVOKE CREATE ON SCHEMA public FROM %I', role_name);
    IF has_schema_privilege(role_name, 'plaik_meta', 'USAGE')
        OR has_schema_privilege(role_name, 'plaik_core', 'USAGE')
        OR has_schema_privilege(role_name, 'public', 'CREATE') THEN
        RAISE EXCEPTION 'package owner can access a protected schema';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_namespace
        WHERE nspname LIKE 'plaik_pkg_%'
          AND nspname <> schema_name
          AND has_schema_privilege(role_name, nspname, 'USAGE')
    ) THEN
        RAISE EXCEPTION 'package owner can access another package schema';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_auth_members AS membership
        JOIN pg_roles AS member_role ON member_role.oid = membership.member
        JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
        WHERE member_role.rolname = role_name
    ) THEN
        RAISE EXCEPTION 'package owner role has outbound role memberships';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_auth_members AS membership
        JOIN pg_roles AS member_role ON member_role.oid = membership.member
        JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
        WHERE granted_role.rolname = role_name
    ) THEN
        RAISE EXCEPTION 'package owner role has inbound role memberships';
    END IF;
END;
$plaik_ensure$;
REVOKE ALL ON FUNCTION plaik_control.ensure_package_owner_login(name, name, text)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION plaik_control.ensure_package_owner_login(name, name, text)
    TO {migrator_role};
CREATE OR REPLACE FUNCTION plaik_control.drop_package_owner_login(
    p_role name,
    p_schema name
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $plaik_drop$
DECLARE
    role_name text := p_role::text;
    schema_name text := p_schema::text;
    database_name text := current_database();
    scope_key text;
    backend integer;
BEGIN
    IF role_name !~ '^plaik_owner_[a-z0-9_]+$' OR char_length(role_name) > 63 THEN
        RAISE EXCEPTION 'invalid package owner role';
    END IF;
    IF schema_name !~ '^plaik_pkg_[a-z0-9_]+$' OR char_length(schema_name) > 63 THEN
        RAISE EXCEPTION 'invalid package schema';
    END IF;
    scope_key := substring(role_name from '^plaik_owner_(.*)$');
    IF scope_key IS NULL
        OR scope_key IS DISTINCT FROM substring(schema_name from '^plaik_pkg_(.*)$') THEN
        RAISE EXCEPTION 'package owner scope is not canonical';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_namespace
        WHERE nspname = schema_name
          AND pg_get_userbyid(nspowner) IS DISTINCT FROM role_name
    ) THEN
        RAISE EXCEPTION 'package schema has unexpected owner';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
        EXECUTE format(
            'ALTER ROLE %I NOLOGIN CONNECTION LIMIT 0',
            role_name
        );
    END IF;
    FOR backend IN
        SELECT pid FROM pg_stat_activity
        WHERE usename = role_name AND pid <> pg_backend_pid()
    LOOP
        PERFORM pg_terminate_backend(backend);
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
        EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM %I', database_name, role_name);
    END IF;
    EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', schema_name);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
        EXECUTE format('DROP ROLE %I', role_name);
    END IF;
END;
$plaik_drop$;
REVOKE ALL ON FUNCTION plaik_control.drop_package_owner_login(name, name)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION plaik_control.drop_package_owner_login(name, name)
    TO {migrator_role};
COMMIT;
"""


def apply_package_owner_control(
    *,
    port: int,
    database: str,
    migrator_role: str,
    inventory: HostInventory,
    runner: ProvisionRunner | None = None,
) -> None:
    """Install LOGIN owner control on an existing local PostgreSQL database.

    This is the supported postgres-peer apply path for create, use-detected, and
    already-provisioned loopback clusters. It does not create databases or
    Core identities.
    """

    if provisionable_listener(inventory, port) is None:
        raise PostgreSQLProvisionError(
            "cannot install package owner control without local postgres peer access"
        )
    identifiers = (database, migrator_role)
    if any(IDENTIFIER.fullmatch(value) is None for value in identifiers):
        raise PostgreSQLProvisionError("invalid PostgreSQL identifier")
    _psql(runner, port, database, package_owner_control_sql(migrator_role))


def try_apply_package_owner_control(
    *,
    port: int,
    database: str,
    migrator_role: str,
    inventory: HostInventory,
    runner: ProvisionRunner | None = None,
) -> bool:
    """Best-effort apply when local postgres peer access is available."""

    if provisionable_listener(inventory, port) is None:
        return False
    try:
        apply_package_owner_control(
            port=port,
            database=database,
            migrator_role=migrator_role,
            inventory=inventory,
            runner=runner,
        )
    except PostgreSQLProvisionError:
        return False
    return True


def restricted_identity_grants(
    migrator_role: str,
    runtime_role: str,
    checkpoint_role: str,
) -> tuple[str, ...]:
    """Return migrator-owned grants that keep runtime off migration evidence.

    Runtime receives DML only on ``plaik_core``. ``plaik_meta`` stays
    migrator/control-plane authority. Checkpoint receives SELECT/INSERT only on
    ``plaik_integrity_checkpoints``. Future Core tables follow default
    privileges limited to ``plaik_core``.
    """

    roles = (migrator_role, runtime_role, checkpoint_role)
    if any(IDENTIFIER.fullmatch(value) is None for value in roles):
        raise PostgreSQLProvisionError("invalid PostgreSQL identifier")
    if len(set(roles)) != len(roles):
        raise PostgreSQLProvisionError("PostgreSQL database and roles must be distinct")
    return (
        f"GRANT USAGE ON SCHEMA plaik_core TO {runtime_role}, {checkpoint_role}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA plaik_core TO {runtime_role}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA plaik_core TO {runtime_role}",
        f"GRANT SELECT, INSERT ON TABLE plaik_core.plaik_integrity_checkpoints TO {checkpoint_role}",
        (
            "REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
            f"ON TABLE plaik_core.plaik_integrity_checkpoints FROM {checkpoint_role}"
        ),
        f"REVOKE ALL ON SCHEMA plaik_meta FROM {runtime_role}, {checkpoint_role}",
        f"REVOKE ALL ON ALL TABLES IN SCHEMA plaik_meta FROM {runtime_role}, {checkpoint_role}",
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA plaik_meta FROM {runtime_role}, {checkpoint_role}",
        (
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {migrator_role} "
            f"REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM {runtime_role}"
        ),
        (
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {migrator_role} "
            f"REVOKE USAGE, SELECT ON SEQUENCES FROM {runtime_role}"
        ),
        (
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {migrator_role} IN SCHEMA plaik_core "
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {runtime_role}"
        ),
        (
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {migrator_role} IN SCHEMA plaik_core "
            f"GRANT USAGE, SELECT ON SEQUENCES TO {runtime_role}"
        ),
    )


def _existing_roles(
    runner: ProvisionRunner | None, port: int, roles: tuple[str, str, str]
) -> tuple[str, ...]:
    listed = ", ".join(literal(role) for role in roles)
    code, output = _psql_query(
        runner,
        port,
        "postgres",
        "SELECT rolname FROM pg_roles WHERE rolname IN "
        f"({listed}) ORDER BY rolname;",
    )
    if code != 0:
        raise PostgreSQLProvisionError("PostgreSQL role inspection failed")
    found = tuple(
        line.strip()
        for line in (output or "").splitlines()
        if line.strip()
    )
    return found


def _drop_created_resources(
    runner: ProvisionRunner | None,
    port: int,
    database: str,
    *,
    created_roles: tuple[str, ...],
    created_database: bool,
) -> None:
    if created_database:
        _psql(runner, port, "postgres", f"DROP DATABASE IF EXISTS {database};")
    for role in reversed(created_roles):
        _psql(runner, port, "postgres", f"DROP ROLE IF EXISTS {role};")


def _psql_command(port: int, database: str) -> list[str]:
    if IDENTIFIER.fullmatch(database) is None and database != "postgres":
        raise PostgreSQLProvisionError("invalid PostgreSQL identifier")
    return [
        RUNUSER,
        "-u",
        "postgres",
        "--",
        PSQL,
        "--no-psqlrc",
        "--no-password",
        "--set=ON_ERROR_STOP=1",
        "-At",
        "--username=postgres",
        "-p",
        str(port),
        "--dbname",
        database,
        "--file",
        "-",
    ]


def _psql_query(
    runner: ProvisionRunner | None, port: int, database: str, sql: str
) -> tuple[int, str]:
    return _run(runner, _psql_command(port, database), sql)


def _psql(
    runner: ProvisionRunner | None, port: int, database: str, sql: str
) -> None:
    code, _output = _psql_query(runner, port, database, sql)
    if code != 0:
        raise PostgreSQLProvisionError("PostgreSQL provision statement failed")
