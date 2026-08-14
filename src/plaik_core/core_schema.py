"""Initial domain-neutral Platform schema for the reference database adapter."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .installer_config import InstallerConfiguration
from .migrations import Migration


CORE_MIGRATIONS = (
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
                config_digest TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE plaik_store_groups (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (installation_id) REFERENCES plaik_installations(id)
            )
            """,
            """
            CREATE TABLE plaik_stores (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (installation_id) REFERENCES plaik_installations(id),
                FOREIGN KEY (group_id) REFERENCES plaik_store_groups(id)
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
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_generation INTEGER NOT NULL CHECK (schema_generation >= 1),
                minimum_reader_generation INTEGER NOT NULL
                    CHECK (
                        minimum_reader_generation >= 1
                        AND minimum_reader_generation <= schema_generation
                    ),
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            INSERT INTO plaik_runtime_schema_metadata
                (singleton, schema_generation, minimum_reader_generation)
            VALUES (1, 2, 1)
            """,
        ),
    ),
)


def initialize_reference_context(
    connect: Callable[[], Any], configuration: InstallerConfiguration
) -> None:
    """Persist the configured installation/group/store tree atomically.

    This is reference-adapter bootstrap data, not a versioned schema change.
    Re-entry is idempotent, but a different value for an existing immutable
    identifier is treated as configuration drift.
    """

    connection = connect()
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        _insert_or_verify(
            connection,
            "plaik_installations",
            (
                "id",
                "profile",
                "locale",
                "timezone",
                "public_url",
                "config_digest",
            ),
            (
                configuration.installation_id,
                configuration.profile.value,
                configuration.locale,
                configuration.timezone,
                str(configuration.public_url),
                configuration.fingerprint(),
            ),
        )
        _insert_or_verify(
            connection,
            "plaik_store_groups",
            ("id", "installation_id"),
            (configuration.group_id, configuration.installation_id),
        )
        _insert_or_verify(
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
    except Exception:
        connection.rollback()
        raise
    finally:
        try:
            connection.close()
        except Exception:
            pass


def verify_reference_context(
    connect: Callable[[], Any], configuration: InstallerConfiguration
) -> None:
    """Verify persisted immutable context and configuration digest read-only."""

    connection = connect()
    try:
        expected_installation = (
            configuration.installation_id,
            configuration.profile.value,
            configuration.locale,
            configuration.timezone,
            str(configuration.public_url),
            configuration.fingerprint(),
        )
        installation = connection.execute(
            """
            SELECT id, profile, locale, timezone, public_url, config_digest
            FROM plaik_installations
            WHERE id = ?
            """,
            (configuration.installation_id,),
        ).fetchone()
        group = connection.execute(
            """
            SELECT id, installation_id
            FROM plaik_store_groups
            WHERE id = ?
            """,
            (configuration.group_id,),
        ).fetchone()
        store = connection.execute(
            """
            SELECT id, installation_id, group_id
            FROM plaik_stores
            WHERE id = ?
            """,
            (configuration.store_id,),
        ).fetchone()
        if installation != expected_installation:
            raise RuntimeError("Platform installation configuration drift detected")
        if group != (configuration.group_id, configuration.installation_id):
            raise RuntimeError("Platform store-group context drift detected")
        if store != (
            configuration.store_id,
            configuration.installation_id,
            configuration.group_id,
        ):
            raise RuntimeError("Platform store context drift detected")
    finally:
        try:
            connection.close()
        except Exception:
            pass


def _insert_or_verify(
    connection: Any,
    table: str,
    columns: tuple[str, ...],
    values: tuple[str, ...],
) -> None:
    placeholders = ", ".join("?" for _ in columns)
    column_list = ", ".join(columns)
    connection.execute(
        f"INSERT OR IGNORE INTO {table} ({column_list}) VALUES ({placeholders})",
        values,
    )
    selected = connection.execute(
        f"SELECT {column_list} FROM {table} WHERE id = ?",
        (values[0],),
    ).fetchone()
    if selected != values:
        raise RuntimeError(f"immutable Platform context drift detected in {table}")
