"""PostgreSQL live SettingsStore on Core table plaik_settings_registry."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from .database import ConnectionFactory, DatabaseConnection
from .settings_store import SettingsStore, SettingsStoreError

_TABLE = "plaik_core.plaik_settings_registry"


class PostgreSQLSettingsStore(SettingsStore):
    """Canonical PostgreSQL persistence for the SettingsStore registry shape.

    The JSON file on ``base.path`` is a one-shot seed when the singleton row
    is first inserted. After that the table is the only live store. Reads
    with no row return an empty registry and do not consult JSON.
    """

    def __init__(self, connect: ConnectionFactory, base: SettingsStore) -> None:
        self.path = base.path
        self.schemas = base.schemas
        self._base = base
        self._connect_factory = connect
        self._thread_lock = threading.RLock()

    @property
    def audit_sink(self):
        return self._base.audit_sink

    @audit_sink.setter
    def audit_sink(self, value) -> None:
        self._base.audit_sink = value

    def _open(self) -> DatabaseConnection:
        try:
            return self._connect_factory()
        except Exception:
            raise SettingsStoreError(
                "PostgreSQL settings registry could not be opened"
            ) from None

    def _read_registry(self) -> dict[str, Any]:
        connection: DatabaseConnection | None = None
        try:
            connection = self._open()
            row = _fetchone(
                connection,
                f"SELECT version, scopes FROM {_TABLE} WHERE singleton = 1",
            )
            connection.rollback()
            if row is None:
                return {"version": self.REGISTRY_VERSION, "scopes": {}}
            return self._registry_from_row(row)
        except SettingsStoreError:
            if connection is not None:
                _safe_rollback(connection)
            raise
        except Exception:
            if connection is not None:
                _safe_rollback(connection)
            raise SettingsStoreError(
                "PostgreSQL settings registry could not be read"
            ) from None
        finally:
            if connection is not None:
                _safe_close(connection)

    @contextmanager
    def _registry_transaction(self) -> Iterator[dict[str, Any]]:
        with self._thread_lock:
            connection: DatabaseConnection | None = None
            try:
                connection = self._open()
                inserted = _fetchone(
                    connection,
                    f"""
                    INSERT INTO {_TABLE} (singleton, version, scopes)
                    VALUES (1, %s, %s::jsonb)
                    ON CONFLICT (singleton) DO NOTHING
                    RETURNING version, scopes
                    """,
                    (self.REGISTRY_VERSION, json.dumps({}, allow_nan=False)),
                )
                row = _fetchone(
                    connection,
                    f"SELECT version, scopes FROM {_TABLE} WHERE singleton = 1 FOR UPDATE",
                )
                if row is None:
                    raise SettingsStoreError("PostgreSQL settings registry row is missing")
                if inserted is not None:
                    registry = self._seed_registry()
                else:
                    registry = self._registry_from_row(row)
                yield registry
                _execute(
                    connection,
                    f"""
                    UPDATE {_TABLE}
                    SET version = %s,
                        scopes = %s::jsonb,
                        updated_at = clock_timestamp()
                    WHERE singleton = 1
                    """,
                    (
                        registry["version"],
                        json.dumps(registry["scopes"], allow_nan=False),
                    ),
                )
                connection.commit()
            except SettingsStoreError:
                if connection is not None:
                    _safe_rollback(connection)
                raise
            except Exception:
                if connection is not None:
                    _safe_rollback(connection)
                raise SettingsStoreError(
                    "PostgreSQL settings registry could not be written"
                ) from None
            except BaseException:
                if connection is not None:
                    _safe_rollback(connection)
                raise
            finally:
                if connection is not None:
                    _safe_close(connection)

    def _seed_registry(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"version": self.REGISTRY_VERSION, "scopes": {}}
        registry = SettingsStore._read_registry(self)
        self._reject_insecure_seed(registry)
        return registry

    def _reject_insecure_seed(self, registry: Mapping[str, Any]) -> None:
        scopes = registry["scopes"]
        for scope_key, namespaces in scopes.items():
            if not isinstance(scope_key, str) or not isinstance(namespaces, dict):
                raise SettingsStoreError(f"invalid settings scope: {scope_key}")
            for namespace, override in namespaces.items():
                if not isinstance(override, dict):
                    raise SettingsStoreError(
                        f"invalid settings record for {scope_key}/{namespace}"
                    )
                if namespace not in self.schemas:
                    continue
                schema = self.schemas[namespace]
                unknown = sorted(set(override) - self._public_field_names(schema))
                if unknown:
                    raise SettingsStoreError(
                        f"unknown settings for {namespace}: {unknown}"
                    )
                validated = self._validate(schema, namespace, override)
                self._assert_secret_references(validated, override)

    def _registry_from_row(self, row: Any) -> dict[str, Any]:
        version, scopes = row
        if isinstance(scopes, str):
            try:
                scopes = json.loads(scopes)
            except json.JSONDecodeError:
                raise SettingsStoreError(
                    "settings registry scopes must be an object"
                ) from None
        return self._require_registry({"version": version, "scopes": scopes})


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
