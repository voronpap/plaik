"""Generation-fenced package LOGIN SQL sessions for ExtensionRuntime.sql."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any

from plaik_sdk import PackageSql, PackageSqlSession

from .postgresql import PostgreSQLOwnerScope, _quote_identifier


class PackageSqlUnavailable(RuntimeError):
    """Package SQL cannot be opened or is no longer bound."""


def _sql_params(params: object) -> tuple[object, ...] | Mapping[str, object]:
    if params is None:
        return ()
    if isinstance(params, Mapping):
        return params
    if isinstance(params, (list, tuple)):
        return tuple(params)
    raise TypeError("SQL params must be a sequence or mapping")


def _sql_row(cursor: Any) -> dict[str, Any] | None:
    row = cursor.fetchone()
    if row is None:
        return None
    description = getattr(cursor, "description", None) or ()
    names = [column[0] for column in description]
    if not names:
        return {str(index): value for index, value in enumerate(row)}
    return {name: value for name, value in zip(names, row, strict=False)}


def _sql_rows(cursor: Any) -> tuple[dict[str, Any], ...]:
    rows = cursor.fetchall()
    description = getattr(cursor, "description", None) or ()
    names = [column[0] for column in description]
    mapped: list[dict[str, Any]] = []
    for row in rows:
        if not names:
            mapped.append({str(index): value for index, value in enumerate(row)})
        else:
            mapped.append(
                {name: value for name, value in zip(names, row, strict=False)}
            )
    return tuple(mapped)


def _close_sql_connection(connection: Any) -> None:
    closer = getattr(connection, "close", None)
    if callable(closer):
        try:
            closer()
        except Exception:
            return


def _cursor_execute(connection: Any, sql: str, params: object = ()) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute(sql, params)
    finally:
        close = getattr(cursor, "close", None)
        if callable(close):
            close()


def prepare_package_search_path(connection: Any, owner: str) -> None:
    scope = PostgreSQLOwnerScope.for_package(owner)
    quoted = _quote_identifier(scope.schema)
    _cursor_execute(connection, f"SET LOCAL search_path TO {quoted}, pg_temp")


class OpenSql:
    __slots__ = ("connection", "depth")

    def __init__(self, connection: Any) -> None:
        self.connection = connection
        self.depth = 0


class OwnerSqlSession(PackageSqlSession):
    def __init__(self, sql: OwnerSql, connection: Any) -> None:
        self._sql = sql
        self._connection = connection

    def execute(
        self,
        sql: str,
        params: list[Any] | tuple[Any, ...] | Mapping[str, Any] | None = None,
    ) -> None:
        self._run(sql, params, fetch="none")

    def fetchone(
        self,
        sql: str,
        params: list[Any] | tuple[Any, ...] | Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any] | None:
        return self._run(sql, params, fetch="one")

    def fetchall(
        self,
        sql: str,
        params: list[Any] | tuple[Any, ...] | Mapping[str, Any] | None = None,
    ) -> tuple[Mapping[str, Any], ...]:
        return self._run(sql, params, fetch="all")

    def _run(self, sql: str, params: object, *, fetch: str) -> Any:
        if type(sql) is not str or not sql.strip():
            raise PackageSqlUnavailable("package SQL statement is empty")
        bound = _sql_params(params)
        self._sql.assert_bound()
        cursor = self._connection.cursor()
        try:
            cursor.execute(sql, bound)
            if fetch == "one":
                return _sql_row(cursor)
            if fetch == "all":
                return _sql_rows(cursor)
            return None
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()


class OwnerSqlTransaction:
    def __init__(self, sql: OwnerSql) -> None:
        self._sql = sql
        self._key: tuple[int, str] | None = None
        self._savepoint: str | None = None
        self._opened = False

    def __enter__(self) -> OwnerSqlSession:
        host = self._sql.host
        owner = self._sql.owner
        self._sql.assert_bound()
        key = (threading.get_ident(), owner)
        self._key = key
        entry = host._sql_open.get(key)
        if entry is None:
            connect = host._package_sql_connect
            if connect is None:
                raise PackageSqlUnavailable("package SQL is unavailable")
            try:
                connection = connect(owner)
            except PackageSqlUnavailable:
                raise
            except Exception as error:
                raise PackageSqlUnavailable("package SQL is unavailable") from error
            try:
                self._sql.assert_bound()
                prepare_package_search_path(connection, owner)
            except Exception:
                _close_sql_connection(connection)
                raise
            entry = OpenSql(connection)
            host._sql_open[key] = entry
            self._opened = True
        entry.depth += 1
        if entry.depth > 1:
            self._savepoint = f"plaik_sql_{entry.depth}"
            _cursor_execute(entry.connection, f"SAVEPOINT {self._savepoint}")
        return OwnerSqlSession(self._sql, entry.connection)

    def __exit__(self, exc_type, exc, tb) -> bool:
        del exc, tb
        key = self._key
        if key is None:
            return False
        host = self._sql.host
        entry = host._sql_open.get(key)
        if entry is None:
            return False
        connection = entry.connection
        try:
            if exc_type is not None:
                if self._savepoint is not None:
                    _cursor_execute(
                        connection, f"ROLLBACK TO SAVEPOINT {self._savepoint}"
                    )
                else:
                    rollback = getattr(connection, "rollback", None)
                    if callable(rollback):
                        rollback()
            else:
                self._sql.assert_bound()
                if self._savepoint is not None:
                    _cursor_execute(
                        connection, f"RELEASE SAVEPOINT {self._savepoint}"
                    )
                else:
                    commit = getattr(connection, "commit", None)
                    if callable(commit):
                        commit()
        except Exception:
            rollback = getattr(connection, "rollback", None)
            if callable(rollback):
                try:
                    rollback()
                except Exception:
                    pass
            if exc_type is None:
                raise
        finally:
            entry.depth -= 1
            if entry.depth <= 0 or self._opened:
                host._sql_open.pop(key, None)
                _close_sql_connection(connection)
        return False


class OwnerSql(PackageSql):
    def __init__(self, host: Any, owner: str, generation: int) -> None:
        self.host = host
        self.owner = owner
        self.generation = generation

    def assert_bound(self) -> None:
        with self.host._lock:
            if self.host._runtime_generations.get(self.owner) != self.generation:
                raise PackageSqlUnavailable("package SQL is no longer bound")

    def transaction(self) -> OwnerSqlTransaction:
        return OwnerSqlTransaction(self)
