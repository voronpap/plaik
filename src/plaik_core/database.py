"""Database connectivity primitives shared by bootstrap and migrations.

The preflight deliberately accepts a DB-API style connection factory instead of
owning credentials.  Configuration and secret loading remain separate concerns.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter
from typing import Any, Protocol


class DatabaseCursor(Protocol):
    """Small DB-API cursor surface required by Core."""

    def execute(self, operation: str, parameters: Any = ...) -> Any: ...

    def fetchone(self) -> Any: ...

    def fetchall(self) -> Any: ...

    def close(self) -> None: ...


class DatabaseConnection(Protocol):
    """Small DB-API connection surface required by Core."""

    def cursor(self) -> DatabaseCursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[[], DatabaseConnection]


class DatabasePreflightError(ConnectionError):
    """Opening the configured database or executing the probe failed."""


@dataclass(frozen=True, slots=True)
class DatabasePreflightResult:
    """Non-secret evidence from a successful connectivity probe."""

    driver: str
    elapsed_ms: float
    probe_value: int


def preflight_connection(
    connect: ConnectionFactory,
) -> DatabasePreflightResult:
    """Open, probe and close a database connection without changing data.

    The factory-created connection is always owned and closed by this function.
    Driver exceptions are deliberately not chained because their message may
    contain a credential-bearing DSN.
    """

    started = perf_counter()
    connection: DatabaseConnection | None = None
    cursor: DatabaseCursor | None = None
    try:
        connection = connect()
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        row = cursor.fetchone()
        if row is None or not row or row[0] != 1:
            raise RuntimeError("database validation query returned an unexpected value")
        elapsed_ms = round((perf_counter() - started) * 1000, 3)
        driver = type(connection).__module__.split(".", maxsplit=1)[0]
        return DatabasePreflightResult(
            driver=driver,
            elapsed_ms=elapsed_ms,
            probe_value=1,
        )
    except Exception as error:
        if isinstance(error, DatabasePreflightError):
            raise
        raise DatabasePreflightError(
            f"database preflight failed ({type(error).__name__})"
        ) from None
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
