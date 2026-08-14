"""Transactional migration runner with an immutable ownership ledger.

The runner is intentionally small and uses SQLite's ``BEGIN IMMEDIATE`` as the
reference locking implementation.  Its public migration and ledger contracts
are suitable for a later PostgreSQL adapter without coupling migrations to the
installer API.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from .database import ConnectionFactory, DatabaseConnection


OWNER_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*$")
TRANSACTION_CONTROL_KEYWORDS = {
    "BEGIN",
    "COMMIT",
    "END",
    "ROLLBACK",
    "SAVEPOINT",
    "RELEASE",
}
FORBIDDEN_MIGRATION_KEYWORDS = {
    "ATTACH",
    "DETACH",
    "PRAGMA",
    "VACUUM",
}
LEDGER_TABLE = "plaik_migration_ledger"
LOCK_TABLE = "plaik_migration_lock"


class MigrationStatus(StrEnum):
    APPLYING = "applying"
    APPLIED = "applied"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Migration:
    """An immutable, checksummed SQL migration owned by Core or one package."""

    owner: str
    version: str
    statements: tuple[str, ...]
    checksum: str = field(init=False)

    def __post_init__(self) -> None:
        if not OWNER_PATTERN.fullmatch(self.owner):
            raise ValueError(f"invalid migration owner: {self.owner!r}")
        if not VERSION_PATTERN.fullmatch(self.version):
            raise ValueError(f"invalid migration version: {self.version!r}")
        statements = tuple(self.statements)
        if not statements:
            raise ValueError("migration requires at least one SQL statement")
        for statement in statements:
            if not isinstance(statement, str) or not statement.strip():
                raise ValueError("migration statements must be non-empty strings")
            _validate_statement_boundary(statement)
        payload = json.dumps(
            statements,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        object.__setattr__(self, "statements", statements)
        object.__setattr__(self, "checksum", hashlib.sha256(payload).hexdigest())

    @property
    def key(self) -> tuple[str, str]:
        return (self.owner, self.version)


@dataclass(frozen=True, slots=True)
class MigrationLedgerEntry:
    owner: str
    version: str
    checksum: str
    status: MigrationStatus
    started_at: str
    finished_at: str | None
    error: str | None


@dataclass(frozen=True, slots=True)
class MigrationRunResult:
    applied: tuple[tuple[str, str], ...]
    skipped: tuple[tuple[str, str], ...]


class MigrationError(RuntimeError):
    """Base migration failure."""


class MigrationLockError(MigrationError):
    """Another process owns the migration writer lock."""


class MigrationChecksumError(MigrationError):
    """An existing owner/version was supplied with different SQL."""


class MigrationStateError(MigrationError):
    """Persisted migration state violates runner invariants."""


class MigrationApplyError(MigrationError):
    """A migration failed and its SQL changes were rolled back."""

    def __init__(
        self,
        migration: Migration,
        *,
        evidence_recorded: bool,
    ) -> None:
        self.owner = migration.owner
        self.version = migration.version
        self.evidence_recorded = evidence_recorded
        super().__init__(
            f"migration {migration.owner}:{migration.version} failed; "
            f"failure evidence recorded={evidence_recorded}"
        )


class MigrationRunner:
    """Apply an ordered migration batch atomically using a SQLite connection."""

    def __init__(
        self,
        connect: ConnectionFactory,
        *,
        lock_timeout_seconds: float = 5.0,
    ) -> None:
        if lock_timeout_seconds < 0:
            raise ValueError("lock timeout cannot be negative")
        self.connect = connect
        self.lock_timeout_ms = round(lock_timeout_seconds * 1000)

    def apply(self, migrations: Iterable[Migration]) -> MigrationRunResult:
        batch = tuple(migrations)
        self._validate_batch(batch)
        connection = self.connect()
        holder = uuid.uuid4().hex
        current: Migration | None = None
        current_started: str | None = None
        applied: list[tuple[str, str]] = []
        skipped: list[tuple[str, str]] = []
        try:
            self._configure(connection)
            try:
                self._initialize_schema(connection)
            except Exception as error:
                if _is_lock_error(error):
                    raise MigrationLockError("migration database is locked") from error
                raise
            self._begin_locked(connection, holder)
            try:
                for migration in batch:
                    current = migration
                    existing = self._entry(connection, migration.owner, migration.version)
                    if existing is not None:
                        if existing.checksum != migration.checksum:
                            raise MigrationChecksumError(
                                f"checksum mismatch for {migration.owner}:{migration.version}"
                            )
                        if existing.status == MigrationStatus.APPLIED:
                            skipped.append(migration.key)
                            continue
                        if existing.status == MigrationStatus.APPLYING:
                            raise MigrationStateError(
                                f"migration is unexpectedly still applying: "
                                f"{migration.owner}:{migration.version}"
                            )

                    current_started = _utc_now()
                    self._mark_applying(connection, migration, current_started)
                    for statement in migration.statements:
                        self._execute_migration_statement(connection, statement)
                    self._mark_applied(connection, migration, _utc_now())
                    applied.append(migration.key)

                self._execute(
                    connection,
                    f"DELETE FROM {LOCK_TABLE} WHERE singleton = 1 AND holder = ?",
                    (holder,),
                )
                connection.commit()
            except (MigrationChecksumError, MigrationStateError):
                connection.rollback()
                raise
            except Exception as error:
                connection.rollback()
                if current is None:
                    raise MigrationError("migration batch failed before applying a step") from error
                evidence_recorded = self._record_failure(
                    connection,
                    current,
                    started_at=current_started or _utc_now(),
                    error=error,
                )
                raise MigrationApplyError(
                    current,
                    evidence_recorded=evidence_recorded,
                ) from error
        finally:
            _safe_close(connection)
        return MigrationRunResult(applied=tuple(applied), skipped=tuple(skipped))

    def ledger(self) -> tuple[MigrationLedgerEntry, ...]:
        connection = self.connect()
        try:
            self._configure(connection)
            self._initialize_schema(connection)
            rows = self._fetchall(
                connection,
                f"""
                SELECT owner, version, checksum, status, started_at, finished_at, error
                FROM {LEDGER_TABLE}
                ORDER BY owner, version
                """,
            )
            return tuple(
                MigrationLedgerEntry(
                    owner=row[0],
                    version=row[1],
                    checksum=row[2],
                    status=MigrationStatus(row[3]),
                    started_at=row[4],
                    finished_at=row[5],
                    error=row[6],
                )
                for row in rows
            )
        finally:
            _safe_close(connection)

    @staticmethod
    def _validate_batch(batch: tuple[Migration, ...]) -> None:
        keys = [migration.key for migration in batch]
        if len(keys) != len(set(keys)):
            raise ValueError("migration batch contains duplicate owner/version keys")

    def _configure(self, connection: DatabaseConnection) -> None:
        self._execute(connection, "PRAGMA foreign_keys = ON")
        self._execute(connection, f"PRAGMA busy_timeout = {self.lock_timeout_ms}")

    def _initialize_schema(self, connection: DatabaseConnection) -> None:
        try:
            self._execute(
                connection,
                f"""
                CREATE TABLE IF NOT EXISTS {LEDGER_TABLE} (
                    owner TEXT NOT NULL,
                    version TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('applying', 'applied', 'failed')),
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    error TEXT,
                    PRIMARY KEY (owner, version)
                )
                """,
            )
            self._execute(
                connection,
                f"""
                CREATE TABLE IF NOT EXISTS {LOCK_TABLE} (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    holder TEXT NOT NULL,
                    acquired_at TEXT NOT NULL
                )
                """,
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _begin_locked(self, connection: DatabaseConnection, holder: str) -> None:
        try:
            self._execute(connection, "BEGIN IMMEDIATE")
            self._execute(
                connection,
                f"INSERT INTO {LOCK_TABLE} (singleton, holder, acquired_at) VALUES (1, ?, ?)",
                (holder, _utc_now()),
            )
        except Exception as error:
            connection.rollback()
            if _is_lock_error(error) or isinstance(error, sqlite3.IntegrityError):
                raise MigrationLockError("migration lock is already held") from error
            raise

    def _entry(
        self,
        connection: DatabaseConnection,
        owner: str,
        version: str,
    ) -> MigrationLedgerEntry | None:
        row = self._fetchone(
            connection,
            f"""
            SELECT owner, version, checksum, status, started_at, finished_at, error
            FROM {LEDGER_TABLE}
            WHERE owner = ? AND version = ?
            """,
            (owner, version),
        )
        if row is None:
            return None
        return MigrationLedgerEntry(
            owner=row[0],
            version=row[1],
            checksum=row[2],
            status=MigrationStatus(row[3]),
            started_at=row[4],
            finished_at=row[5],
            error=row[6],
        )

    def _mark_applying(
        self,
        connection: DatabaseConnection,
        migration: Migration,
        started_at: str,
    ) -> None:
        existing = self._entry(connection, migration.owner, migration.version)
        if existing is None:
            self._execute(
                connection,
                f"""
                INSERT INTO {LEDGER_TABLE}
                    (owner, version, checksum, status, started_at, finished_at, error)
                VALUES (?, ?, ?, 'applying', ?, NULL, NULL)
                """,
                (migration.owner, migration.version, migration.checksum, started_at),
            )
        else:
            self._execute(
                connection,
                f"""
                UPDATE {LEDGER_TABLE}
                SET status = 'applying', started_at = ?, finished_at = NULL, error = NULL
                WHERE owner = ? AND version = ?
                """,
                (started_at, migration.owner, migration.version),
            )

    def _mark_applied(
        self,
        connection: DatabaseConnection,
        migration: Migration,
        finished_at: str,
    ) -> None:
        self._execute(
            connection,
            f"""
            UPDATE {LEDGER_TABLE}
            SET status = 'applied', finished_at = ?, error = NULL
            WHERE owner = ? AND version = ?
            """,
            (finished_at, migration.owner, migration.version),
        )

    def _record_failure(
        self,
        connection: DatabaseConnection,
        migration: Migration,
        *,
        started_at: str,
        error: Exception,
    ) -> bool:
        driver_code = getattr(error, "sqlite_errorname", None)
        safe_error = type(error).__name__
        if isinstance(driver_code, str) and driver_code:
            safe_error = f"{safe_error} ({driver_code})"
        finished_at = _utc_now()
        try:
            self._execute(connection, "BEGIN IMMEDIATE")
            existing = self._entry(connection, migration.owner, migration.version)
            if existing is not None and existing.status == MigrationStatus.APPLIED:
                connection.rollback()
                return False
            if existing is None:
                self._execute(
                    connection,
                    f"""
                    INSERT INTO {LEDGER_TABLE}
                        (owner, version, checksum, status, started_at, finished_at, error)
                    VALUES (?, ?, ?, 'failed', ?, ?, ?)
                    """,
                    (
                        migration.owner,
                        migration.version,
                        migration.checksum,
                        started_at,
                        finished_at,
                        safe_error,
                    ),
                )
            else:
                self._execute(
                    connection,
                    f"""
                    UPDATE {LEDGER_TABLE}
                    SET checksum = ?, status = 'failed', started_at = ?,
                        finished_at = ?, error = ?
                    WHERE owner = ? AND version = ?
                    """,
                    (
                        migration.checksum,
                        started_at,
                        finished_at,
                        safe_error,
                        migration.owner,
                        migration.version,
                    ),
                )
            self._execute(connection, f"DELETE FROM {LOCK_TABLE} WHERE singleton = 1")
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            return False

    @staticmethod
    def _execute_migration_statement(
        connection: DatabaseConnection,
        operation: str,
    ) -> None:
        """Execute package/Core SQL under the SQLite reference sandbox.

        Static token validation catches portable boundary violations early. The
        SQLite authorizer is the runtime backstop against attached databases,
        internal-ledger mutation, transaction control and extension loading.
        A production PostgreSQL adapter needs its own parser and role isolation.
        """

        set_authorizer = getattr(connection, "set_authorizer", None)
        if not callable(set_authorizer):
            raise MigrationError(
                "reference migration connection does not support SQLite authorization"
            )
        set_authorizer(_sqlite_migration_authorizer)
        try:
            MigrationRunner._execute(connection, operation)
        finally:
            set_authorizer(None)

    @staticmethod
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

    @staticmethod
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

    @staticmethod
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


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _is_lock_error(error: Exception) -> bool:
    message = str(error).lower()
    return "locked" in message or "busy" in message


def _safe_close(resource: Any) -> None:
    try:
        resource.close()
    except Exception:
        # Cleanup must not replace the migration result or its primary error.
        pass


def _validate_statement_boundary(statement: str) -> None:
    """Reject transaction control and multi-statement SQL conservatively.

    Strings, quoted identifiers and line/block comments are erased before the
    boundary is inspected. This closes comment-prefix bypasses while allowing
    words such as ``COMMIT`` inside a literal value.
    """

    executable = _erase_sql_literals_and_comments(statement).strip()
    if not executable:
        raise ValueError("migration statement contains no executable SQL")

    semicolons = [index for index, character in enumerate(executable) if character == ";"]
    if semicolons and not (len(semicolons) == 1 and semicolons[0] == len(executable) - 1):
        raise ValueError("migration statements must contain exactly one SQL command")

    first_token = re.search(r"[A-Za-z_][A-Za-z0-9_$]*", executable)
    if first_token:
        keyword = first_token.group(0).upper()
        if keyword in TRANSACTION_CONTROL_KEYWORDS:
            raise ValueError("migration may not control its transaction")
        if keyword in FORBIDDEN_MIGRATION_KEYWORDS:
            raise ValueError(f"migration command is not allowed: {keyword}")
    if re.search(r"\bload_extension\s*\(", executable, flags=re.IGNORECASE):
        raise ValueError("migration may not load SQLite extensions")


def _sqlite_migration_authorizer(
    action: int,
    argument_one: str | None,
    argument_two: str | None,
    database_name: str | None,
    _trigger_or_view: str | None,
) -> int:
    denied_actions = {
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_DETACH,
        sqlite3.SQLITE_PRAGMA,
        sqlite3.SQLITE_TRANSACTION,
        sqlite3.SQLITE_CREATE_VTABLE,
        sqlite3.SQLITE_DROP_VTABLE,
    }
    savepoint_action = getattr(sqlite3, "SQLITE_SAVEPOINT", None)
    if savepoint_action is not None:
        denied_actions.add(savepoint_action)
    if action in denied_actions:
        return sqlite3.SQLITE_DENY
    if database_name not in {None, "main"}:
        return sqlite3.SQLITE_DENY
    if argument_one in {LEDGER_TABLE, LOCK_TABLE}:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and (
        (argument_one or "").casefold() == "load_extension"
        or (argument_two or "").casefold() == "load_extension"
    ):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _erase_sql_literals_and_comments(statement: str) -> str:
    output = list(statement)
    index = 0
    length = len(statement)
    while index < length:
        pair = statement[index : index + 2]
        if pair == "--":
            end = statement.find("\n", index + 2)
            end = length if end < 0 else end
            for position in range(index, end):
                output[position] = " "
            index = end
            continue
        if pair == "/*":
            depth = 1
            end = index + 2
            while end < length and depth:
                if statement[end : end + 2] == "/*":
                    depth += 1
                    end += 2
                elif statement[end : end + 2] == "*/":
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise ValueError("migration statement contains an unterminated comment")
            for position in range(index, end):
                output[position] = " "
            index = end
            continue
        if statement[index] in {"'", '"', "`"}:
            quote = statement[index]
            end = index + 1
            while end < length:
                if statement[end] == quote:
                    if end + 1 < length and statement[end + 1] == quote:
                        end += 2
                        continue
                    end += 1
                    break
                if statement[end] == "\\" and end + 1 < length:
                    end += 2
                else:
                    end += 1
            else:
                raise ValueError("migration statement contains an unterminated quote")
            for position in range(index, end):
                output[position] = " "
            index = end
            continue
        if statement[index] == "[":
            end = statement.find("]", index + 1)
            if end < 0:
                raise ValueError("migration statement contains an unterminated identifier")
            end += 1
            for position in range(index, end):
                output[position] = " "
            index = end
            continue
        if statement[index] == "$":
            delimiter_match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", statement[index:])
            if delimiter_match:
                delimiter = delimiter_match.group(0)
                end = statement.find(delimiter, index + len(delimiter))
                if end < 0:
                    raise ValueError("migration statement contains an unterminated dollar quote")
                end += len(delimiter)
                for position in range(index, end):
                    output[position] = " "
                index = end
                continue
        index += 1
    return "".join(output)
