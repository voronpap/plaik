"""PostgreSQL-backed identity, session, audit and operation journals."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from .audit import (
    GENESIS_HASH as AUDIT_GENESIS,
    AuditEvent,
    AuditIntegrityError,
    AuditLog,
    AuditOutcome,
    AuditVerification,
    _as_utc as audit_as_utc,
    _event_body as audit_event_body,
    _json_copy as audit_json_copy,
    _validate_name as audit_validate_name,
)
from .database import ConnectionFactory
from .identity import (
    SUPER_ADMIN_PERMISSION,
    SUPER_ADMIN_ROLE,
    AuthenticationError,
    AuthorizationError,
    IdentityError,
    IdentityInvariantError,
    PasswordHasher,
    RoleRecord,
    SessionError,
    SessionRecord,
    SessionToken,
    UserRecord,
    _as_utc,
    _normalize_email,
    _parse_session_token,
    _require_user,
    _validate_cleanup_batch_size,
    _validate_permission,
    _validate_role_id,
)
from .operation_journal import (
    GENESIS_HASH as OPERATION_GENESIS,
    OperationEvent,
    OperationJournal,
    OperationJournalIntegrityError,
    OperationJournalVerification,
    OperationState,
    OperationStatus,
    _apply_event,
    _event_body as operation_event_body,
)
from .postgresql import (
    CORE_SCHEMA,
    _execute,
    _fetchall,
    _fetchone,
    _qualified,
    _safe_close,
    _safe_rollback,
)


JOURNAL_AUDIT = "audit"
JOURNAL_OPERATIONS = "operations"

_IDENTITY_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"plaik-v2:postgresql-identity:v1").digest()[:8],
    byteorder="big",
    signed=True,
)
_SESSION_LOCK_KEY = _IDENTITY_LOCK_KEY + 1
_AUDIT_LOCK_KEY = _IDENTITY_LOCK_KEY + 2
_OPERATION_LOCK_KEY = _IDENTITY_LOCK_KEY + 3


class PostgreSQLJournalLines:
    """Append-only JSONL lines stored in ``plaik_journal_lines``."""

    def __init__(self, connect: ConnectionFactory, journal_id: str) -> None:
        self.connect = connect
        self.journal_id = journal_id
        self._table = _qualified(CORE_SCHEMA, "plaik_journal_lines")

    def read_lines(self) -> list[str]:
        connection = self.connect()
        try:
            rows = _fetchall(
                connection,
                f"""
                SELECT content FROM {self._table}
                WHERE journal_id = %s
                ORDER BY sequence
                """,
                (self.journal_id,),
            )
            connection.commit()
            return [row[0] for row in rows]
        except Exception:
            _safe_rollback(connection)
            raise
        finally:
            _safe_close(connection)

    def append_line(self, line: str) -> None:
        if not line.endswith("\n"):
            raise ValueError("journal line must include trailing newline")
        connection = self.connect()
        try:
            _execute(
                connection,
                "SELECT pg_advisory_lock(%s)",
                (_journal_lock(self.journal_id),),
            )
            row = _fetchone(
                connection,
                f"""
                SELECT COALESCE(MAX(sequence), 0) + 1
                FROM {self._table}
                WHERE journal_id = %s
                """,
                (self.journal_id,),
            )
            sequence = int(row[0]) if row else 1
            _execute(
                connection,
                f"""
                INSERT INTO {self._table} (journal_id, sequence, content)
                VALUES (%s, %s, %s)
                """,
                (self.journal_id, sequence, line),
            )
            connection.commit()
        except Exception:
            _safe_rollback(connection)
            raise
        finally:
            try:
                _execute(
                    connection,
                    "SELECT pg_advisory_unlock(%s)",
                    (_journal_lock(self.journal_id),),
                )
                connection.commit()
            except Exception:
                _safe_rollback(connection)
            _safe_close(connection)

    def import_lines_if_empty(self, lines: list[str]) -> bool:
        """Insert ``lines`` in one transaction when this journal has no rows.

        Returns True if the snapshot was stored, False if rows already existed.
        A mismatch or any error rolls the whole import back so a later boot can
        retry instead of keeping a truncated chain.
        """

        if not lines:
            return False
        for line in lines:
            if not line.endswith("\n"):
                raise ValueError("journal line must include trailing newline")
        connection = self.connect()
        try:
            _execute(
                connection,
                "SELECT pg_advisory_lock(%s)",
                (_journal_lock(self.journal_id),),
            )
            row = _fetchone(
                connection,
                f"""
                SELECT COALESCE(MAX(sequence), 0)
                FROM {self._table}
                WHERE journal_id = %s
                """,
                (self.journal_id,),
            )
            if int(row[0] if row else 0) > 0:
                connection.commit()
                return False
            for sequence, line in enumerate(lines, start=1):
                _execute(
                    connection,
                    f"""
                    INSERT INTO {self._table} (journal_id, sequence, content)
                    VALUES (%s, %s, %s)
                    """,
                    (self.journal_id, sequence, line),
                )
            stored = _fetchall(
                connection,
                f"""
                SELECT content FROM {self._table}
                WHERE journal_id = %s
                ORDER BY sequence
                """,
                (self.journal_id,),
            )
            if [item[0] for item in stored] != list(lines):
                raise RuntimeError("imported journal lines did not round-trip")
            connection.commit()
            return True
        except Exception:
            _safe_rollback(connection)
            raise
        finally:
            try:
                _execute(
                    connection,
                    "SELECT pg_advisory_unlock(%s)",
                    (_journal_lock(self.journal_id),),
                )
                connection.commit()
            except Exception:
                _safe_rollback(connection)
            _safe_close(connection)


def _journal_lock(journal_id: str) -> int:
    digest = hashlib.sha256(f"plaik-journal:{journal_id}".encode()).digest()[:8]
    return int.from_bytes(digest, byteorder="big", signed=True)


@contextmanager
def _journal_chain_lock(
    connect: ConnectionFactory,
    lock_key: int,
    thread_lock: threading.RLock,
) -> Iterator[None]:
    """Serialize one journal read/derive/append decision across processes.

    The row-allocation lock in ``PostgreSQLJournalLines.append_line`` is too late
    to protect the HMAC chain: the event sequence and previous hash are derived
    before that append call. This outer, distinct advisory lock covers the whole
    base journal mutation while leaving database reads/appends on their owned
    short-lived connections.
    """

    with thread_lock:
        connection = connect()
        locked = False
        try:
            _execute(connection, "SELECT pg_advisory_lock(%s)", (lock_key,))
            locked = True
            connection.commit()
            yield
        finally:
            if locked:
                try:
                    _execute(connection, "SELECT pg_advisory_unlock(%s)", (lock_key,))
                    connection.commit()
                except Exception:
                    _safe_rollback(connection)
            _safe_close(connection)


def _decode_role_permissions(value: Any) -> frozenset[str]:
    """Normalize PostgreSQL JSON/JSONB role permissions and enforce RBAC invariants."""

    if isinstance(value, (str, bytes, bytearray)):
        try:
            value = json.loads(value)
        except (UnicodeError, json.JSONDecodeError, TypeError) as error:
            raise IdentityInvariantError(
                "persisted role permissions are invalid"
            ) from error
    if not isinstance(value, list):
        raise IdentityInvariantError("persisted role permissions are invalid")
    try:
        permissions = frozenset(_validate_permission(item) for item in value)
    except (TypeError, ValueError) as error:
        raise IdentityInvariantError(
            "persisted role permissions are invalid"
        ) from error
    if not permissions:
        raise IdentityInvariantError("persisted role permissions are empty")
    return permissions


class PostgreSQLAuditLog(AuditLog):
    """Audit hash chain persisted in PostgreSQL instead of JSONL files."""

    def __init__(self, connect: ConnectionFactory, *, integrity_key: bytes) -> None:
        if len(integrity_key) < 32:
            raise ValueError("audit integrity key must contain at least 32 bytes")
        self._connect = connect
        self._lines = PostgreSQLJournalLines(connect, JOURNAL_AUDIT)
        self._integrity_key = integrity_key
        self._thread_lock = threading.RLock()
        # File path unused; satisfy type checkers for base helpers if any.
        self.path = None  # type: ignore[assignment]

    def _read_and_verify(self) -> list[AuditEvent]:
        events: list[AuditEvent] = []
        previous_hash = AUDIT_GENESIS
        try:
            for line_number, line in enumerate(self._lines.read_lines(), start=1):
                if not line.endswith("\n"):
                    raise AuditIntegrityError(f"audit line {line_number} is incomplete")
                event = AuditEvent.model_validate(json.loads(line))
                if event.sequence != line_number:
                    raise AuditIntegrityError(f"invalid audit sequence at line {line_number}")
                if event.previous_hash != previous_hash:
                    raise AuditIntegrityError(f"broken audit chain at line {line_number}")
                body = audit_event_body(event)
                expected = self._sign(body)
                if not hmac.compare_digest(event.event_hash, expected):
                    raise AuditIntegrityError(f"invalid audit signature at line {line_number}")
                previous_hash = event.event_hash
                events.append(event)
        except AuditIntegrityError:
            raise
        except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
            raise AuditIntegrityError("audit journal cannot be verified") from error
        return events

    def _append_line(self, value: Mapping[str, Any]) -> None:
        payload = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        )
        self._lines.append_line(payload)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with _journal_chain_lock(
            self._connect,
            _AUDIT_LOCK_KEY,
            self._thread_lock,
        ):
            yield

    def adopt_legacy_file_if_empty(self, path: Path) -> None:
        """Copy a verified JSONL audit chain into an empty PostgreSQL journal."""

        _adopt_legacy_file_if_empty(
            path,
            integrity_key=self._integrity_key,
            file_journal_cls=AuditLog,
            lines=self._lines,
            exclusive_lock=self._exclusive_lock,
            integrity_error_cls=AuditIntegrityError,
            journal_label="audit",
        )


class PostgreSQLOperationJournal(OperationJournal):
    """Operation journal hash chain persisted in PostgreSQL."""

    def __init__(self, connect: ConnectionFactory, *, integrity_key: bytes) -> None:
        if len(integrity_key) < 32:
            raise ValueError("operation journal integrity key must contain at least 32 bytes")
        self._connect = connect
        self._lines = PostgreSQLJournalLines(connect, JOURNAL_OPERATIONS)
        self._integrity_key = integrity_key
        self._thread_lock = threading.RLock()
        self.path = None  # type: ignore[assignment]

    def _read_and_verify(
        self,
    ) -> tuple[list[OperationEvent], dict[str, OperationState]]:
        events: list[OperationEvent] = []
        states: dict[str, OperationState] = {}
        previous_hash = OPERATION_GENESIS
        try:
            for line_number, line in enumerate(self._lines.read_lines(), start=1):
                if not line.endswith("\n"):
                    raise OperationJournalIntegrityError(
                        f"operation journal line {line_number} is incomplete"
                    )
                event = OperationEvent.model_validate(json.loads(line))
                if event.sequence != line_number:
                    raise OperationJournalIntegrityError(
                        f"invalid operation sequence at line {line_number}"
                    )
                if event.previous_hash != previous_hash:
                    raise OperationJournalIntegrityError(
                        f"broken operation chain at line {line_number}"
                    )
                if not hmac.compare_digest(
                    event.event_hash,
                    self._sign(operation_event_body(event)),
                ):
                    raise OperationJournalIntegrityError(
                        f"invalid operation signature at line {line_number}"
                    )
                states[event.operation_id] = _apply_event(
                    states.get(event.operation_id), event
                )
                previous_hash = event.event_hash
                events.append(event)
        except OperationJournalIntegrityError:
            raise
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise OperationJournalIntegrityError(
                "operation journal cannot be verified"
            ) from error
        return events, states

    def _append_line(self, value: Mapping[str, Any]) -> None:
        payload = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        )
        self._lines.append_line(payload)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with _journal_chain_lock(
            self._connect,
            _OPERATION_LOCK_KEY,
            self._thread_lock,
        ):
            yield

    def adopt_legacy_file_if_empty(self, path: Path) -> None:
        """Copy a verified JSONL operation chain into an empty PostgreSQL journal."""

        _adopt_legacy_file_if_empty(
            path,
            integrity_key=self._integrity_key,
            file_journal_cls=OperationJournal,
            lines=self._lines,
            exclusive_lock=self._exclusive_lock,
            integrity_error_cls=OperationJournalIntegrityError,
            journal_label="operation",
        )


def _jsonl_snapshot(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    if not text:
        return []
    return [
        line if line.endswith("\n") else f"{line}\n"
        for line in text.splitlines(keepends=True)
    ]


def _adopt_legacy_file_if_empty(
    path: Path,
    *,
    integrity_key: bytes,
    file_journal_cls: type[AuditLog] | type[OperationJournal],
    lines: PostgreSQLJournalLines,
    exclusive_lock,
    integrity_error_cls: type[Exception],
    journal_label: str,
) -> None:
    if not path.exists():
        return
    try:
        expected = file_journal_cls(path, integrity_key=integrity_key).verify()
    except Exception as error:
        if isinstance(error, integrity_error_cls):
            raise
        raise integrity_error_cls(
            f"legacy {journal_label} journal cannot be verified"
        ) from None
    if expected.event_count == 0:
        return
    try:
        payload = _jsonl_snapshot(path)
    except Exception:
        raise integrity_error_cls(
            f"legacy {journal_label} journal cannot be verified"
        ) from None
    if len(payload) != expected.event_count:
        raise integrity_error_cls(
            f"legacy {journal_label} journal changed during cutover"
        )
    with exclusive_lock():
        try:
            imported = lines.import_lines_if_empty(payload)
        except Exception as error:
            if isinstance(error, integrity_error_cls):
                raise
            raise integrity_error_cls(
                f"legacy {journal_label} journal cannot be imported"
            ) from None
        if not imported:
            return


class PostgreSQLIdentityStore:
    """Transactional PostgreSQL identity store with the same invariants as JSON."""

    def __init__(
        self,
        connect: ConnectionFactory,
        *,
        password_hasher: PasswordHasher | None = None,
    ) -> None:
        self.connect = connect
        self.password_hasher = password_hasher or PasswordHasher()
        self._dummy_password_hash = self.password_hasher.hash(
            "plaik-constant-time-dummy-password"
        )
        # Write methods use ``self._connection`` as the active transaction
        # connection. Keep that mutable slot process-local and serialized; the
        # PostgreSQL advisory lock remains the cross-process writer lock.
        self._thread_lock = threading.RLock()

    def roles(self) -> dict[str, RoleRecord]:
        with self._transaction(_IDENTITY_LOCK_KEY):
            return self._load_roles()

    def users(self) -> dict[str, UserRecord]:
        with self._transaction(_IDENTITY_LOCK_KEY):
            return self._load_users(self._load_roles())

    def get_user(self, user_id: str) -> UserRecord | None:
        """Read one identity by primary key without taking the global writer lock."""

        return self._read_user("id", user_id)

    def has_active_super_admin(self) -> bool:
        return bool(self._active_super_admins(self.users()))

    def define_role(self, role_id: str, permissions: Iterable[str]) -> RoleRecord:
        role_id = _validate_role_id(role_id)
        if role_id == SUPER_ADMIN_ROLE:
            raise IdentityInvariantError("the super-admin role is protected")
        normalized = frozenset(_validate_permission(item) for item in permissions)
        if not normalized:
            raise ValueError("a role must contain at least one permission")
        with self._transaction(_IDENTITY_LOCK_KEY):
            roles = self._load_roles()
            role = RoleRecord(id=role_id, permissions=normalized)
            roles[role_id] = role
            self._persist_role(role)
            return role

    def create_first_super_admin(
        self,
        email: str,
        password: str,
        *,
        now: datetime | None = None,
    ) -> UserRecord:
        with self._transaction(_IDENTITY_LOCK_KEY):
            users = self._load_users(self._load_roles())
            if users:
                raise IdentityInvariantError("the first super administrator already exists")
            user = self._new_user(
                email,
                password,
                roles=frozenset({SUPER_ADMIN_ROLE}),
                now=now,
            )
            self._insert_user(user)
            return user

    def create_user(
        self,
        email: str,
        password: str,
        *,
        roles: Iterable[str] = (),
        now: datetime | None = None,
    ) -> UserRecord:
        normalized_roles = frozenset(_validate_role_id(role) for role in roles)
        normalized_email = _normalize_email(email)
        with self._transaction(_IDENTITY_LOCK_KEY):
            known_roles = self._load_roles()
            users = self._load_users(known_roles)
            if not self._active_super_admins(users):
                raise IdentityInvariantError(
                    "create the first super administrator before other users"
                )
            missing = normalized_roles.difference(known_roles)
            if missing:
                raise ValueError(f"unknown roles: {sorted(missing)}")
            if any(user.email == normalized_email for user in users.values()):
                raise IdentityInvariantError("an identity with this email already exists")
            user = self._new_user(normalized_email, password, roles=normalized_roles, now=now)
            self._insert_user(user)
            return user

    def set_roles(self, user_id: str, roles: Iterable[str]) -> UserRecord:
        normalized = frozenset(_validate_role_id(role) for role in roles)
        with self._transaction(_IDENTITY_LOCK_KEY):
            known_roles = self._load_roles()
            users = self._load_users(known_roles)
            user = _require_user(users, user_id)
            missing = normalized.difference(known_roles)
            if missing:
                raise ValueError(f"unknown roles: {sorted(missing)}")
            updated = user.model_copy(update={"roles": normalized})
            users[user_id] = updated
            self._require_active_super_admin(users)
            roles_table = _qualified(CORE_SCHEMA, "plaik_user_roles")
            _execute(
                self._connection,
                f"DELETE FROM {roles_table} WHERE user_id = %s",
                (user_id,),
            )
            for role_id in sorted(normalized):
                _execute(
                    self._connection,
                    f"""
                    INSERT INTO {roles_table} (user_id, role_id)
                    VALUES (%s, %s)
                    """,
                    (user_id, role_id),
                )
            return updated

    def set_active(self, user_id: str, active: bool) -> UserRecord:
        with self._transaction(_IDENTITY_LOCK_KEY):
            known_roles = self._load_roles()
            users = self._load_users(known_roles)
            user = _require_user(users, user_id)
            updated = user.model_copy(update={"active": bool(active)})
            users[user_id] = updated
            self._require_active_super_admin(users)
            users_table = _qualified(CORE_SCHEMA, "plaik_users")
            _execute(
                self._connection,
                f"UPDATE {users_table} SET active = %s WHERE id = %s",
                (updated.active, user_id),
            )
            return updated

    def authenticate(self, email: str, password: str) -> UserRecord:
        normalized_email = _normalize_email(email)
        user = self._read_user("email", normalized_email)
        candidate_hash = (
            user.password_hash
            if user is not None and user.active
            else self._dummy_password_hash
        )
        verified = self.password_hasher.verify(password, candidate_hash)
        if user is None or not user.active or not verified:
            raise AuthenticationError("invalid credentials")
        return user

    def permissions_for(self, user_id: str) -> frozenset[str]:
        users_table = _qualified(CORE_SCHEMA, "plaik_users")
        user_roles_table = _qualified(CORE_SCHEMA, "plaik_user_roles")
        roles_table = _qualified(CORE_SCHEMA, "plaik_roles")
        connection = self.connect()
        try:
            rows = _fetchall(
                connection,
                f"""
                SELECT u.active, r.id, r.permissions, r.protected
                FROM {users_table} AS u
                LEFT JOIN {user_roles_table} AS ur ON ur.user_id = u.id
                LEFT JOIN {roles_table} AS r ON r.id = ur.role_id
                WHERE u.id = %s
                ORDER BY r.id
                """,
                (user_id,),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            _safe_close(connection)
        if not rows:
            raise IdentityError(f"unknown user: {user_id}")
        active = bool(rows[0][0])
        if any(bool(row[0]) != active for row in rows[1:]):
            raise IdentityInvariantError("identity permission rows disagree on active state")
        if not active:
            return frozenset()
        permissions: set[str] = set()
        for _active, role_id, raw_permissions, protected in rows:
            if role_id is None:
                continue
            try:
                normalized_role = _validate_role_id(role_id)
            except (TypeError, ValueError) as error:
                raise IdentityInvariantError("persisted role id is invalid") from error
            role_permissions = _decode_role_permissions(raw_permissions)
            if normalized_role == SUPER_ADMIN_ROLE and (
                not bool(protected)
                or role_permissions != frozenset({SUPER_ADMIN_PERMISSION})
            ):
                raise IdentityInvariantError("the persisted super-admin role is invalid")
            permissions.update(role_permissions)
        return frozenset(permissions)

    def has_permission(self, user_id: str, permission: str) -> bool:
        permission = _validate_permission(permission)
        granted = self.permissions_for(user_id)
        if SUPER_ADMIN_PERMISSION in granted or permission in granted:
            return True
        parts = permission.split(".")
        return any(".".join(parts[:index]) + ".*" in granted for index in range(1, len(parts)))

    def require_permission(self, user_id: str, permission: str) -> None:
        if not self.has_permission(user_id, permission):
            raise AuthorizationError(f"permission denied: {permission}")

    def _new_user(
        self,
        email: str,
        password: str,
        *,
        roles: frozenset[str],
        now: datetime | None,
    ) -> UserRecord:
        return UserRecord(
            id=str(uuid4()),
            email=_normalize_email(email),
            password_hash=self.password_hasher.hash(password),
            roles=roles,
            created_at=_as_utc(now or datetime.now(UTC)),
        )

    def _read_user(self, lookup_column: str, value: str) -> UserRecord | None:
        if lookup_column not in {"id", "email"}:
            raise ValueError("unsupported identity lookup column")
        users_table = _qualified(CORE_SCHEMA, "plaik_users")
        user_roles_table = _qualified(CORE_SCHEMA, "plaik_user_roles")
        predicate = "u.id" if lookup_column == "id" else "lower(u.email)"
        connection = self.connect()
        try:
            rows = _fetchall(
                connection,
                f"""
                SELECT u.id, u.email, u.password_hash, u.active, u.created_at, ur.role_id
                FROM {users_table} AS u
                LEFT JOIN {user_roles_table} AS ur ON ur.user_id = u.id
                WHERE {predicate} = %s
                ORDER BY ur.role_id
                """,
                (value,),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            _safe_close(connection)
        if not rows:
            return None
        first = rows[0]
        if any(tuple(row[:5]) != tuple(first[:5]) for row in rows[1:]):
            raise IdentityInvariantError("identity lookup returned inconsistent user rows")
        try:
            roles = frozenset(
                _validate_role_id(row[5]) for row in rows if row[5] is not None
            )
        except (TypeError, ValueError) as error:
            raise IdentityInvariantError("persisted user role id is invalid") from error
        return UserRecord(
            id=first[0],
            email=first[1],
            password_hash=first[2],
            active=bool(first[3]),
            roles=roles,
            created_at=_as_utc(first[4]),
        )

    def _insert_user(self, user: UserRecord) -> None:
        users_table = _qualified(CORE_SCHEMA, "plaik_users")
        roles_table = _qualified(CORE_SCHEMA, "plaik_user_roles")
        _execute(
            self._connection,
            f"""
            INSERT INTO {users_table}
                (id, email, password_hash, active, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                user.id,
                user.email,
                user.password_hash,
                user.active,
                user.created_at,
            ),
        )
        for role_id in sorted(user.roles):
            _execute(
                self._connection,
                f"""
                INSERT INTO {roles_table} (user_id, role_id)
                VALUES (%s, %s)
                """,
                (user.id, role_id),
            )

    def _persist_role(self, role: RoleRecord) -> None:
        table = _qualified(CORE_SCHEMA, "plaik_roles")
        _execute(
            self._connection,
            f"""
            INSERT INTO {table} (id, permissions, protected)
            VALUES (%s, %s::jsonb, %s)
            ON CONFLICT (id) DO UPDATE
            SET permissions = EXCLUDED.permissions,
                protected = EXCLUDED.protected
            """,
            (
                role.id,
                json.dumps(sorted(role.permissions)),
                role.protected,
            ),
        )

    def _load_roles(self) -> dict[str, RoleRecord]:
        table = _qualified(CORE_SCHEMA, "plaik_roles")
        rows = _fetchall(
            self._connection,
            f"SELECT id, permissions, protected FROM {table}",
        )
        roles = {
            row[0]: RoleRecord(
                id=row[0],
                permissions=_decode_role_permissions(row[1]),
                protected=bool(row[2]),
            )
            for row in rows
        }
        roles.setdefault(
            SUPER_ADMIN_ROLE,
            RoleRecord(
                id=SUPER_ADMIN_ROLE,
                permissions=frozenset({SUPER_ADMIN_PERMISSION}),
                protected=True,
            ),
        )
        super_role = roles[SUPER_ADMIN_ROLE]
        if super_role.permissions != frozenset({SUPER_ADMIN_PERMISSION}) or not super_role.protected:
            raise IdentityInvariantError("the persisted super-admin role is invalid")
        return roles

    def _load_users(self, roles: dict[str, RoleRecord]) -> dict[str, UserRecord]:
        users_table = _qualified(CORE_SCHEMA, "plaik_users")
        roles_table = _qualified(CORE_SCHEMA, "plaik_user_roles")
        user_rows = _fetchall(
            self._connection,
            f"""
            SELECT id, email, password_hash, active, created_at
            FROM {users_table}
            """,
        )
        role_rows = _fetchall(
            self._connection,
            f"SELECT user_id, role_id FROM {roles_table}",
        )
        role_map: dict[str, set[str]] = {}
        for user_id, role_id in role_rows:
            role_map.setdefault(user_id, set()).add(role_id)
        users = {
            row[0]: UserRecord(
                id=row[0],
                email=row[1],
                password_hash=row[2],
                active=bool(row[3]),
                roles=frozenset(role_map.get(row[0], set())),
                created_at=_as_utc(row[4]),
            )
            for row in user_rows
        }
        if users:
            if not self._active_super_admins(users):
                raise IdentityInvariantError("at least one active super administrator is required")
        return users

    @staticmethod
    def _active_super_admins(users: dict[str, UserRecord]) -> list[UserRecord]:
        return [
            user
            for user in users.values()
            if user.active and SUPER_ADMIN_ROLE in user.roles
        ]

    @classmethod
    def _require_active_super_admin(cls, users: dict[str, UserRecord]) -> None:
        if not cls._active_super_admins(users):
            raise IdentityInvariantError("at least one active super administrator is required")

    _connection: Any

    @contextmanager
    def _transaction(self, lock_key: int) -> Iterator[None]:
        with self._thread_lock:
            connection = self.connect()
            self._connection = connection
            try:
                _execute(connection, "SELECT pg_advisory_lock(%s)", (lock_key,))
                yield
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                try:
                    _execute(connection, "SELECT pg_advisory_unlock(%s)", (lock_key,))
                    connection.commit()
                except Exception:
                    connection.rollback()
                _safe_close(connection)


class PostgreSQLSessionStore:
    """Session digests stored in PostgreSQL; API matches JSON SessionStore."""

    def __init__(
        self,
        connect: ConnectionFactory,
        *,
        token_pepper: bytes,
        identity_store: PostgreSQLIdentityStore | None = None,
        default_ttl: timedelta = timedelta(hours=8),
        maximum_ttl: timedelta = timedelta(days=30),
        cleanup_batch_size: int = 256,
    ) -> None:
        if len(token_pepper) < 32:
            raise ValueError("session token pepper must contain at least 32 bytes")
        if default_ttl <= timedelta(0) or default_ttl > maximum_ttl:
            raise ValueError("invalid default session lifetime")
        self.connect = connect
        self._token_pepper = token_pepper
        self.identity_store = identity_store
        self.default_ttl = default_ttl
        self.maximum_ttl = maximum_ttl
        self.cleanup_batch_size = _validate_cleanup_batch_size(cleanup_batch_size)

    def create(
        self,
        user_id: str,
        *,
        now: datetime | None = None,
        ttl: timedelta | None = None,
    ) -> SessionToken:
        import secrets

        from pydantic import SecretStr

        self._require_active_user(user_id)
        issued_at = _as_utc(now or datetime.now(UTC))
        lifetime = ttl or self.default_ttl
        if lifetime <= timedelta(0) or lifetime > self.maximum_ttl:
            raise ValueError("invalid session lifetime")
        session_id = str(uuid4())
        secret = secrets.token_urlsafe(32)
        value = f"{session_id}.{secret}"
        table = _qualified(CORE_SCHEMA, "plaik_sessions")
        connection = self.connect()
        try:
            _execute(connection, "SELECT pg_advisory_lock(%s)", (_SESSION_LOCK_KEY,))
            self._purge_terminal_on_connection(
                connection,
                checked_at=issued_at,
                limit=self.cleanup_batch_size,
            )
            _execute(
                connection,
                f"""
                INSERT INTO {table}
                    (id, user_id, token_digest, issued_at, expires_at, revoked_at)
                VALUES (%s, %s, %s, %s, %s, NULL)
                """,
                (
                    session_id,
                    user_id,
                    self._digest(value),
                    issued_at,
                    issued_at + lifetime,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            try:
                _execute(connection, "SELECT pg_advisory_unlock(%s)", (_SESSION_LOCK_KEY,))
                connection.commit()
            except Exception:
                connection.rollback()
            _safe_close(connection)
        return SessionToken(
            session_id=session_id,
            value=SecretStr(value),
            expires_at=issued_at + lifetime,
        )

    def validate(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> SessionRecord:
        checked_at = _as_utc(now or datetime.now(UTC))
        raw_token, session_id = _parse_session_token(token)

        table = _qualified(CORE_SCHEMA, "plaik_sessions")
        connection = self.connect()
        try:
            row = _fetchone(
                connection,
                f"""
                SELECT id, user_id, token_digest, issued_at, expires_at, revoked_at
                FROM {table}
                WHERE id = %s
                """,
                (session_id,),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            _safe_close(connection)

        if row is None:
            raise SessionError("invalid session")
        record = SessionRecord(
            id=row[0],
            user_id=row[1],
            token_digest=row[2],
            issued_at=_as_utc(row[3]),
            expires_at=_as_utc(row[4]),
            revoked_at=_as_utc(row[5]) if row[5] is not None else None,
        )
        if record.revoked_at is not None or checked_at >= record.expires_at:
            raise SessionError("invalid session")
        if not hmac.compare_digest(record.token_digest, self._digest(raw_token)):
            raise SessionError("invalid session")
        self._require_active_user(record.user_id)
        return record

    def revoke(self, session_id: str, *, now: datetime | None = None) -> SessionRecord:
        table = _qualified(CORE_SCHEMA, "plaik_sessions")
        connection = self.connect()
        try:
            _execute(connection, "SELECT pg_advisory_lock(%s)", (_SESSION_LOCK_KEY,))
            row = _fetchone(
                connection,
                f"""
                SELECT id, user_id, token_digest, issued_at, expires_at, revoked_at
                FROM {table}
                WHERE id = %s
                """,
                (session_id,),
            )
            if row is None:
                raise SessionError("session does not exist")
            revoked_at = row[5] or _as_utc(now or datetime.now(UTC))
            if row[5] is None:
                _execute(
                    connection,
                    f"UPDATE {table} SET revoked_at = %s WHERE id = %s",
                    (revoked_at, session_id),
                )
            connection.commit()
            return SessionRecord(
                id=row[0],
                user_id=row[1],
                token_digest=row[2],
                issued_at=_as_utc(row[3]),
                expires_at=_as_utc(row[4]),
                revoked_at=_as_utc(revoked_at) if revoked_at else None,
            )
        except SessionError:
            connection.rollback()
            raise
        except Exception:
            connection.rollback()
            raise
        finally:
            try:
                _execute(connection, "SELECT pg_advisory_unlock(%s)", (_SESSION_LOCK_KEY,))
                connection.commit()
            except Exception:
                connection.rollback()
            _safe_close(connection)

    def revoke_user(self, user_id: str, *, now: datetime | None = None) -> int:
        revoked_at = _as_utc(now or datetime.now(UTC))
        table = _qualified(CORE_SCHEMA, "plaik_sessions")
        connection = self.connect()
        try:
            _execute(connection, "SELECT pg_advisory_lock(%s)", (_SESSION_LOCK_KEY,))
            rows = _fetchall(
                connection,
                f"""
                UPDATE {table}
                SET revoked_at = %s
                WHERE user_id = %s AND revoked_at IS NULL
                RETURNING id
                """,
                (revoked_at, user_id),
            )
            connection.commit()
            return len(rows)
        except Exception:
            connection.rollback()
            raise
        finally:
            try:
                _execute(connection, "SELECT pg_advisory_unlock(%s)", (_SESSION_LOCK_KEY,))
                connection.commit()
            except Exception:
                connection.rollback()
            _safe_close(connection)

    def purge_terminal(
        self,
        *,
        now: datetime | None = None,
        limit: int | None = None,
    ) -> int:
        """Delete one bounded batch of expired or revoked session records."""

        checked_at = _as_utc(now or datetime.now(UTC))
        cleanup_limit = _validate_cleanup_batch_size(
            self.cleanup_batch_size if limit is None else limit
        )
        connection = self.connect()
        try:
            _execute(connection, "SELECT pg_advisory_lock(%s)", (_SESSION_LOCK_KEY,))
            removed = self._purge_terminal_on_connection(
                connection,
                checked_at=checked_at,
                limit=cleanup_limit,
            )
            connection.commit()
            return removed
        except Exception:
            connection.rollback()
            raise
        finally:
            try:
                _execute(connection, "SELECT pg_advisory_unlock(%s)", (_SESSION_LOCK_KEY,))
                connection.commit()
            except Exception:
                connection.rollback()
            _safe_close(connection)

    def records(self) -> dict[str, SessionRecord]:
        table = _qualified(CORE_SCHEMA, "plaik_sessions")
        connection = self.connect()
        try:
            rows = _fetchall(
                connection,
                f"""
                SELECT id, user_id, token_digest, issued_at, expires_at, revoked_at
                FROM {table}
                """,
            )
            connection.commit()
            return {
                row[0]: SessionRecord(
                    id=row[0],
                    user_id=row[1],
                    token_digest=row[2],
                    issued_at=_as_utc(row[3]),
                    expires_at=_as_utc(row[4]),
                    revoked_at=_as_utc(row[5]) if row[5] is not None else None,
                )
                for row in rows
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            _safe_close(connection)

    @staticmethod
    def _purge_terminal_on_connection(
        connection: Any,
        *,
        checked_at: datetime,
        limit: int,
    ) -> int:
        table = _qualified(CORE_SCHEMA, "plaik_sessions")
        rows = _fetchall(
            connection,
            f"""
            WITH terminal AS (
                (
                    SELECT id, expires_at AS terminal_at
                    FROM {table}
                    WHERE revoked_at IS NULL AND expires_at <= %s
                    ORDER BY expires_at, id
                    LIMIT %s
                )
                UNION ALL
                (
                    SELECT id, revoked_at AS terminal_at
                    FROM {table}
                    WHERE revoked_at IS NOT NULL
                    ORDER BY revoked_at, id
                    LIMIT %s
                )
            ),
            candidates AS (
                SELECT id
                FROM terminal
                ORDER BY terminal_at, id
                LIMIT %s
            )
            DELETE FROM {table} AS sessions
            USING candidates
            WHERE sessions.id = candidates.id
            RETURNING sessions.id
            """,
            (checked_at, limit, limit, limit),
        )
        return len(rows)

    def _digest(self, token: str) -> str:
        return hmac.new(self._token_pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def _require_active_user(self, user_id: str) -> None:
        if self.identity_store is None:
            return
        user = self.identity_store.get_user(user_id)
        if user is None or not user.active:
            raise SessionError("session owner is not an active identity")


class DelegatingStore:
    """Resolve the active backend on each attribute access."""

    def __init__(self, resolver: Callable[[], Any]) -> None:
        self._resolver = resolver

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resolver(), name)


def postgresql_security_enabled(configuration) -> bool:
    from .installer_config import PostgreSQLDatabase

    return isinstance(getattr(configuration, "database", None), PostgreSQLDatabase)
