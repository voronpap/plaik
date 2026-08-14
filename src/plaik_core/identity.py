"""Identity primitives for bootstrap authentication, sessions, and RBAC.

The JSON-backed stores are deliberately small, single-node foundations.  Their
interfaces keep credential handling and invariants out of HTTP code so a
transactional database implementation can replace them without changing the
security contract.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, SecretStr

from .storage import exclusive_file_lock, read_json, write_json_atomic


SUPER_ADMIN_ROLE = "super_admin"
SUPER_ADMIN_PERMISSION = "*"

_ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_PERMISSION_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}(?:\.\*)?$")
_SESSION_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_SESSION_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_MAX_SESSION_TOKEN_CHARS = 36 + 1 + 128
_MAX_SESSION_CLEANUP_BATCH = 10_000


class IdentityError(RuntimeError):
    """Base error for identity operations."""


class AuthenticationError(IdentityError):
    """Credentials are invalid without disclosing which check failed."""


class AuthorizationError(IdentityError):
    """An active user does not hold a required permission."""


class IdentityInvariantError(IdentityError):
    """An operation would violate a persistent identity invariant."""


class SessionError(IdentityError):
    """A session is malformed, expired, revoked, or otherwise invalid."""


class PasswordHasher:
    """Versioned stdlib-only password hashing based on ``hashlib.scrypt``."""

    algorithm = "scrypt"
    format_version = 1

    def __init__(
        self,
        *,
        n: int = 2**14,
        r: int = 8,
        p: int = 1,
        salt_bytes: int = 16,
        derived_key_bytes: int = 32,
        minimum_length: int = 12,
        maximum_bytes: int = 1024,
    ) -> None:
        if n < 2**14 or n & (n - 1):
            raise ValueError("scrypt n must be a power of two and at least 16384")
        if r < 1 or p < 1 or salt_bytes < 16 or derived_key_bytes < 32:
            raise ValueError("unsafe scrypt parameters")
        self.n = n
        self.r = r
        self.p = p
        self.salt_bytes = salt_bytes
        self.derived_key_bytes = derived_key_bytes
        self.minimum_length = minimum_length
        self.maximum_bytes = maximum_bytes

    def hash(self, password: str) -> str:
        encoded = self._encode_new_password(password)
        salt = secrets.token_bytes(self.salt_bytes)
        digest = hashlib.scrypt(
            encoded,
            salt=salt,
            n=self.n,
            r=self.r,
            p=self.p,
            dklen=self.derived_key_bytes,
        )
        return "$".join(
            (
                self.algorithm,
                str(self.format_version),
                str(self.n),
                str(self.r),
                str(self.p),
                _b64encode(salt),
                _b64encode(digest),
            )
        )

    def verify(self, password: str, encoded_hash: str) -> bool:
        try:
            encoded = password.encode("utf-8")
            if not encoded or len(encoded) > self.maximum_bytes:
                return False
            algorithm, version, n, r, p, salt, expected = encoded_hash.split("$")
            if algorithm != self.algorithm or int(version) != self.format_version:
                return False
            parsed_n, parsed_r, parsed_p = int(n), int(r), int(p)
            if parsed_n < 2**14 or parsed_n > 2**20 or parsed_n & (parsed_n - 1):
                return False
            if not 1 <= parsed_r <= 32 or not 1 <= parsed_p <= 16:
                return False
            salt_bytes = _b64decode(salt)
            expected_bytes = _b64decode(expected)
            if len(salt_bytes) < 16 or not 32 <= len(expected_bytes) <= 128:
                return False
            actual = hashlib.scrypt(
                encoded,
                salt=salt_bytes,
                n=parsed_n,
                r=parsed_r,
                p=parsed_p,
                dklen=len(expected_bytes),
            )
            return hmac.compare_digest(actual, expected_bytes)
        except (TypeError, ValueError, UnicodeError):
            return False

    def needs_rehash(self, encoded_hash: str) -> bool:
        try:
            algorithm, version, n, r, p, _salt, digest = encoded_hash.split("$")
            return (
                algorithm != self.algorithm
                or int(version) != self.format_version
                or int(n) != self.n
                or int(r) != self.r
                or int(p) != self.p
                or len(_b64decode(digest)) != self.derived_key_bytes
            )
        except (TypeError, ValueError):
            return True

    def _encode_new_password(self, password: str) -> bytes:
        if not isinstance(password, str):
            raise TypeError("password must be text")
        if len(password) < self.minimum_length:
            raise ValueError(f"password must contain at least {self.minimum_length} characters")
        encoded = password.encode("utf-8")
        if len(encoded) > self.maximum_bytes:
            raise ValueError(f"password must not exceed {self.maximum_bytes} UTF-8 bytes")
        return encoded


class RoleRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    permissions: frozenset[str]
    protected: bool = False


class UserRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    email: str
    password_hash: str
    roles: frozenset[str]
    active: bool = True
    created_at: datetime


class IdentityStore:
    """Atomic bootstrap identity store with last-super-admin protection."""

    def __init__(self, path: Path, *, password_hasher: PasswordHasher | None = None) -> None:
        self.path = path
        self.password_hasher = password_hasher or PasswordHasher()
        self._dummy_password_hash = self.password_hasher.hash(
            "plaik-constant-time-dummy-password"
        )

    def roles(self) -> dict[str, RoleRecord]:
        roles, _users = self._read()
        return roles

    def users(self) -> dict[str, UserRecord]:
        _roles, users = self._read()
        return users

    def get_user(self, user_id: str) -> UserRecord | None:
        """Return one identity without requiring callers to enumerate the store."""

        _roles, users = self._read()
        return users.get(user_id)

    def has_active_super_admin(self) -> bool:
        return bool(self._active_super_admins(self.users()))

    def define_role(self, role_id: str, permissions: Iterable[str]) -> RoleRecord:
        role_id = _validate_role_id(role_id)
        if role_id == SUPER_ADMIN_ROLE:
            raise IdentityInvariantError("the super-admin role is protected")
        normalized_permissions = frozenset(_validate_permission(item) for item in permissions)
        if not normalized_permissions:
            raise ValueError("a role must contain at least one permission")
        with exclusive_file_lock(self.path):
            roles, users = self._read()
            role = RoleRecord(id=role_id, permissions=normalized_permissions)
            roles[role_id] = role
            self._write(roles, users)
            return role

    def create_first_super_admin(
        self,
        email: str,
        password: str,
        *,
        now: datetime | None = None,
    ) -> UserRecord:
        with exclusive_file_lock(self.path):
            roles, users = self._read()
            if users:
                raise IdentityInvariantError("the first super administrator already exists")
            user = self._new_user(
                email,
                password,
                roles=frozenset({SUPER_ADMIN_ROLE}),
                now=now,
            )
            users[user.id] = user
            self._write(roles, users)
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
        with exclusive_file_lock(self.path):
            known_roles, users = self._read()
            if not self._active_super_admins(users):
                raise IdentityInvariantError(
                    "create the first super administrator before other users"
                )
            missing = normalized_roles.difference(known_roles)
            if missing:
                raise ValueError(f"unknown roles: {sorted(missing)}")
            if any(user.email == normalized_email for user in users.values()):
                raise IdentityInvariantError("an identity with this email already exists")
            user = self._new_user(
                normalized_email,
                password,
                roles=normalized_roles,
                now=now,
            )
            users[user.id] = user
            self._write(known_roles, users)
            return user

    def set_roles(self, user_id: str, roles: Iterable[str]) -> UserRecord:
        normalized = frozenset(_validate_role_id(role) for role in roles)
        with exclusive_file_lock(self.path):
            known_roles, users = self._read()
            user = _require_user(users, user_id)
            missing = normalized.difference(known_roles)
            if missing:
                raise ValueError(f"unknown roles: {sorted(missing)}")
            updated = user.model_copy(update={"roles": normalized})
            users[user_id] = updated
            self._require_active_super_admin(users)
            self._write(known_roles, users)
            return updated

    def set_active(self, user_id: str, active: bool) -> UserRecord:
        with exclusive_file_lock(self.path):
            roles, users = self._read()
            user = _require_user(users, user_id)
            updated = user.model_copy(update={"active": bool(active)})
            users[user_id] = updated
            self._require_active_super_admin(users)
            self._write(roles, users)
            return updated

    def authenticate(self, email: str, password: str) -> UserRecord:
        normalized_email = _normalize_email(email)
        roles, users = self._read()
        del roles
        user = next((item for item in users.values() if item.email == normalized_email), None)
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
        roles, users = self._read()
        user = _require_user(users, user_id)
        if not user.active:
            return frozenset()
        permissions: set[str] = set()
        for role_id in user.roles:
            role = roles.get(role_id)
            if role is None:
                raise IdentityInvariantError(f"user references unknown role: {role_id}")
            permissions.update(role.permissions)
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

    def _read(self) -> tuple[dict[str, RoleRecord], dict[str, UserRecord]]:
        data = read_json(self.path, {"roles": {}, "users": {}})
        roles = {
            role_id: RoleRecord.model_validate(value)
            for role_id, value in data.get("roles", {}).items()
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
        if not super_role.protected or super_role.permissions != frozenset({SUPER_ADMIN_PERMISSION}):
            raise IdentityInvariantError("the persisted super-admin role is invalid")
        users = {
            user_id: UserRecord.model_validate(value)
            for user_id, value in data.get("users", {}).items()
        }
        if users:
            self._require_active_super_admin(users)
        return roles, users

    def _write(self, roles: dict[str, RoleRecord], users: dict[str, UserRecord]) -> None:
        if users:
            self._require_active_super_admin(users)
        write_json_atomic(
            self.path,
            {
                "roles": {
                    role_id: role.model_dump(mode="json")
                    for role_id, role in sorted(roles.items())
                },
                "users": {
                    user_id: user.model_dump(mode="json")
                    for user_id, user in sorted(users.items())
                },
            },
        )

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


class SessionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    user_id: str
    token_digest: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None


class SessionToken(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str
    value: SecretStr
    expires_at: datetime


class SessionStore:
    """Opaque, revocable sessions; only keyed token digests are persisted."""

    def __init__(
        self,
        path: Path,
        *,
        token_pepper: bytes,
        identity_store: IdentityStore | None = None,
        default_ttl: timedelta = timedelta(hours=8),
        maximum_ttl: timedelta = timedelta(days=30),
        cleanup_batch_size: int = 256,
    ) -> None:
        if len(token_pepper) < 32:
            raise ValueError("session token pepper must contain at least 32 bytes")
        if default_ttl <= timedelta(0) or default_ttl > maximum_ttl:
            raise ValueError("invalid default session lifetime")
        self.path = path
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
        self._require_active_user(user_id)
        issued_at = _as_utc(now or datetime.now(UTC))
        lifetime = ttl or self.default_ttl
        if lifetime <= timedelta(0) or lifetime > self.maximum_ttl:
            raise ValueError("invalid session lifetime")
        session_id = str(uuid4())
        secret = secrets.token_urlsafe(32)
        value = f"{session_id}.{secret}"
        record = SessionRecord(
            id=session_id,
            user_id=user_id,
            token_digest=self._digest(value),
            issued_at=issued_at,
            expires_at=issued_at + lifetime,
        )
        with exclusive_file_lock(self.path):
            records = self.records()
            self._purge_records(
                records,
                checked_at=issued_at,
                limit=self.cleanup_batch_size,
            )
            records[session_id] = record
            self._write(records)
        return SessionToken(
            session_id=session_id,
            value=SecretStr(value),
            expires_at=record.expires_at,
        )

    def validate(
        self,
        token: str | SecretStr,
        *,
        now: datetime | None = None,
    ) -> SessionRecord:
        checked_at = _as_utc(now or datetime.now(UTC))
        raw_token, session_id = _parse_session_token(token)
        record = self.records().get(session_id)
        if record is None or record.revoked_at is not None or checked_at >= record.expires_at:
            raise SessionError("invalid session")
        if not hmac.compare_digest(record.token_digest, self._digest(raw_token)):
            raise SessionError("invalid session")
        self._require_active_user(record.user_id)
        return record

    def revoke(self, session_id: str, *, now: datetime | None = None) -> SessionRecord:
        with exclusive_file_lock(self.path):
            records = self.records()
            try:
                record = records[session_id]
            except KeyError as error:
                raise SessionError("session does not exist") from error
            if record.revoked_at is None:
                record = record.model_copy(
                    update={"revoked_at": _as_utc(now or datetime.now(UTC))}
                )
                records[session_id] = record
                self._write(records)
            return record

    def revoke_user(self, user_id: str, *, now: datetime | None = None) -> int:
        revoked_at = _as_utc(now or datetime.now(UTC))
        with exclusive_file_lock(self.path):
            records = self.records()
            changed = 0
            for session_id, record in tuple(records.items()):
                if record.user_id == user_id and record.revoked_at is None:
                    records[session_id] = record.model_copy(
                        update={"revoked_at": revoked_at}
                    )
                    changed += 1
            if changed:
                self._write(records)
            return changed

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
        with exclusive_file_lock(self.path):
            records = self.records()
            removed = self._purge_records(
                records,
                checked_at=checked_at,
                limit=cleanup_limit,
            )
            if removed:
                self._write(records)
            return removed

    def records(self) -> dict[str, SessionRecord]:
        data = read_json(self.path, {"sessions": {}})
        return {
            session_id: SessionRecord.model_validate(value)
            for session_id, value in data.get("sessions", {}).items()
        }

    @staticmethod
    def _purge_records(
        records: dict[str, SessionRecord],
        *,
        checked_at: datetime,
        limit: int,
    ) -> int:
        terminal: list[tuple[datetime, str]] = []
        for session_id, record in records.items():
            if record.revoked_at is not None:
                terminal_at = _as_utc(record.revoked_at)
            elif _as_utc(record.expires_at) <= checked_at:
                terminal_at = _as_utc(record.expires_at)
            else:
                continue
            terminal.append((terminal_at, session_id))
        terminal.sort(key=lambda item: (item[0], item[1]))
        selected = terminal[:limit]
        for _terminal_at, session_id in selected:
            del records[session_id]
        return len(selected)

    def _digest(self, token: str) -> str:
        return hmac.new(self._token_pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def _require_active_user(self, user_id: str) -> None:
        if self.identity_store is None:
            return
        user = self.identity_store.get_user(user_id)
        if user is None or not user.active:
            raise SessionError("invalid session identity")

    def _write(self, records: dict[str, SessionRecord]) -> None:
        write_json_atomic(
            self.path,
            {
                "sessions": {
                    session_id: record.model_dump(mode="json")
                    for session_id, record in sorted(records.items())
                }
            },
        )


def _validate_cleanup_batch_size(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("session cleanup batch size must be an integer")
    if not 1 <= value <= _MAX_SESSION_CLEANUP_BATCH:
        raise ValueError(
            f"session cleanup batch size must be between 1 and {_MAX_SESSION_CLEANUP_BATCH}"
        )
    return value


def _parse_session_token(token: str | SecretStr) -> tuple[str, str]:
    raw_token = token.get_secret_value() if isinstance(token, SecretStr) else token
    if (
        not isinstance(raw_token, str)
        or not raw_token.isascii()
        or len(raw_token) > _MAX_SESSION_TOKEN_CHARS
    ):
        raise SessionError("invalid session")
    try:
        session_id, secret = raw_token.split(".", 1)
    except ValueError:
        raise SessionError("invalid session") from None
    if (
        not _SESSION_ID_PATTERN.fullmatch(session_id)
        or not _SESSION_SECRET_PATTERN.fullmatch(secret)
    ):
        raise SessionError("invalid session")
    return raw_token, session_id


def _normalize_email(email: str) -> str:
    if not isinstance(email, str):
        raise TypeError("email must be text")
    normalized = email.strip().casefold()
    if len(normalized) > 254 or normalized.count("@") != 1:
        raise ValueError("invalid email address")
    local, domain = normalized.split("@")
    if not local or not domain or "." not in domain:
        raise ValueError("invalid email address")
    return normalized


def _validate_role_id(role_id: str) -> str:
    if not isinstance(role_id, str) or not _ROLE_PATTERN.fullmatch(role_id):
        raise ValueError("invalid role id")
    return role_id


def _validate_permission(permission: str) -> str:
    if permission == SUPER_ADMIN_PERMISSION:
        return permission
    if not isinstance(permission, str) or not _PERMISSION_PATTERN.fullmatch(permission):
        raise ValueError("invalid permission")
    return permission


def _require_user(users: dict[str, UserRecord], user_id: str) -> UserRecord:
    try:
        return users[user_id]
    except KeyError as error:
        raise IdentityError(f"unknown user: {user_id}") from error


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(UTC)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)
