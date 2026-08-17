"""Composable HTTP authentication, CSRF, RBAC and audit integration.

The adapter is intentionally independent from the Core application factory. A
composition root creates :class:`HttpAuth`, includes ``router``, and uses the
dependency callables on its own routes. The JSON identity/session stores and
in-memory limiter are reference adapters, not the production deployment claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from inspect import signature
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
)

from .audit import AuditEvent, AuditLog, AuditOutcome
from .identity import (
    AuthenticationError,
    AuthorizationError,
    IdentityError,
    IdentityStore,
    SessionError,
    SessionRecord,
    SessionStore,
    SessionToken,
    UserRecord,
)

_COOKIE_NAME = re.compile(r"^__Host-[A-Za-z0-9_-]{1,64}$")
_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,63}$")
_PERMISSION = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}(?:\.\*)?$|^\*$")
_BOOTSTRAP_NONCE = re.compile(r"^[A-Za-z0-9_-]{40,64}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def request_host_is_loopback(request: Request) -> bool:
    raw = (request.headers.get("host") or "").strip().casefold()
    if raw.startswith("["):
        end = raw.find("]")
        host = raw[1:end] if end > 1 else ""
    else:
        host = raw.split(":", 1)[0]
    return host in _LOOPBACK_HOSTS


def request_is_wan_control(request: Request, control_hostname: str | None) -> bool:
    """True when the request is not loopback and Remote Control is advertised."""

    if not control_hostname:
        return False
    return not request_host_is_loopback(request)


class PublicIdentity(BaseModel):
    """The only identity representation returned by the HTTP adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    email: str
    roles: tuple[str, ...]


class LoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    user: PublicIdentity


class CsrfResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    csrf_token: str


class _LoginCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    email: str = Field(min_length=3, max_length=254)
    password: SecretStr = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email_shape(cls, value: str) -> str:
        normalized = value.strip().casefold()
        if len(normalized) > 254 or normalized.count("@") != 1:
            raise ValueError("invalid email address")
        local, domain = normalized.split("@")
        if not local or not domain or "." not in domain:
            raise ValueError("invalid email address")
        return value

    @field_validator("password")
    @classmethod
    def validate_password_bytes(cls, value: SecretStr) -> SecretStr:
        try:
            size = len(value.get_secret_value().encode("utf-8"))
        except UnicodeEncodeError:
            raise ValueError("invalid password encoding") from None
        if size > 1024:
            raise ValueError("password exceeds the accepted byte length")
        return value


class HttpAuthPolicy(BaseModel):
    """Fixed-safe cookie policy plus bounded reference-adapter limits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    route_prefix: str = Field(
        default="/api/auth",
        pattern=r"^/[A-Za-z0-9/_-]*[A-Za-z0-9_-]$",
    )
    session_cookie_name: str = Field(
        default="__Host-plaik-session",
        pattern=_COOKIE_NAME.pattern,
    )
    control_session_cookie_name: str = Field(
        default="__Host-plaik_control_session",
        pattern=_COOKIE_NAME.pattern,
    )
    csrf_cookie_name: str = Field(
        default="__Host-plaik-csrf",
        pattern=_COOKIE_NAME.pattern,
    )
    csrf_header_name: str = Field(
        default="X-CSRF-Token",
        pattern=_HEADER_NAME.pattern,
    )
    cookie_path: Literal["/"] = "/"
    cookie_secure: Literal[True] = True
    cookie_same_site: Literal["strict"] = "strict"
    bootstrap_csrf_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    login_body_limit_bytes: int = Field(
        default=16 * 1024,
        ge=1024,
        le=1024 * 1024,
    )
    denial_audit_interval_seconds: float = Field(default=60.0, ge=1.0, le=3600.0)
    denial_audit_maximum_clients: int = Field(default=4096, ge=1, le=65536)


class AuthenticatedPrincipal(BaseModel):
    """An active identity bound to one currently valid opaque session."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: str
    email: str
    roles: tuple[str, ...]
    session_id: str
    session_expires_at: datetime
    token: SecretStr = Field(exclude=True, repr=False)

    def __repr__(self) -> str:
        return (
            "AuthenticatedPrincipal("
            f"user_id={self.user_id!r}, session_id={self.session_id!r})"
        )


class RateLimitExceeded(RuntimeError):
    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__("login rate limit exceeded")


@dataclass(slots=True)
class _FailureWindow:
    failures: deque[float] = field(default_factory=deque)
    blocked_until: float = 0.0


class LoginRateLimiter:
    """Bounded, peer-address limiter for the single-process reference adapter.

    A successful authentication never erases fresh failures for the same peer.
    Otherwise an attacker controlling one valid account could alternate a valid
    login with guesses for another account and continuously reset the peer
    throttle. Failure history expires only through the configured time window.
    """

    def __init__(
        self,
        *,
        maximum_failures: int = 5,
        window_seconds: float = 60.0,
        block_seconds: float = 300.0,
        maximum_clients: int = 4096,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if maximum_failures < 1:
            raise ValueError("maximum_failures must be positive")
        if window_seconds <= 0 or block_seconds <= 0:
            raise ValueError("rate-limit durations must be positive")
        if maximum_clients < 1:
            raise ValueError("maximum_clients must be positive")
        self.maximum_failures = maximum_failures
        self.window_seconds = float(window_seconds)
        self.block_seconds = float(block_seconds)
        self.maximum_clients = maximum_clients
        self._clock = clock
        self._entries: OrderedDict[str, _FailureWindow] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def entry_count(self) -> int:
        with self._lock:
            return len(self._entries)

    @staticmethod
    def key_for(request: Request) -> str:
        """Hash the direct ASGI peer; forwarded headers are not trusted here."""

        peer = request.client.host if request.client is not None else "unknown-peer"
        return hashlib.sha256(peer.encode("utf-8", errors="replace")).hexdigest()

    def check(self, key: str) -> None:
        key = self._normalized_key(key)
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return
            self._prune(entry, now)
            if entry.blocked_until > now:
                self._entries.move_to_end(key)
                raise RateLimitExceeded(math.ceil(entry.blocked_until - now))
            entry.blocked_until = 0.0
            if not entry.failures:
                self._entries.pop(key, None)

    def record_failure(self, key: str) -> None:
        key = self._normalized_key(key)
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                while len(self._entries) >= self.maximum_clients:
                    self._entries.popitem(last=False)
                entry = _FailureWindow(
                    failures=deque(maxlen=self.maximum_failures)
                )
                self._entries[key] = entry
            self._prune(entry, now)
            entry.failures.append(now)
            if len(entry.failures) >= self.maximum_failures:
                entry.blocked_until = max(entry.blocked_until, now + self.block_seconds)
            self._entries.move_to_end(key)

    def record_success(self, key: str) -> None:
        """Prune stale peer state without forgiving fresh failed attempts."""

        key = self._normalized_key(key)
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return
            self._prune(entry, now)
            if entry.blocked_until <= now:
                entry.blocked_until = 0.0
            if not entry.failures and entry.blocked_until == 0.0:
                self._entries.pop(key, None)
            else:
                self._entries.move_to_end(key)

    def _prune(self, entry: _FailureWindow, now: float) -> None:
        threshold = now - self.window_seconds
        while entry.failures and entry.failures[0] <= threshold:
            entry.failures.popleft()

    @staticmethod
    def _normalized_key(key: str) -> str:
        if not isinstance(key, str):
            raise TypeError("rate-limit key must be text")
        return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()


class _DenialAuditSampler:
    """Bound repeated unauthenticated denial audits by direct ASGI peer."""

    def __init__(
        self,
        *,
        interval_seconds: float,
        maximum_clients: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.interval_seconds = float(interval_seconds)
        self.maximum_clients = maximum_clients
        self._clock = clock
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def should_audit(self, request: Request) -> bool:
        key = LoginRateLimiter.key_for(request)
        now = self._clock()
        with self._lock:
            previous = self._entries.get(key)
            if previous is not None and now - previous < self.interval_seconds:
                self._entries.move_to_end(key)
                return False
            while len(self._entries) >= self.maximum_clients:
                self._entries.popitem(last=False)
            self._entries[key] = now
            self._entries.move_to_end(key)
            return True


def _normalize_audit_checkpoint(
    callback: Callable[[AuditEvent], None] | Callable[[], None] | None,
) -> Callable[[AuditEvent], None] | None:
    if callback is None:
        return None
    try:
        callback_signature = signature(callback)
    except (TypeError, ValueError):
        return callback  # type: ignore[return-value]
    try:
        callback_signature.bind(None)
    except TypeError as event_error:
        try:
            callback_signature.bind()
        except TypeError:
            raise ValueError(
                "audit checkpoint callback must accept zero or one positional event"
            ) from event_error
        return lambda _event: callback()  # type: ignore[call-arg]
    return callback  # type: ignore[return-value]


class HttpAuth:
    """Includable FastAPI router and dependency provider for Core identity."""

    def __init__(
        self,
        identity_store: IdentityStore,
        session_store: SessionStore,
        audit_log: AuditLog,
        *,
        csrf_key: bytes,
        policy: HttpAuthPolicy | None = None,
        rate_limiter: LoginRateLimiter | None = None,
        audit_checkpoint: Callable[[AuditEvent], None] | Callable[[], None] | None = None,
        wan_control_hostname: Callable[[], str | None] | None = None,
    ) -> None:
        if not isinstance(csrf_key, (bytes, bytearray)) or len(csrf_key) < 32:
            raise ValueError("CSRF integrity key must contain at least 32 bytes")
        if (
            session_store.identity_store is not None
            and session_store.identity_store is not identity_store
        ):
            raise ValueError("session and HTTP authentication identity stores differ")
        self.identity_store = identity_store
        self.session_store = session_store
        self.audit_log = audit_log
        self.policy = policy or HttpAuthPolicy()
        if self.policy.session_cookie_name == self.policy.csrf_cookie_name:
            raise ValueError("session and CSRF cookie names must differ")
        if self.policy.control_session_cookie_name in {
            self.policy.session_cookie_name,
            self.policy.csrf_cookie_name,
        }:
            raise ValueError("control session cookie name must be distinct")
        self._wan_control_hostname = wan_control_hostname
        self.rate_limiter = (
            rate_limiter if rate_limiter is not None else LoginRateLimiter()
        )
        self._denial_audit_sampler = _DenialAuditSampler(
            interval_seconds=self.policy.denial_audit_interval_seconds,
            maximum_clients=self.policy.denial_audit_maximum_clients,
        )
        self.audit_checkpoint = _normalize_audit_checkpoint(audit_checkpoint)
        self._csrf_key = bytes(csrf_key)
        self.router = self._build_router()

    def __repr__(self) -> str:
        return f"HttpAuth(route_prefix={self.policy.route_prefix!r})"

    def _raw_session_token(self, request: Request) -> str | None:
        control = request.cookies.get(self.policy.control_session_cookie_name)
        loopback = request.cookies.get(self.policy.session_cookie_name)
        advertised = (
            self._wan_control_hostname() if self._wan_control_hostname is not None else None
        )
        if advertised and not request_host_is_loopback(request):
            return control
        return loopback or control

    def authenticate(self, request: Request) -> AuthenticatedPrincipal:
        """FastAPI dependency: require a valid session and an active identity."""

        raw_token = self._raw_session_token(request)
        if not raw_token:
            self._deny_authentication(request)
        try:
            session = self.session_store.validate(raw_token)
            user = self.identity_store.get_user(session.user_id)
        except SessionError:
            self._deny_authentication(request)
        except (IdentityError, OSError, ValueError, TypeError):
            raise self._service_unavailable() from None
        if user is None or not user.active:
            self._deny_authentication(request)
        return self._principal(user, session, SecretStr(raw_token))

    def verify_csrf(self, request: Request) -> AuthenticatedPrincipal:
        """FastAPI dependency: authenticate and verify session-bound CSRF."""

        principal = self.authenticate(request)
        expected = self._session_csrf(principal.token.get_secret_value())
        supplied_cookie = request.cookies.get(self.policy.csrf_cookie_name, "")
        supplied_header = request.headers.get(self.policy.csrf_header_name, "")
        if not self._matching_csrf(supplied_cookie, supplied_header, expected):
            self._audit(
                actor_id=principal.user_id,
                action="identity.access.denied",
                target_type="security.csrf",
                outcome=AuditOutcome.DENIED,
                metadata={"reason": "csrf_failed"},
            )
            raise HTTPException(
                status_code=403,
                detail="request denied",
                headers={"Cache-Control": "no-store"},
            )
        return principal

    def require_permission(
        self,
        permission: str,
        *,
        csrf: bool = False,
    ) -> Callable[[Request], AuthenticatedPrincipal]:
        """Return an authentication/RBAC dependency for a composition route."""

        if not isinstance(permission, str) or not _PERMISSION.fullmatch(permission):
            raise ValueError("invalid HTTP permission dependency")

        def dependency(request: Request) -> AuthenticatedPrincipal:
            principal = self.verify_csrf(request) if csrf else self.authenticate(request)
            try:
                self.identity_store.require_permission(principal.user_id, permission)
            except AuthorizationError:
                self._audit(
                    actor_id=principal.user_id,
                    action="identity.access.denied",
                    target_type="identity.permission",
                    target_id=permission,
                    outcome=AuditOutcome.DENIED,
                    metadata={"reason": "permission_denied"},
                )
                raise HTTPException(
                    status_code=403,
                    detail="permission denied",
                    headers={"Cache-Control": "no-store"},
                ) from None
            except (IdentityError, OSError, ValueError, TypeError):
                raise self._service_unavailable() from None
            return principal

        safe_name = re.sub(r"[^A-Za-z0-9_]", "_", permission)
        dependency.__name__ = f"require_{safe_name}"
        return dependency

    def require_mutation(
        self, permission: str
    ) -> Callable[[Request], AuthenticatedPrincipal]:
        """Return a combined session, CSRF and permission dependency."""

        return self.require_permission(permission, csrf=True)

    def rotate_session(
        self,
        principal: AuthenticatedPrincipal,
        response: Response,
    ) -> AuthenticatedPrincipal:
        """Revoke a current session and issue a replacement after privilege change."""

        try:
            self.session_store.revoke(principal.session_id)
            issued = self.session_store.create(principal.user_id)
        except (SessionError, OSError, ValueError, TypeError):
            raise self._service_unavailable() from None
        try:
            self._audit(
                actor_id=principal.user_id,
                action="identity.session.rotate",
                target_type="identity.session",
                target_id=issued.session_id,
                metadata={"previous_session_id": principal.session_id},
            )
        except HTTPException:
            self._revoke_after_failed_issue(issued)
            raise
        try:
            session = self.session_store.validate(issued.value)
            user = self.identity_store.get_user(session.user_id)
            if user is None or not user.active:
                raise SessionError("invalid session identity")
            rotated = self._principal(user, session, issued.value)
        except (SessionError, OSError, ValueError, TypeError):
            self._revoke_after_failed_issue(issued)
            raise self._service_unavailable() from None
        self._set_authenticated_cookies(response, issued)
        return rotated

    def _build_router(self) -> APIRouter:
        router = APIRouter(prefix=self.policy.route_prefix, tags=["identity"])

        @router.get("/csrf", response_model=CsrfResponse)
        def issue_csrf(request: Request, response: Response) -> CsrfResponse:
            principal = self._optional_principal(request)
            if principal is None:
                token = self._bootstrap_csrf()
                max_age = self.policy.bootstrap_csrf_ttl_seconds
            else:
                token = self._session_csrf(principal.token.get_secret_value())
                max_age = self._session_max_age(principal.session_expires_at)
            self._set_csrf_cookie(response, token, max_age=max_age)
            self._set_no_store(response)
            return CsrfResponse(csrf_token=token)

        @router.post("/login", response_model=LoginResponse)
        async def login(request: Request, response: Response) -> LoginResponse:
            return await self._login(request, response)

        @router.post("/logout", status_code=204)
        def logout(request: Request) -> Response:
            principal = self.verify_csrf(request)
            try:
                self.session_store.revoke(principal.session_id)
            except (SessionError, OSError, ValueError, TypeError):
                raise self._service_unavailable() from None
            self._audit(
                actor_id=principal.user_id,
                action="identity.logout",
                target_type="identity.session",
                target_id=principal.session_id,
            )
            result = Response(status_code=204)
            self._clear_cookies(result)
            self._set_no_store(result)
            return result

        @router.get("/me", response_model=PublicIdentity)
        def me(request: Request, response: Response) -> PublicIdentity:
            principal = self.authenticate(request)
            self._set_no_store(response)
            return PublicIdentity(
                id=principal.user_id,
                email=principal.email,
                roles=principal.roles,
            )

        return router

    async def _login(self, request: Request, response: Response) -> LoginResponse:
        if self._wan_control_hostname is not None and request_is_wan_control(
            request, self._wan_control_hostname()
        ):
            raise HTTPException(
                status_code=404,
                detail="not found",
                headers={"Cache-Control": "no-store"},
            )
        client_key = self.rate_limiter.key_for(request)
        try:
            self.rate_limiter.check(client_key)
        except RateLimitExceeded as error:
            self._audit_login_denial(request, "rate_limited", AuditOutcome.DENIED)
            raise HTTPException(
                status_code=429,
                detail="authentication temporarily unavailable",
                headers={
                    "Cache-Control": "no-store",
                    "Retry-After": str(error.retry_after_seconds),
                },
            ) from None

        if not self._valid_login_csrf(request):
            self.rate_limiter.record_failure(client_key)
            self._audit_login_denial(request, "csrf_failed", AuditOutcome.DENIED)
            raise HTTPException(
                status_code=403,
                detail="request denied",
                headers={"Cache-Control": "no-store"},
            )

        try:
            credentials = await self._read_login_credentials(request)
        except HTTPException:
            self.rate_limiter.record_failure(client_key)
            self._audit_login_denial(request, "invalid_request", AuditOutcome.FAILURE)
            raise

        password = credentials.password.get_secret_value()
        try:
            user = self.identity_store.authenticate(credentials.email, password)
        except AuthenticationError:
            self.rate_limiter.record_failure(client_key)
            self._audit_login_denial(
                request,
                "invalid_credentials",
                AuditOutcome.FAILURE,
            )
            raise HTTPException(
                status_code=401,
                detail="invalid credentials",
                headers={
                    "Cache-Control": "no-store",
                    "WWW-Authenticate": "Session",
                },
            ) from None
        except (IdentityError, OSError, TypeError, ValueError):
            raise self._service_unavailable() from None

        previous = self._optional_principal(request)
        try:
            if previous is not None:
                self.session_store.revoke(previous.session_id)
            issued = self.session_store.create(user.id)
        except (SessionError, OSError, ValueError, TypeError):
            self._audit_login_denial(
                request,
                "session_unavailable",
                AuditOutcome.FAILURE,
            )
            raise self._service_unavailable() from None

        try:
            self._audit(
                actor_id=user.id,
                action="identity.login",
                target_type="identity.session",
                target_id=issued.session_id,
                metadata={"rotated_existing_session": previous is not None},
            )
        except HTTPException:
            self._revoke_after_failed_issue(issued)
            raise

        self.rate_limiter.record_success(client_key)
        self._set_authenticated_cookies(response, issued)
        self._set_no_store(response)
        return LoginResponse(user=self._public_identity(user))

    async def _read_login_credentials(self, request: Request) -> _LoginCredentials:
        body = bytearray()
        try:
            async for chunk in request.stream():
                if len(body) + len(chunk) > self.policy.login_body_limit_bytes:
                    raise ValueError
                body.extend(chunk)
            payload: Any = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError
            return _LoginCredentials.model_validate(payload)
        except (
            UnicodeError,
            json.JSONDecodeError,
            ValidationError,
            ValueError,
            TypeError,
        ):
            raise HTTPException(
                status_code=422,
                detail="invalid login request",
                headers={"Cache-Control": "no-store"},
            ) from None

    def _optional_principal(self, request: Request) -> AuthenticatedPrincipal | None:
        raw_token = self._raw_session_token(request)
        if not raw_token:
            return None
        try:
            session = self.session_store.validate(raw_token)
            user = self.identity_store.get_user(session.user_id)
        except SessionError:
            return None
        except (IdentityError, OSError, ValueError, TypeError):
            raise self._service_unavailable() from None
        if user is None or not user.active:
            return None
        return self._principal(user, session, SecretStr(raw_token))

    def _valid_login_csrf(self, request: Request) -> bool:
        supplied_cookie = request.cookies.get(self.policy.csrf_cookie_name, "")
        supplied_header = request.headers.get(self.policy.csrf_header_name, "")
        if not supplied_cookie or not supplied_header:
            return False
        if (
            len(supplied_cookie) > 256
            or len(supplied_header) > 256
            or not supplied_cookie.isascii()
            or not supplied_header.isascii()
        ):
            return False
        if not hmac.compare_digest(supplied_cookie, supplied_header):
            return False
        if self._valid_bootstrap_csrf(supplied_cookie):
            return True
        principal = self._optional_principal(request)
        if principal is None:
            return False
        expected = self._session_csrf(principal.token.get_secret_value())
        return self._matching_csrf(supplied_cookie, supplied_header, expected)

    def _bootstrap_csrf(self) -> str:
        nonce = secrets.token_urlsafe(32)
        issued_at = str(int(time.time()))
        signature = self._sign_csrf(f"bootstrap\0{nonce}\0{issued_at}")
        return f"{nonce}.{issued_at}.{signature}"

    def _valid_bootstrap_csrf(self, token: str) -> bool:
        try:
            nonce, issued_at_raw, signature = token.split(".", 2)
            issued_at = int(issued_at_raw)
        except (AttributeError, TypeError, ValueError):
            return False
        if not _BOOTSTRAP_NONCE.fullmatch(nonce) or not _HEX_DIGEST.fullmatch(
            signature
        ):
            return False
        age = int(time.time()) - issued_at
        if age < -30 or age > self.policy.bootstrap_csrf_ttl_seconds:
            return False
        expected = self._sign_csrf(f"bootstrap\0{nonce}\0{issued_at_raw}")
        return hmac.compare_digest(signature, expected)

    def _session_csrf(self, raw_session_token: str) -> str:
        return self._sign_csrf(f"session\0{raw_session_token}")

    def _sign_csrf(self, material: str) -> str:
        return hmac.new(
            self._csrf_key,
            material.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _matching_csrf(cookie: str, header: str, expected: str) -> bool:
        return bool(
            _HEX_DIGEST.fullmatch(cookie)
            and _HEX_DIGEST.fullmatch(header)
            and hmac.compare_digest(cookie, header)
            and hmac.compare_digest(header, expected)
        )

    def _deny_authentication(self, request: Request) -> None:
        if self._denial_audit_sampler.should_audit(request):
            self._audit(
                actor_id=None,
                action="identity.access.denied",
                target_type="identity.session",
                outcome=AuditOutcome.DENIED,
                metadata={"reason": "authentication_required"},
            )
        raise HTTPException(
            status_code=401,
            detail="authentication required",
            headers={
                "Cache-Control": "no-store",
                "WWW-Authenticate": "Session",
            },
        )

    def _audit_login_denial(
        self,
        request: Request,
        reason: str,
        outcome: AuditOutcome,
    ) -> None:
        if self._denial_audit_sampler.should_audit(request):
            self._audit(
                actor_id=None,
                action="identity.login",
                target_type="identity.session",
                outcome=outcome,
                metadata={"reason": reason},
            )

    def _audit(
        self,
        *,
        actor_id: str | None,
        action: str,
        target_type: str,
        target_id: str | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        try:
            event = self.audit_log.append(
                actor_id=actor_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                outcome=outcome,
                metadata=metadata,
            )
            if self.audit_checkpoint is not None:
                self.audit_checkpoint(event)
        except Exception:
            raise self._service_unavailable() from None

    @staticmethod
    def _service_unavailable() -> HTTPException:
        return HTTPException(
            status_code=503,
            detail="identity security service unavailable",
            headers={"Cache-Control": "no-store"},
        )

    def _set_authenticated_cookies(
        self, response: Response, issued: SessionToken
    ) -> None:
        raw_token = issued.value.get_secret_value()
        max_age = self._session_max_age(issued.expires_at)
        response.set_cookie(
            key=self.policy.session_cookie_name,
            value=raw_token,
            max_age=max_age,
            path=self.policy.cookie_path,
            secure=self.policy.cookie_secure,
            httponly=True,
            samesite=self.policy.cookie_same_site,
        )
        self._set_csrf_cookie(
            response,
            self._session_csrf(raw_token),
            max_age=max_age,
        )

    def _set_csrf_cookie(self, response: Response, value: str, *, max_age: int) -> None:
        response.set_cookie(
            key=self.policy.csrf_cookie_name,
            value=value,
            max_age=max(1, max_age),
            path=self.policy.cookie_path,
            secure=self.policy.cookie_secure,
            httponly=False,
            samesite=self.policy.cookie_same_site,
        )

    def _clear_cookies(self, response: Response) -> None:
        response.delete_cookie(
            self.policy.session_cookie_name,
            path=self.policy.cookie_path,
            secure=self.policy.cookie_secure,
            httponly=True,
            samesite=self.policy.cookie_same_site,
        )
        response.delete_cookie(
            self.policy.control_session_cookie_name,
            path=self.policy.cookie_path,
            secure=self.policy.cookie_secure,
            httponly=True,
            samesite=self.policy.cookie_same_site,
        )
        response.delete_cookie(
            self.policy.csrf_cookie_name,
            path=self.policy.cookie_path,
            secure=self.policy.cookie_secure,
            httponly=False,
            samesite=self.policy.cookie_same_site,
        )

    @staticmethod
    def _set_no_store(response: Response) -> None:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

    @staticmethod
    def _session_max_age(expires_at: datetime) -> int:
        return max(1, math.ceil((expires_at - datetime.now(UTC)).total_seconds()))

    @staticmethod
    def _public_identity(user: UserRecord) -> PublicIdentity:
        return PublicIdentity(
            id=user.id,
            email=user.email,
            roles=tuple(sorted(user.roles)),
        )

    @staticmethod
    def _principal(
        user: UserRecord,
        session: SessionRecord,
        token: SecretStr,
    ) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=user.id,
            email=user.email,
            roles=tuple(sorted(user.roles)),
            session_id=session.id,
            session_expires_at=session.expires_at,
            token=token,
        )

    def _revoke_after_failed_issue(self, issued: SessionToken) -> None:
        try:
            self.session_store.revoke(issued.session_id)
        except Exception:
            # Cleanup must not replace the audit/storage failure that denied use.
            pass


__all__ = [
    "AuthenticatedPrincipal",
    "CsrfResponse",
    "HttpAuth",
    "HttpAuthPolicy",
    "LoginRateLimiter",
    "LoginResponse",
    "PublicIdentity",
    "RateLimitExceeded",
]
