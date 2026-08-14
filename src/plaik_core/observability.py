"""Safe structured telemetry and bounded diagnostic checks."""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict


_EVENT_NAME = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
_CORRELATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SENSITIVE_PARTS = {
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
}
_SENSITIVE_COMPACT_KEYS = {
    "accesstoken",
    "apikey",
    "clientsecret",
    "privatekey",
    "refreshtoken",
    "sessioncookie",
}
MAX_STRUCTURED_FIELDS_BYTES = 64 * 1024
MAX_STRUCTURED_FIELDS_DEPTH = 16
MAX_STRUCTURED_FIELDS_KEYS = 512
MAX_STRUCTURED_FIELDS_ITEMS = 4096
MAX_STRUCTURED_FIELD_KEY_BYTES = 128


class StructuredEventLogger:
    """Serialize bounded allowlisted event fields without secret material."""

    def __init__(self, sink: Callable[[str], None]) -> None:
        if not callable(sink):
            raise TypeError("structured log sink must be callable")
        self._sink = sink

    def emit(
        self,
        event: str,
        *,
        level: str = "info",
        correlation_id: str | None = None,
        fields: Mapping[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> str:
        if not _EVENT_NAME.fullmatch(event):
            raise ValueError("invalid structured event name")
        if level not in {"debug", "info", "warning", "error", "critical"}:
            raise ValueError("invalid structured log level")
        if correlation_id is not None and not _CORRELATION_ID.fullmatch(correlation_id):
            raise ValueError("invalid correlation id")
        safe_fields = _safe_fields(fields or {})
        timestamp = occurred_at or datetime.now(UTC)
        if timestamp.tzinfo is None:
            raise ValueError("structured log timestamp must be timezone-aware")
        record = {
            "occurred_at": timestamp.astimezone(UTC).isoformat(),
            "level": level,
            "event": event,
            "correlation_id": correlation_id,
            **safe_fields,
        }
        encoded = json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        self._sink(encoded)
        return encoded


class CorrelationMiddleware:
    """Pure ASGI middleware adding request IDs and safe completion telemetry."""

    def __init__(
        self,
        app,
        *,
        logger: StructuredEventLogger,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.app = app
        self.logger = logger
        self.clock = clock

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        supplied = _header(scope.get("headers", ()), b"x-request-id")
        correlation_id = (
            supplied if supplied is not None and _CORRELATION_ID.fullmatch(supplied) else uuid4().hex
        )
        state = scope.setdefault("state", {})
        state["correlation_id"] = correlation_id
        started = self.clock()
        status_code = 500

        async def send_with_correlation(message) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 500))
                headers = list(message.get("headers", ()))
                headers = [item for item in headers if item[0].lower() != b"x-request-id"]
                headers.append((b"x-request-id", correlation_id.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        outcome = "success"
        try:
            await self.app(scope, receive, send_with_correlation)
        except Exception:
            outcome = "error"
            raise
        finally:
            duration_ms = max(0.0, (self.clock() - started) * 1000)
            try:
                self.logger.emit(
                    "http.request.completed",
                    level="error" if outcome == "error" or status_code >= 500 else "info",
                    correlation_id=correlation_id,
                    fields={
                        "method": scope.get("method", ""),
                        "route": _safe_route_label(scope),
                        "status_code": status_code,
                        "duration_ms": round(duration_ms, 3),
                        "outcome": outcome,
                    },
                )
            except Exception:
                pass


class DiagnosticResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    passed: bool
    code: str
    duration_ms: float


DiagnosticCheck = Callable[[], tuple[bool, str]]


class _DiagnosticExecution:
    __slots__ = ("done", "result", "error_type")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: tuple[bool, str] | None = None
        self.error_type: str | None = None


class DiagnosticRegistry:
    def __init__(self) -> None:
        self._checks: dict[str, DiagnosticCheck] = {}
        self._executions: dict[str, _DiagnosticExecution] = {}
        self._lock = threading.RLock()

    def register(self, check_id: str, check: DiagnosticCheck) -> None:
        if not _EVENT_NAME.fullmatch(check_id):
            raise ValueError("invalid diagnostic check id")
        if not callable(check):
            raise TypeError("diagnostic check must be callable")
        with self._lock:
            if check_id in self._checks:
                raise ValueError("diagnostic check is already registered")
            self._checks[check_id] = check

    def run(self, *, timeout_seconds: float = 2.0) -> tuple[DiagnosticResult, ...]:
        if not 0.01 <= timeout_seconds <= 30:
            raise ValueError("diagnostic timeout must be between 0.01 and 30 seconds")
        with self._lock:
            checks = tuple(sorted(self._checks.items()))
        results: list[DiagnosticResult] = []
        for check_id, check in checks:
            started = time.perf_counter()
            execution = self._execution(check_id, check)
            if not execution.done.wait(timeout=timeout_seconds):
                passed, code = False, "diagnostic.timeout"
            else:
                try:
                    if execution.error_type is not None:
                        passed = False
                        code = f"diagnostic.{execution.error_type}"[:128]
                    else:
                        if execution.result is None:
                            raise ValueError("diagnostic produced no result")
                        passed, code = execution.result
                        if not _EVENT_NAME.fullmatch(code):
                            raise ValueError("diagnostic returned an invalid code")
                except Exception as error:
                    passed = False
                    code = f"diagnostic.{type(error).__name__.casefold()}"[:128]
            results.append(
                DiagnosticResult(
                    id=check_id,
                    passed=bool(passed),
                    code=code,
                    duration_ms=round(max(0.0, (time.perf_counter() - started) * 1000), 3),
                )
            )
        return tuple(results)

    def _execution(
        self,
        check_id: str,
        check: DiagnosticCheck,
    ) -> _DiagnosticExecution:
        with self._lock:
            existing = self._executions.get(check_id)
            if existing is not None and not existing.done.is_set():
                return existing
            execution = _DiagnosticExecution()
            self._executions[check_id] = execution

        def invoke() -> None:
            try:
                execution.result = check()
            except Exception as error:
                execution.error_type = type(error).__name__.casefold()
            finally:
                execution.done.set()

        threading.Thread(
            target=invoke,
            name=f"plaik-diagnostic-{check_id}",
            daemon=True,
        ).start()
        return execution


def _safe_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(fields, Mapping):
        raise TypeError("structured log fields must be an object")
    _validate_field_structure(fields)
    try:
        encoded = json.dumps(
            fields,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_STRUCTURED_FIELDS_BYTES:
            raise ValueError("structured log fields exceed the size limit")
        copied = json.loads(encoded)
    except ValueError as error:
        if str(error) == "structured log fields exceed the size limit":
            raise
        raise ValueError("structured log fields must be JSON-safe") from None
    except (OverflowError, RecursionError, TypeError, UnicodeError):
        raise ValueError("structured log fields must be JSON-safe") from None
    if not isinstance(copied, dict):
        raise TypeError("structured log fields must be an object")
    return copied


def _validate_field_structure(fields: Mapping[str, Any]) -> None:
    stack: list[tuple[Any, int]] = [(fields, 1)]
    seen_containers: set[int] = set()
    key_count = 0
    item_count = 0
    while stack:
        value, depth = stack.pop()
        item_count += 1
        if item_count > MAX_STRUCTURED_FIELDS_ITEMS:
            raise ValueError("structured log fields exceed the item limit")
        if depth > MAX_STRUCTURED_FIELDS_DEPTH:
            raise ValueError("structured log fields exceed the depth limit")
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in seen_containers:
                raise ValueError("structured log fields must be acyclic")
            seen_containers.add(identity)
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise ValueError("structured log field names must be strings")
                try:
                    key_size = len(key.encode("utf-8"))
                except UnicodeError:
                    raise ValueError("structured log field name is invalid") from None
                if (
                    not 1 <= key_size <= MAX_STRUCTURED_FIELD_KEY_BYTES
                    or any(ord(character) < 32 or ord(character) == 127 for character in key)
                ):
                    raise ValueError("structured log field name is invalid")
                key_count += 1
                if key_count > MAX_STRUCTURED_FIELDS_KEYS:
                    raise ValueError("structured log fields exceed the key limit")
                if _is_sensitive_field_key(key):
                    raise ValueError("structured log contains a sensitive field")
                stack.append((nested, depth + 1))
        elif isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in seen_containers:
                raise ValueError("structured log fields must be acyclic")
            seen_containers.add(identity)
            stack.extend((nested, depth + 1) for nested in value)


def _is_sensitive_field_key(key: str) -> bool:
    with_camel_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    ordered_parts = [
        part
        for part in re.split(r"[^A-Za-z0-9]+", with_camel_boundaries.casefold())
        if part
    ]
    parts = set(ordered_parts)
    compact = "".join(ordered_parts)
    return bool(parts & _SENSITIVE_PARTS) or compact in _SENSITIVE_COMPACT_KEYS


def _header(headers, name: bytes) -> str | None:
    values = [value for key, value in headers if key.lower() == name]
    if len(values) != 1:
        return None
    try:
        return values[0].decode("ascii")
    except UnicodeDecodeError:
        return None


def _safe_route_label(scope: Mapping[str, Any]) -> str:
    """Return a bounded route class without logging configured or raw paths."""

    route = scope.get("route")
    template = getattr(route, "path", None)
    if not isinstance(template, str):
        return "unmatched"
    if template == "/health":
        return "health"
    if template == "/":
        return "application.root"
    if template == "/api/core/status":
        return "core.status"
    if template.startswith("/api/auth/"):
        return "identity.api"
    if template == "/api/install" or template.startswith("/api/install/"):
        return "installer.api"
    if template == "/api/admin" or template.startswith("/api/admin/"):
        return "admin.api"
    if template.startswith("/themes/"):
        return "web.theme-asset"
    return "application.route"
