"""Remote Control Center intent, observed status and gateway protocol.

This module is the fail-closed contract for publishing Control Center through
an HTTPS gateway. It does not bind WAN listeners, issue certificates, talk to
nginx, or register WebAuthn credentials.

Runtime loopback invariants are part of the contract:

- Public Surface: 127.0.0.1:8080
- Control Center: 127.0.0.1:8081
- Installer: 127.0.0.1:8765

``remote_control_enabled`` is derived from observed status. ENABLED is
impossible without an enrolled admin passkey. ERROR never opens port 8081.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .installer import InstallState
from .storage import exclusive_file_lock, read_json, write_json_atomic


WEB_LOOPBACK = ("127.0.0.1", 8080)
CONTROL_LOOPBACK = ("127.0.0.1", 8081)
INSTALLER_LOOPBACK = ("127.0.0.1", 8765)
RUNTIME_LOOPBACK_ENDPOINTS = (WEB_LOOPBACK, CONTROL_LOOPBACK, INSTALLER_LOOPBACK)
FORBIDDEN_WAN_BIND_ADDRESSES = frozenset({"0.0.0.0", "::", "[::]"})
CONTROL_SESSION_COOKIE = "__Host-plaik_control_session"

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_INJECTION = re.compile(r"[^a-z0-9.-]")
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")


class RemoteControlError(RuntimeError):
    """Remote Control Center contract failed without opening WAN listeners."""


class InvalidRemoteControlTransition(RemoteControlError):
    """A requested status change violates the Remote Control state machine."""


class InvalidRemoteHostname(RemoteControlError, ValueError):
    """A hostname is not a safe public or control identity."""


class TlsMode(StrEnum):
    ACME = "acme"
    EXISTING_CERTIFICATE = "existing_certificate"
    DISABLED = "disabled"


class GatewayProviderName(StrEnum):
    NONE = "none"
    NGINX = "nginx"
    CADDY = "caddy"
    TRAEFIK = "traefik"
    EXTERNAL = "external"


class RemoteControlStatus(StrEnum):
    DISABLED = "disabled"
    PREFLIGHT = "preflight"
    ENROLLMENT_PENDING = "enrollment_pending"
    ENABLED = "enabled"
    ERROR = "error"


class WanSurface(StrEnum):
    CLOSED = "closed"
    ACTIVATE_ONLY = "activate_only"
    CONTROL_CENTER = "control_center"


def wan_surface_for(status: RemoteControlStatus) -> WanSurface:
    """Map observed status to the only WAN surface a gateway may expose."""

    if status is RemoteControlStatus.ENABLED:
        return WanSurface.CONTROL_CENTER
    if status is RemoteControlStatus.ENROLLMENT_PENDING:
        return WanSurface.ACTIVATE_ONLY
    return WanSurface.CLOSED


def remote_control_enabled(status: RemoteControlStatus) -> bool:
    """Derived flag. Not an independent stored boolean."""

    return status is RemoteControlStatus.ENABLED


def is_forbidden_wan_bind(host: str) -> bool:
    return host.strip().casefold() in {item.casefold() for item in FORBIDDEN_WAN_BIND_ADDRESSES}


def validate_dns_hostname(value: str, *, label: str) -> str:
    """Accept a DNS hostname, never an IP, URL, wildcard or injector string."""

    candidate = value.strip().rstrip(".").casefold()
    if not candidate:
        raise InvalidRemoteHostname(f"{label} is required")
    if _INJECTION.search(candidate):
        raise InvalidRemoteHostname(f"{label} contains forbidden characters")
    if candidate in {"localhost", "localhost.localdomain"}:
        raise InvalidRemoteHostname(f"{label} must not be a loopback name")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise InvalidRemoteHostname(f"{label} must not be an IP address")
    if candidate.endswith(".localhost") or candidate.endswith(".local"):
        raise InvalidRemoteHostname(f"{label} must not be a local resolver name")
    if not _HOSTNAME.fullmatch(candidate):
        raise InvalidRemoteHostname(f"{label} must be a DNS hostname")
    return candidate


class RemoteControlIntent(BaseModel):
    """Operator-requested Remote Control publication. Not observed readiness."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    public_hostname: str
    control_hostname: str
    tls_mode: TlsMode
    gateway_provider: GatewayProviderName
    remote_access_requested: bool = False

    @field_validator("public_hostname")
    @classmethod
    def validate_public_hostname(cls, value: str) -> str:
        return validate_dns_hostname(value, label="public_hostname")

    @field_validator("control_hostname")
    @classmethod
    def validate_control_hostname(cls, value: str) -> str:
        return validate_dns_hostname(value, label="control_hostname")

    @model_validator(mode="after")
    def validate_intent_contract(self) -> "RemoteControlIntent":
        if self.public_hostname == self.control_hostname:
            raise ValueError("control_hostname must differ from public_hostname")
        if not self.remote_access_requested:
            return self
        if self.tls_mode is TlsMode.DISABLED:
            raise ValueError("remote access cannot be requested without TLS")
        if self.gateway_provider is GatewayProviderName.NONE:
            raise ValueError("remote access requires an HTTPS gateway provider")
        return self


class GatewayPlan(BaseModel):
    """Provider-agnostic publication plan. Contains no nginx syntax."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    intent: RemoteControlIntent
    wan_surface: WanSurface
    web_bind_host: str = Field(default=WEB_LOOPBACK[0])
    web_bind_port: int = Field(default=WEB_LOOPBACK[1], ge=1, le=65535)
    control_bind_host: str = Field(default=CONTROL_LOOPBACK[0])
    control_bind_port: int = Field(default=CONTROL_LOOPBACK[1], ge=1, le=65535)

    @model_validator(mode="after")
    def validate_loopback_only_binds(self) -> "GatewayPlan":
        for host, port, expected in (
            (self.web_bind_host, self.web_bind_port, WEB_LOOPBACK),
            (self.control_bind_host, self.control_bind_port, CONTROL_LOOPBACK),
        ):
            if is_forbidden_wan_bind(host):
                raise ValueError("gateway plan cannot bind PLAIK to a WAN address")
            if (host, port) != expected:
                raise ValueError("gateway plan must target the loopback PLAIK endpoints")
        if (
            self.wan_surface is WanSurface.CONTROL_CENTER
            and not self.intent.remote_access_requested
        ):
            raise ValueError("control center WAN surface requires remote access intent")
        return self


class GatewayInspection(BaseModel):
    """Observed gateway facts. Never a license to bind 8081 on WAN."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: GatewayProviderName
    wan_surface: WanSurface
    control_port_public: bool = False
    installer_open: bool = False

    @model_validator(mode="after")
    def validate_fail_closed_inspection(self) -> "GatewayInspection":
        if self.control_port_public:
            raise ValueError("Control Center port 8081 must not be public")
        if self.installer_open:
            raise ValueError("installer must stay closed after completed handoff")
        if self.wan_surface is WanSurface.CLOSED and self.control_port_public:
            raise ValueError("closed WAN surface cannot publish Control Center")
        return self


@runtime_checkable
class HttpsGatewayProvider(Protocol):
    """HTTPS publication adapter. Core never writes nginx configuration files."""

    name: str

    def plan(
        self,
        intent: RemoteControlIntent,
        *,
        wan_surface: WanSurface,
    ) -> GatewayPlan: ...

    def validate(self, plan: GatewayPlan) -> None: ...

    def apply(self, plan: GatewayPlan) -> None: ...

    def verify(self) -> None: ...

    def rollback(self) -> None: ...

    def inspect(self) -> GatewayInspection: ...


class RemoteControlRecord(BaseModel):
    """Persisted observed Remote Control state plus the last accepted intent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    intent: RemoteControlIntent | None = None
    status: RemoteControlStatus = RemoteControlStatus.DISABLED
    enrolled_admin_passkey: bool = False
    error_code: str | None = None

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _ERROR_CODE.fullmatch(value):
            raise ValueError("invalid remote control error code")
        return value

    @model_validator(mode="after")
    def validate_observed_invariants(self) -> "RemoteControlRecord":
        if (
            self.status is RemoteControlStatus.ENABLED
            and not self.enrolled_admin_passkey
        ):
            raise ValueError("ENABLED is impossible without an enrolled admin passkey")
        if self.status is RemoteControlStatus.ENABLED and self.intent is None:
            raise ValueError("ENABLED requires a remote control intent")
        if (
            self.status
            in {
                RemoteControlStatus.PREFLIGHT,
                RemoteControlStatus.ENROLLMENT_PENDING,
                RemoteControlStatus.ENABLED,
            }
            and (self.intent is None or not self.intent.remote_access_requested)
        ):
            raise ValueError("active remote control requires requested intent")
        if self.status is not RemoteControlStatus.ERROR and self.error_code is not None:
            raise ValueError("error_code is only valid while status is ERROR")
        if self.status is RemoteControlStatus.ERROR and self.error_code is None:
            raise ValueError("ERROR requires an error_code")
        return self

    @property
    def remote_control_enabled(self) -> bool:
        return remote_control_enabled(self.status)

    @property
    def wan_surface(self) -> WanSurface:
        return wan_surface_for(self.status)


def _require_completed(install_state: InstallState) -> None:
    if install_state is not InstallState.COMPLETED:
        raise InvalidRemoteControlTransition(
            "remote control starts only after installation is COMPLETED"
        )


class RemoteControlStore:
    """Atomic Remote Control record. Never writes installer state."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> RemoteControlRecord:
        if not self.path.is_file():
            return RemoteControlRecord()
        return RemoteControlRecord.model_validate(read_json(self.path, {}))

    def request_remote(
        self,
        intent: RemoteControlIntent,
        *,
        install_state: InstallState,
    ) -> RemoteControlRecord:
        _require_completed(install_state)
        intent = RemoteControlIntent.model_validate(intent.model_dump())
        if not intent.remote_access_requested:
            raise InvalidRemoteControlTransition("remote access was not requested")
        with exclusive_file_lock(self.path):
            current = self.read()
            if current.status is RemoteControlStatus.ENABLED:
                raise InvalidRemoteControlTransition("remote control is already ENABLED")
            record = RemoteControlRecord(
                intent=intent,
                status=RemoteControlStatus.PREFLIGHT,
                enrolled_admin_passkey=current.enrolled_admin_passkey,
                error_code=None,
            )
            return self._write_unlocked(record)

    def preflight_failed(
        self,
        error_code: str,
        *,
        install_state: InstallState,
    ) -> RemoteControlRecord:
        _require_completed(install_state)
        with exclusive_file_lock(self.path):
            current = self.read()
            if current.status not in {
                RemoteControlStatus.PREFLIGHT,
                RemoteControlStatus.ENROLLMENT_PENDING,
                RemoteControlStatus.ENABLED,
            }:
                raise InvalidRemoteControlTransition(
                    f"cannot mark preflight failure from {current.status.value}"
                )
            return self._fail_unlocked(current, error_code)

    def preflight_succeeded(self, *, install_state: InstallState) -> RemoteControlRecord:
        _require_completed(install_state)
        with exclusive_file_lock(self.path):
            current = self.read()
            if current.status is not RemoteControlStatus.PREFLIGHT:
                raise InvalidRemoteControlTransition(
                    "preflight success is only valid from PREFLIGHT"
                )
            if current.enrolled_admin_passkey:
                record = current.model_copy(
                    update={"status": RemoteControlStatus.ENABLED, "error_code": None}
                )
            else:
                record = current.model_copy(
                    update={
                        "status": RemoteControlStatus.ENROLLMENT_PENDING,
                        "error_code": None,
                    }
                )
            return self._write_unlocked(record)

    def record_admin_passkey_enrolled(
        self, *, install_state: InstallState
    ) -> RemoteControlRecord:
        """WebAuthn enrollment hook. PR1 only records the fact, not the ceremony."""

        _require_completed(install_state)
        with exclusive_file_lock(self.path):
            current = self.read()
            if current.status is not RemoteControlStatus.ENROLLMENT_PENDING:
                raise InvalidRemoteControlTransition(
                    "admin passkey enrollment is only valid during ENROLLMENT_PENDING"
                )
            if wan_surface_for(current.status) is not WanSurface.ACTIVATE_ONLY:
                raise InvalidRemoteControlTransition(
                    "passkey enrollment requires the activate-only WAN surface"
                )
            record = current.model_copy(
                update={
                    "enrolled_admin_passkey": True,
                    "status": RemoteControlStatus.ENABLED,
                    "error_code": None,
                }
            )
            return self._write_unlocked(record)

    def fail(
        self,
        error_code: str,
        *,
        install_state: InstallState,
    ) -> RemoteControlRecord:
        _require_completed(install_state)
        with exclusive_file_lock(self.path):
            current = self.read()
            if current.status is RemoteControlStatus.DISABLED:
                raise InvalidRemoteControlTransition("DISABLED has no WAN failure mode")
            return self._fail_unlocked(current, error_code)

    def retry_preflight(self, *, install_state: InstallState) -> RemoteControlRecord:
        _require_completed(install_state)
        with exclusive_file_lock(self.path):
            current = self.read()
            if current.status is not RemoteControlStatus.ERROR:
                raise InvalidRemoteControlTransition("retry is only valid from ERROR")
            if current.intent is None or not current.intent.remote_access_requested:
                raise InvalidRemoteControlTransition("retry requires requested intent")
            record = current.model_copy(
                update={"status": RemoteControlStatus.PREFLIGHT, "error_code": None}
            )
            return self._write_unlocked(record)

    def disable(self, *, install_state: InstallState) -> RemoteControlRecord:
        _require_completed(install_state)
        with exclusive_file_lock(self.path):
            current = self.read()
            record = RemoteControlRecord(
                intent=current.intent,
                status=RemoteControlStatus.DISABLED,
                enrolled_admin_passkey=current.enrolled_admin_passkey,
                error_code=None,
            )
            return self._write_unlocked(record)

    def _fail_unlocked(
        self, current: RemoteControlRecord, error_code: str
    ) -> RemoteControlRecord:
        record = current.model_copy(
            update={"status": RemoteControlStatus.ERROR, "error_code": error_code}
        )
        return self._write_unlocked(record)

    def _write_unlocked(self, record: RemoteControlRecord) -> RemoteControlRecord:
        record = RemoteControlRecord.model_validate(record.model_dump(mode="json"))
        write_json_atomic(
            self.path,
            record.model_dump(mode="json"),
        )
        return record


def plan_for(record: RemoteControlRecord) -> GatewayPlan:
    """Build the only gateway plan Core will hand to a provider."""

    if record.intent is None:
        raise RemoteControlError("gateway plan requires a remote control intent")
    return GatewayPlan(intent=record.intent, wan_surface=record.wan_surface)
