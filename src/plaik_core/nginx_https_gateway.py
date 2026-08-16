"""nginx HTTPS gateway adapter for Remote Control publication.

This module renders and reloads a *managed* nginx snippet. It never binds the
PLAIK runtime to a WAN address, never exposes port 8081 or the installer, and
never talks to WebAuthn. Operator enable/disable/reconfigure must go through
:func:`publish_nginx_remote_control`, which uses ``HttpsGatewayTransaction``.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol

from .https_gateway import HttpsGatewayTransaction, HttpsGatewayTransactionResult
from .installer import InstallState
from .remote_control import (
    GatewayInspection,
    GatewayPlan,
    GatewayProviderName,
    RemoteControlError,
    RemoteControlRecord,
    RemoteControlStore,
    WanSurface,
)
from .storage import fsync_directory_best_effort


MANAGED_MARKER = "plaik-managed-https-gateway"
SURFACE_MARKER = "plaik-wan-surface"
WEB_PROXY = "http://127.0.0.1:8080"
CONTROL_PROXY = "http://127.0.0.1:8081"
MAX_CONFIG_BYTES = 256 * 1024
_LISTEN_UNSAFE = re.compile(r"(8081|8765)")
_INJECT = re.compile(r"[\n;{}]")
_LISTEN_8081 = re.compile(r"listen\s+\S*8081\b")
_LISTEN_8765 = re.compile(r"listen\s+\S*8765\b")
_PROXY_INSTALLER = re.compile(r"proxy_pass\s+http://127\.0\.0\.1:8765\b")
_PROXY_CONTROL_ROOT = re.compile(
    r"location\s+/\s*\{[^}]*proxy_pass\s+http://127\.0\.0\.1:8081",
    re.DOTALL,
)
_PROXY_ADMIN = re.compile(
    r"location\s+/api/admin[^\n]*\{[^}]*proxy_pass\s+http://127\.0\.0\.1:8081",
    re.DOTALL,
)
_PROXY_CONTROL_CENTER = re.compile(
    r"location\s+/control-center[^\n]*\{[^}]*proxy_pass\s+http://127\.0\.0\.1:8081",
    re.DOTALL,
)
_ACTIVATE_PROXY = re.compile(
    r"location\s+=\s+/activate/?\s*\{[^}]*proxy_pass\s+http://127\.0\.0\.1:8081",
    re.DOTALL,
)
_SERVER_BLOCK = re.compile(r"\bserver\s*\{")


class NginxGatewayError(RemoteControlError):
    """nginx publication failed without changing installer state."""


class NginxProcess(Protocol):
    def test(self) -> None: ...

    def reload(self) -> None: ...


class SubprocessNginxProcess:
    """Runs ``nginx -t`` / ``nginx -s reload`` with a fixed argv prefix."""

    def __init__(self, argv: tuple[str, ...] = ("nginx",)) -> None:
        if not argv:
            raise NginxGatewayError("nginx argv is required")
        self.argv = argv

    def test(self) -> None:
        self._run(("-t",), action="test")

    def reload(self) -> None:
        self._run(("-s", "reload"), action="reload")

    def _run(self, extra: tuple[str, ...], *, action: str) -> None:
        completed = subprocess.run(
            [*self.argv, *extra],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or action).strip()
            raise NginxGatewayError(f"nginx {action} failed: {detail[:500]}")


class MemoryNginxProcess:
    """In-process nginx stand-in. No host nginx, no sockets."""

    def __init__(self) -> None:
        self.tests = 0
        self.reloads = 0
        self.fail_tests_remaining = 0
        self.fail_reload = False

    def test(self) -> None:
        self.tests += 1
        if self.fail_tests_remaining > 0:
            self.fail_tests_remaining -= 1
            raise NginxGatewayError("nginx test failed")

    def reload(self) -> None:
        self.reloads += 1
        if self.fail_reload:
            raise NginxGatewayError("nginx reload failed")


def _write_text_atomic(path: Path, text: str) -> None:
    payload = text.encode("utf-8")
    if len(payload) > MAX_CONFIG_BYTES:
        raise NginxGatewayError("nginx config exceeds the size limit")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}-", dir=target.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        expected = temporary_path.lstat()
        os.replace(temporary_path, target)
        current = os.stat(target, follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != expected.st_dev
            or current.st_ino != expected.st_ino
            or current.st_size != expected.st_size
        ):
            raise NginxGatewayError("nginx config changed while it was published")
        fsync_directory_best_effort(target.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def _safe_token(value: str, *, label: str) -> str:
    candidate = value.strip()
    if not candidate or _INJECT.search(candidate):
        raise NginxGatewayError(f"{label} is not a safe nginx token")
    return candidate


def _safe_listen(listen: str) -> str:
    candidate = _safe_token(listen, label="listen")
    if _LISTEN_UNSAFE.search(candidate):
        raise NginxGatewayError(
            "gateway listen cannot expose Control Center port 8081 or installer port 8765"
        )
    return candidate


def _safe_file(path: Path, *, label: str) -> Path:
    target = Path(path).expanduser()
    if not target.is_absolute():
        raise NginxGatewayError(f"{label} must be an absolute path")
    try:
        metadata = os.lstat(target)
    except OSError as error:
        raise NginxGatewayError(f"{label} cannot be read") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise NginxGatewayError(f"{label} must be a regular file")
    return target


def _proxy_headers() -> str:
    return (
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
    )


def _ssl_server(
    *,
    listen: str,
    server_name: str,
    certificate: Path,
    certificate_key: Path,
    locations: str,
) -> str:
    return (
        "server {\n"
        f"    listen {listen};\n"
        f"    server_name {server_name};\n"
        f"    ssl_certificate {certificate};\n"
        f"    ssl_certificate_key {certificate_key};\n"
        f"{locations}"
        "}\n"
    )


def render_nginx_gateway_config(
    plan: GatewayPlan,
    *,
    certificate_path: Path | None,
    certificate_key_path: Path | None,
    listen: str = "443 ssl",
) -> str:
    """Render the managed snippet for ``plan.wan_surface``."""

    intent = plan.intent
    listen = _safe_listen(listen)
    public_hostname = _safe_token(intent.public_hostname, label="public_hostname")
    control_hostname = _safe_token(intent.control_hostname, label="control_hostname")
    lines = [
        f"# {MANAGED_MARKER}",
        f"# {SURFACE_MARKER}: {plan.wan_surface.value}",
        f"# plaik-public-hostname: {public_hostname}",
        f"# plaik-control-hostname: {control_hostname}",
        "",
    ]
    if plan.wan_surface is WanSurface.CLOSED:
        lines.append("# WAN closed: no server blocks.\n")
        text = "\n".join(lines)
        _assert_rendered_safe(text, plan)
        return text
    if certificate_path is None or certificate_key_path is None:
        raise NginxGatewayError("TLS certificate and key are required to publish WAN")
    certificate = _safe_file(certificate_path, label="ssl_certificate")
    certificate_key = _safe_file(certificate_key_path, label="ssl_certificate_key")
    public_locations = (
        "    location / {\n"
        f"        proxy_pass {WEB_PROXY};\n"
        f"{_proxy_headers()}\n"
        "    }\n"
    )
    lines.append(
        _ssl_server(
            listen=listen,
            server_name=public_hostname,
            certificate=certificate,
            certificate_key=certificate_key,
            locations=public_locations,
        )
    )
    if plan.wan_surface is WanSurface.ACTIVATE_ONLY:
        control_locations = (
            "    location = /activate {\n"
            f"        proxy_pass {CONTROL_PROXY};\n"
            f"{_proxy_headers()}\n"
            "    }\n"
            "    location = /activate/ {\n"
            f"        proxy_pass {CONTROL_PROXY};\n"
            f"{_proxy_headers()}\n"
            "    }\n"
            "    location /control-center { return 404; }\n"
            "    location /api/admin { return 404; }\n"
            "    location / { return 404; }\n"
        )
    else:
        control_locations = (
            "    location / {\n"
            f"        proxy_pass {CONTROL_PROXY};\n"
            f"{_proxy_headers()}\n"
            "    }\n"
        )
    lines.append(
        _ssl_server(
            listen=listen,
            server_name=control_hostname,
            certificate=certificate,
            certificate_key=certificate_key,
            locations=control_locations,
        )
    )
    text = "\n".join(lines)
    if not text.endswith("\n"):
        text += "\n"
    _assert_rendered_safe(text, plan)
    return text


def _assert_rendered_safe(text: str, plan: GatewayPlan) -> None:
    if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise NginxGatewayError("nginx config exceeds the size limit")
    if _LISTEN_8081.search(text) or _LISTEN_8765.search(text):
        raise NginxGatewayError("rendered nginx config cannot listen on 8081 or 8765")
    if _PROXY_INSTALLER.search(text):
        raise NginxGatewayError("rendered nginx config cannot proxy the installer")
    if "0.0.0.0:8081" in text or "[::]:8081" in text:
        raise NginxGatewayError("rendered nginx config cannot expose Control Center on WAN")
    if plan.wan_surface is WanSurface.CLOSED:
        if _SERVER_BLOCK.search(text):
            raise NginxGatewayError("closed WAN surface cannot contain server blocks")
        return
    if plan.wan_surface is WanSurface.ACTIVATE_ONLY:
        if not _ACTIVATE_PROXY.search(text):
            raise NginxGatewayError("activate-only surface must proxy /activate")
        if _PROXY_CONTROL_ROOT.search(text):
            raise NginxGatewayError("activate-only surface cannot proxy Control Center /")
        if _PROXY_ADMIN.search(text) or _PROXY_CONTROL_CENTER.search(text):
            raise NginxGatewayError(
                "activate-only surface cannot proxy /api/admin or /control-center"
            )
        return
    if not _PROXY_CONTROL_ROOT.search(text):
        raise NginxGatewayError("Control Center surface must proxy / to 127.0.0.1:8081")


def inspect_nginx_config(text: str) -> WanSurface:
    """Derive WAN surface from the managed snippet. Marker is not trusted alone."""

    if MANAGED_MARKER not in text or not text.strip():
        return WanSurface.CLOSED
    if not _SERVER_BLOCK.search(text):
        return WanSurface.CLOSED
    if _LISTEN_8081.search(text) or _LISTEN_8765.search(text) or _PROXY_INSTALLER.search(text):
        raise NginxGatewayError("managed nginx config exposes a forbidden listener")
    if _PROXY_CONTROL_ROOT.search(text):
        return WanSurface.CONTROL_CENTER
    if _ACTIVATE_PROXY.search(text):
        if _PROXY_ADMIN.search(text) or _PROXY_CONTROL_CENTER.search(text):
            raise NginxGatewayError("activate-only config proxies the Control Center")
        return WanSurface.ACTIVATE_ONLY
    return WanSurface.CLOSED


class NginxHttpsGatewayProvider:
    """``HttpsGatewayProvider`` adapter. Does not choose ``wan_surface``."""

    name = GatewayProviderName.NGINX

    def __init__(
        self,
        *,
        config_path: Path,
        certificate_path: Path | None = None,
        certificate_key_path: Path | None = None,
        listen: str = "443 ssl",
        nginx: NginxProcess | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.certificate_path = certificate_path
        self.certificate_key_path = certificate_key_path
        self.listen = listen
        self.nginx = nginx or SubprocessNginxProcess()
        self._previous: str | None = None
        self._last_plan: GatewayPlan | None = None

    def plan(self, record: RemoteControlRecord) -> GatewayPlan:
        return GatewayPlan.from_record(record)

    def validate(self, plan: GatewayPlan) -> None:
        if plan.intent.gateway_provider is not GatewayProviderName.NGINX:
            raise NginxGatewayError("nginx provider cannot publish a non-nginx intent")
        render_nginx_gateway_config(
            plan,
            certificate_path=self.certificate_path,
            certificate_key_path=self.certificate_key_path,
            listen=self.listen,
        )

    def apply(self, plan: GatewayPlan) -> None:
        rendered = render_nginx_gateway_config(
            plan,
            certificate_path=self.certificate_path,
            certificate_key_path=self.certificate_key_path,
            listen=self.listen,
        )
        previous = ""
        if self.config_path.is_file():
            previous = self.config_path.read_text(encoding="utf-8")
        self._previous = previous
        _write_text_atomic(self.config_path, rendered)
        try:
            self.nginx.test()
            self.nginx.reload()
        except Exception:
            _write_text_atomic(self.config_path, previous)
            raise
        self._last_plan = plan

    def verify(self) -> None:
        if not self.config_path.is_file():
            raise NginxGatewayError("managed nginx config is missing")
        self.nginx.test()
        if self._last_plan is not None:
            current = inspect_nginx_config(self.config_path.read_text(encoding="utf-8"))
            if current is not self._last_plan.wan_surface:
                raise NginxGatewayError("nginx verify does not match the applied surface")

    def rollback(self) -> None:
        if self._previous is None:
            return
        _write_text_atomic(self.config_path, self._previous)
        self.nginx.test()
        self.nginx.reload()
        self._last_plan = None

    def inspect(self) -> GatewayInspection:
        if not self.config_path.is_file():
            surface = WanSurface.CLOSED
        else:
            surface = inspect_nginx_config(self.config_path.read_text(encoding="utf-8"))
        return GatewayInspection(
            provider=GatewayProviderName.NGINX,
            wan_surface=surface,
        )


def publish_nginx_remote_control(
    store: RemoteControlStore,
    provider: NginxHttpsGatewayProvider,
    *,
    install_state: InstallState,
) -> HttpsGatewayTransactionResult:
    """The only operator publication path. Never writes nginx outside the transaction."""

    if GatewayProviderName(provider.name) is not GatewayProviderName.NGINX:
        raise NginxGatewayError("publish_nginx_remote_control requires the nginx provider")
    return HttpsGatewayTransaction(provider, store).run(install_state=install_state)
