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
import time
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
MANAGED_CONFIG_NAME = "plaik-remote-control.conf"
WEB_PROXY = "http://127.0.0.1:8080"
CONTROL_PROXY = "http://127.0.0.1:8081"
MAX_CONFIG_BYTES = 256 * 1024
MAX_DUMP_BYTES = 8 * 1024 * 1024
RELOAD_CONVERGE_SECONDS = 5.0
_PID_DIRECTIVE = re.compile(r"^pid\s+(\S+);", re.MULTILINE)
_LISTEN_UNSAFE = re.compile(r"(8081|8765)")
_INJECT = re.compile(r"[\n;{}]")
_PATH_UNSAFE = re.compile(r'[\n;{}`"\'\\$]')
_LISTEN_8081 = re.compile(r"listen\s+(?:\S+:)?8081\b")
_LISTEN_8765 = re.compile(r"listen\s+(?:\S+:)?8765\b")
_LISTEN_SPEC = re.compile(r"listen\s+([^;]+);")
_CONFIG_FILE_HEADER = re.compile(r"^# configuration file (.+):\s*$", re.MULTILINE)
_SERVER_NAME_LIST = re.compile(r"server_name\s+([^;]+);")
_PROXY_INSTALLER = re.compile(r"proxy_pass\s+http://127\.0\.0\.1:8765\b")
_PROXY_8081 = re.compile(r"proxy_pass\s+http://127\.0\.0\.1:8081\b")
_PROXY_CONTROL_ROOT = re.compile(
    r"location\s+/\s*\{[^}]*proxy_pass\s+http://127\.0\.0\.1:\d+",
    re.DOTALL,
)
_PROXY_ADMIN = re.compile(
    r"location\s+/api/admin[^\n]*\{[^}]*proxy_pass\s+",
    re.DOTALL,
)
_PROXY_CONTROL_CENTER = re.compile(
    r"location\s+/control-center[^\n]*\{[^}]*proxy_pass\s+",
    re.DOTALL,
)
_ACTIVATE_PROXY = re.compile(
    r"location\s+=\s+/activate/?\s*\{[^}]*proxy_pass\s+http://127\.0\.0\.1:\d+",
    re.DOTALL,
)
_LOOPBACK_PROXY = re.compile(r"^http://127\.0\.0\.1:([1-9][0-9]{0,4})$")
_SERVER_NAME = re.compile(r"server_name\s+(\S+);")
_MARKER_VALUE = re.compile(r"# plaik-(public|control)-hostname:\s*(\S+)")


class NginxGatewayError(RemoteControlError):
    """nginx publication failed without changing installer state."""


class NginxProcess(Protocol):
    def test(self) -> None: ...

    def reload(self) -> None: ...

    def effective_config(self) -> str: ...


class SubprocessNginxProcess:
    """Runs ``nginx -t`` / ``nginx -s reload`` / ``nginx -T`` with a fixed argv prefix."""

    def __init__(self, argv: tuple[str, ...] = ("nginx",)) -> None:
        if not argv:
            raise NginxGatewayError("nginx argv is required")
        self.argv = argv

    def test(self) -> None:
        self._run(("-t",), action="test")

    def reload(self) -> None:
        master, old_workers = self._generation()
        self._run(("-s", "reload"), action="reload")
        self._wait_reload_converged(master, old_workers)

    def effective_config(self) -> str:
        completed = self._completed(("-T",), action="dump")
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if _CONFIG_FILE_HEADER.search(stdout):
            dump = stdout
        elif _CONFIG_FILE_HEADER.search(stderr):
            dump = stderr
        else:
            dump = f"{stdout}\n{stderr}"
        if len(dump.encode("utf-8")) > MAX_DUMP_BYTES:
            raise NginxGatewayError("nginx effective config exceeds the size limit")
        return dump

    def _config_path(self) -> Path | None:
        argv = list(self.argv)
        try:
            index = argv.index("-c")
        except ValueError:
            return None
        if index + 1 >= len(argv):
            return None
        return Path(argv[index + 1])

    def _pid_file(self) -> Path:
        config = self._config_path()
        if config is not None:
            try:
                text = config.read_text(encoding="utf-8")
            except OSError as error:
                raise NginxGatewayError("nginx pid file path cannot be read") from error
            match = _PID_DIRECTIVE.search(text)
            if match:
                return Path(match.group(1))
        return Path("/run/nginx.pid")

    def _read_master_pid(self) -> int | None:
        try:
            text = self._pid_file().read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not text.isdigit():
            return None
        pid = int(text)
        if not Path(f"/proc/{pid}").exists():
            return None
        return pid

    def _worker_pids(self, master: int) -> frozenset[int]:
        workers: set[int] = set()
        try:
            entries = Path("/proc").iterdir()
        except OSError:
            return frozenset()
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                status = (entry / "status").read_text(encoding="utf-8")
            except OSError:
                continue
            ppid = None
            for line in status.splitlines():
                if line.startswith("PPid:"):
                    ppid = int(line.split()[1])
                    break
            if ppid != master:
                continue
            try:
                command = (
                    (entry / "cmdline")
                    .read_bytes()
                    .replace(b"\x00", b" ")
                    .decode("utf-8", "replace")
                )
            except OSError:
                continue
            if "worker process" in command:
                workers.add(int(entry.name))
        return frozenset(workers)

    def _generation(self) -> tuple[int | None, frozenset[int]]:
        master = self._read_master_pid()
        if master is None:
            return None, frozenset()
        return master, self._worker_pids(master)

    def _wait_reload_converged(
        self, master: int | None, old_workers: frozenset[int]
    ) -> None:
        if master is None:
            raise NginxGatewayError("nginx reload cannot converge without a master process")
        deadline = time.monotonic() + RELOAD_CONVERGE_SECONDS
        while time.monotonic() < deadline:
            current_master = self._read_master_pid()
            if current_master != master:
                time.sleep(0.02)
                continue
            current_workers = self._worker_pids(current_master)
            old_still_running = old_workers & current_workers
            new_workers = current_workers - old_workers
            if old_workers:
                if not old_still_running and new_workers:
                    return
            elif current_workers:
                return
            time.sleep(0.02)
        raise NginxGatewayError(
            "nginx reload did not converge onto a new worker generation"
        )

    def _run(self, extra: tuple[str, ...], *, action: str) -> None:
        self._completed(extra, action=action)

    def _completed(
        self, extra: tuple[str, ...], *, action: str
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [*self.argv, *extra],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or action).strip()
            raise NginxGatewayError(f"nginx {action} failed: {detail[:500]}")
        return completed


class MemoryNginxProcess:
    """In-process nginx stand-in. No host nginx, no sockets."""

    def __init__(self, *, include_managed: bool = True) -> None:
        self.tests = 0
        self.reloads = 0
        self.fail_tests_remaining = 0
        self.fail_reload = False
        self.include_managed = include_managed
        self.managed_config: Path | None = None
        self.dumps = 0
        self.extra_dump = ""

    def test(self) -> None:
        self.tests += 1
        if self.fail_tests_remaining > 0:
            self.fail_tests_remaining -= 1
            raise NginxGatewayError("nginx test failed")

    def reload(self) -> None:
        self.reloads += 1
        if self.fail_reload:
            raise NginxGatewayError("nginx reload failed")

    def effective_config(self) -> str:
        self.dumps += 1
        path = self.managed_config if self.include_managed else None
        if path is None or not path.is_file():
            dump = (
                "# configuration file /tmp/plaik-unrelated.conf:\n"
                "events { worker_connections 1; }\n"
            )
        else:
            dump = f"# configuration file {path}:\n{path.read_text(encoding='utf-8')}"
        return dump + self.extra_dump


def _write_text_atomic(path: Path, text: str) -> None:
    payload = text.encode("utf-8")
    if len(payload) > MAX_CONFIG_BYTES:
        raise NginxGatewayError("nginx config exceeds the size limit")
    target = Path(path)
    if not target.parent.is_dir():
        raise NginxGatewayError("managed nginx parent directory does not exist")
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


def _safe_listen(listen: str, *, require_tls: bool = True) -> str:
    candidate = _safe_token(listen, label="listen")
    if _LISTEN_UNSAFE.search(candidate):
        raise NginxGatewayError(
            "gateway listen cannot expose Control Center port 8081 or installer port 8765"
        )
    if require_tls and "ssl" not in candidate.casefold().split():
        raise NginxGatewayError("gateway listen must enable TLS")
    return candidate


def _normalize_nginx_text(text: str) -> str:
    return text.replace("\r\n", "\n").strip() + "\n"


def _path_aliases(path: Path) -> set[str]:
    aliases = {str(path)}
    try:
        aliases.add(str(path.resolve()))
    except OSError:
        pass
    return aliases


def _split_effective_files(dump: str) -> dict[str, str]:
    files: dict[str, str] = {}
    matches = list(_CONFIG_FILE_HEADER.finditer(dump))
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(dump)
        files[match.group(1)] = dump[start:end].lstrip("\n")
    return files


def _included_managed_snippet(dump: str, config_path: Path) -> str:
    files = _split_effective_files(dump)
    wanted = _path_aliases(config_path)
    for key, body in files.items():
        if _path_aliases(Path(key)) & wanted:
            return body
    raise NginxGatewayError(
        "managed nginx config is not in the effective nginx configuration"
    )


def _foreign_effective_text(dump: str, config_path: Path) -> str:
    files = _split_effective_files(dump)
    wanted = _path_aliases(config_path)
    parts: list[str] = []
    for key, body in files.items():
        if _path_aliases(Path(key)) & wanted:
            continue
        parts.append(body)
    return "\n".join(parts)


def _server_names(block: str) -> tuple[str, ...]:
    names: list[str] = []
    for match in _SERVER_NAME_LIST.finditer(block):
        names.extend(token for token in match.group(1).split() if token != "_")
    return tuple(names)


def _assert_no_forbidden_listeners(text: str, *, label: str) -> None:
    if _LISTEN_8081.search(text) or _LISTEN_8765.search(text):
        raise NginxGatewayError(f"{label} exposes a forbidden listener")
    if _PROXY_INSTALLER.search(text):
        raise NginxGatewayError(f"{label} proxies the installer")


def _assert_effective_dump(
    dump: str,
    snippet: str,
    config_path: Path,
    extra_hostnames: frozenset[str] = frozenset(),
) -> None:
    """Fail closed on conflicts outside the managed snippet. Does not edit foreign files."""

    _assert_no_forbidden_listeners(dump, label="effective nginx config")
    foreign = _foreign_effective_text(dump, config_path)
    if _PROXY_8081.search(foreign):
        raise NginxGatewayError(
            "effective nginx config still publishes Control Center"
        )
    reserved = {name for name in _marker_hostnames(snippet) if name}
    reserved.update(extra_hostnames)
    if not reserved:
        return
    for block in _server_blocks(foreign):
        if reserved.intersection(_server_names(block)):
            raise NginxGatewayError(
                "effective nginx config has a conflicting server_name"
            )


def _assert_tls_server(block: str) -> None:
    specs = _LISTEN_SPEC.findall(block)
    if not specs:
        raise NginxGatewayError("managed nginx server must listen with TLS")
    for spec in specs:
        if "ssl" not in spec.casefold().split():
            raise NginxGatewayError("managed nginx server must listen with TLS")


def _safe_loopback_proxy(url: str, *, label: str) -> str:
    candidate = url.strip()
    match = _LOOPBACK_PROXY.fullmatch(candidate)
    if not match:
        raise NginxGatewayError(f"{label} must be http://127.0.0.1:<port>")
    port = int(match.group(1))
    if port > 65535 or port == 8765:
        raise NginxGatewayError(f"{label} cannot target the installer or an invalid port")
    return candidate


def _readable_cert_path(path: Path, *, label: str) -> Path:
    """Read-only TLS path. Symlink chains (certbot live/) are allowed."""

    target = Path(path).expanduser()
    if not target.is_absolute():
        raise NginxGatewayError(f"{label} must be an absolute path")
    rendered = str(target)
    if _PATH_UNSAFE.search(rendered) or " " in rendered:
        raise NginxGatewayError(f"{label} is not a safe nginx path")
    if ".." in target.parts:
        raise NginxGatewayError(f"{label} must not contain parent-directory segments")
    try:
        if not target.is_file():
            raise NginxGatewayError(f"{label} cannot be read")
    except OSError as error:
        raise NginxGatewayError(f"{label} cannot be read") from error
    return target


def _require_managed_root(path: Path) -> Path:
    root = Path(path).expanduser()
    if not root.is_absolute():
        raise NginxGatewayError("managed root must be an absolute path")
    if ".." in root.parts:
        raise NginxGatewayError("managed root must not contain parent-directory segments")
    try:
        metadata = os.lstat(root)
    except OSError as error:
        raise NginxGatewayError("managed root does not exist") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise NginxGatewayError("managed root cannot be a symlink")
    if not stat.S_ISDIR(metadata.st_mode):
        raise NginxGatewayError("managed root must be a directory")
    return root


def _managed_config_path(managed_root: Path) -> Path:
    root = _require_managed_root(managed_root)
    target = root / MANAGED_CONFIG_NAME
    if target.exists() or target.is_symlink():
        try:
            metadata = os.lstat(target)
        except OSError as error:
            raise NginxGatewayError("managed nginx config cannot be read") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise NginxGatewayError("managed nginx config cannot be a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            raise NginxGatewayError("managed nginx config must be a regular file")
        existing = target.read_text(encoding="utf-8")
        if existing.strip() and MANAGED_MARKER not in existing:
            raise NginxGatewayError("refusing to overwrite a non-PLAIK nginx file")
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
    web_proxy: str = WEB_PROXY,
    control_proxy: str = CONTROL_PROXY,
) -> str:
    """Render the managed snippet for ``plan.wan_surface``."""

    intent = plan.intent
    listen = _safe_listen(
        listen, require_tls=plan.wan_surface is not WanSurface.CLOSED
    )
    web_proxy = _safe_loopback_proxy(web_proxy, label="web_proxy")
    control_proxy = _safe_loopback_proxy(control_proxy, label="control_proxy")
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
    certificate = _readable_cert_path(certificate_path, label="ssl_certificate")
    certificate_key = _readable_cert_path(certificate_key_path, label="ssl_certificate_key")
    public_locations = (
        "    location / {\n"
        f"        proxy_pass {web_proxy};\n"
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
            f"        proxy_pass {control_proxy};\n"
            f"{_proxy_headers()}\n"
            "    }\n"
            "    location = /activate/ {\n"
            f"        proxy_pass {control_proxy};\n"
            f"{_proxy_headers()}\n"
            "    }\n"
            "    location /control-center { return 404; }\n"
            "    location /api/admin { return 404; }\n"
            "    location / { return 404; }\n"
        )
    else:
        control_locations = (
            "    location / {\n"
            f"        proxy_pass {control_proxy};\n"
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


def _server_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    for match in re.finditer(r"\bserver\s*\{", text):
        start = match.start()
        depth = 0
        for index, char in enumerate(text[start:]):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[start : start + index + 1])
                    break
        else:
            raise NginxGatewayError("unknown managed nginx topology")
    return blocks


def _marker_hostnames(text: str) -> tuple[str | None, str | None]:
    public = control = None
    for match in _MARKER_VALUE.finditer(text):
        if match.group(1) == "public":
            public = match.group(2)
        else:
            control = match.group(2)
    return public, control


def _proxy_targets(block: str) -> tuple[str, ...]:
    return tuple(re.findall(r"proxy_pass\s+(http://127\.0\.0\.1:\d+)\b", block))


def _assert_public_web_only(block: str) -> None:
    if _PROXY_8081.search(block):
        raise NginxGatewayError("public hostname cannot proxy Control Center")
    targets = _proxy_targets(block)
    if len(targets) != 1 or not targets[0].startswith("http://127.0.0.1:"):
        raise NginxGatewayError("unknown managed nginx topology")
    if targets[0].endswith(":8765") or targets[0].endswith(":8081"):
        raise NginxGatewayError("unknown managed nginx topology")


def inspect_nginx_config(text: str) -> WanSurface:
    """Derive WAN surface from the managed snippet.

    ``CLOSED`` is only valid when no ``server`` blocks exist. Any unknown
    topology, including an unexpected 8081 proxy, is an inspection failure.
    """

    if _LISTEN_8081.search(text) or _LISTEN_8765.search(text) or _PROXY_INSTALLER.search(text):
        raise NginxGatewayError("managed nginx config exposes a forbidden listener")
    blocks = _server_blocks(text)
    if not blocks:
        if _PROXY_8081.search(text):
            raise NginxGatewayError("unknown managed nginx topology")
        return WanSurface.CLOSED
    for block in blocks:
        _assert_tls_server(block)
    public, control = _marker_hostnames(text)
    if public is None or control is None or public == control:
        raise NginxGatewayError("unknown managed nginx topology")
    names: dict[str, str] = {}
    for block in blocks:
        match = _SERVER_NAME.search(block)
        if match is None:
            raise NginxGatewayError("unknown managed nginx topology")
        name = match.group(1)
        if name in names:
            raise NginxGatewayError("unknown managed nginx topology")
        names[name] = block
    if set(names) != {public, control}:
        raise NginxGatewayError("unknown managed nginx topology")
    public_block = names[public]
    control_block = names[control]
    _assert_public_web_only(public_block)
    control_targets = _proxy_targets(control_block)
    if any(target.endswith(":8765") for target in control_targets):
        raise NginxGatewayError("managed nginx config cannot proxy the installer")
    if _PROXY_CONTROL_ROOT.search(control_block) and not _ACTIVATE_PROXY.search(control_block):
        if len(control_targets) != 1:
            raise NginxGatewayError("unknown managed nginx topology")
        if _PROXY_ADMIN.search(control_block) or _PROXY_CONTROL_CENTER.search(control_block):
            raise NginxGatewayError("unknown managed nginx topology")
        return WanSurface.CONTROL_CENTER
    if _ACTIVATE_PROXY.search(control_block) and not _PROXY_CONTROL_ROOT.search(control_block):
        if _PROXY_ADMIN.search(control_block) or _PROXY_CONTROL_CENTER.search(control_block):
            raise NginxGatewayError("activate-only config proxies the Control Center")
        if len(control_targets) != 2:
            raise NginxGatewayError("unknown managed nginx topology")
        if "location /control-center { return 404; }" not in control_block:
            raise NginxGatewayError("unknown managed nginx topology")
        if "location /api/admin { return 404; }" not in control_block:
            raise NginxGatewayError("unknown managed nginx topology")
        return WanSurface.ACTIVATE_ONLY
    raise NginxGatewayError("unknown managed nginx topology")


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
        if _server_blocks(text):
            raise NginxGatewayError("closed WAN surface cannot contain server blocks")
        return
    if inspect_nginx_config(text) is not plan.wan_surface:
        raise NginxGatewayError("rendered nginx config does not match the planned WAN surface")


class NginxHttpsGatewayProvider:
    """``HttpsGatewayProvider`` adapter. Does not choose ``wan_surface``."""

    name = GatewayProviderName.NGINX

    def __init__(
        self,
        *,
        managed_root: Path,
        certificate_path: Path | None = None,
        certificate_key_path: Path | None = None,
        listen: str = "443 ssl",
        nginx: NginxProcess | None = None,
        web_proxy: str = WEB_PROXY,
        control_proxy: str = CONTROL_PROXY,
    ) -> None:
        self.managed_root = _require_managed_root(managed_root)
        self.config_path = _managed_config_path(self.managed_root)
        self.certificate_path = certificate_path
        self.certificate_key_path = certificate_key_path
        self.listen = listen
        self.web_proxy = _safe_loopback_proxy(web_proxy, label="web_proxy")
        self.control_proxy = _safe_loopback_proxy(control_proxy, label="control_proxy")
        self.nginx = nginx or SubprocessNginxProcess()
        self._previous: str | None = None
        self._last_plan: GatewayPlan | None = None
        self._reserved_hostnames: frozenset[str] = frozenset()
        if isinstance(self.nginx, MemoryNginxProcess) and self.nginx.managed_config is None:
            self.nginx.managed_config = self.config_path

    def _render(self, plan: GatewayPlan) -> str:
        self._reserved_hostnames = frozenset(
            {plan.intent.public_hostname, plan.intent.control_hostname}
        )
        return render_nginx_gateway_config(
            plan,
            certificate_path=self.certificate_path,
            certificate_key_path=self.certificate_key_path,
            listen=self.listen,
            web_proxy=self.web_proxy,
            control_proxy=self.control_proxy,
        )

    def plan(self, record: RemoteControlRecord) -> GatewayPlan:
        return GatewayPlan.from_record(record)

    def validate(self, plan: GatewayPlan) -> None:
        if plan.intent.gateway_provider is not GatewayProviderName.NGINX:
            raise NginxGatewayError("nginx provider cannot publish a non-nginx intent")
        self.config_path = _managed_config_path(self.managed_root)
        self._render(plan)

    def apply(self, plan: GatewayPlan) -> None:
        self.config_path = _managed_config_path(self.managed_root)
        rendered = self._render(plan)
        previous = ""
        if self.config_path.is_file():
            previous = self.config_path.read_text(encoding="utf-8")
        self._previous = previous
        _write_text_atomic(self.config_path, rendered)
        try:
            self.nginx.test()
            self.nginx.reload()
            self._assert_effective(rendered, plan)
        except Exception:
            _write_text_atomic(self.config_path, previous)
            raise
        self._last_plan = plan

    def _effective_snippet(self) -> str:
        dump = self.nginx.effective_config()
        if len(dump.encode("utf-8")) > MAX_DUMP_BYTES:
            raise NginxGatewayError("nginx effective config exceeds the size limit")
        snippet = _included_managed_snippet(dump, self.config_path)
        _assert_effective_dump(
            dump,
            snippet,
            self.config_path,
            extra_hostnames=self._reserved_hostnames,
        )
        return snippet

    def _assert_effective(self, expected: str, plan: GatewayPlan) -> None:
        snippet = self._effective_snippet()
        if _normalize_nginx_text(snippet) != _normalize_nginx_text(expected):
            raise NginxGatewayError(
                "effective nginx config does not match the managed file"
            )
        if inspect_nginx_config(snippet) is not plan.wan_surface:
            raise NginxGatewayError(
                "effective nginx config does not match the planned WAN surface"
            )

    def verify(self) -> None:
        if not self.config_path.is_file():
            raise NginxGatewayError("managed nginx config is missing")
        self.nginx.test()
        snippet = self._effective_snippet()
        on_disk = self.config_path.read_text(encoding="utf-8")
        if _normalize_nginx_text(snippet) != _normalize_nginx_text(on_disk):
            raise NginxGatewayError(
                "effective nginx config does not match the managed file"
            )
        current = inspect_nginx_config(snippet)
        if self._last_plan is not None:
            expected = self._render(self._last_plan)
            if (
                _normalize_nginx_text(snippet) != _normalize_nginx_text(expected)
                or current is not self._last_plan.wan_surface
            ):
                raise NginxGatewayError("nginx verify does not match the applied surface")

    def rollback(self) -> None:
        if self._previous is None:
            return
        self.config_path = _managed_config_path(self.managed_root)
        _write_text_atomic(self.config_path, self._previous)
        self.nginx.test()
        self.nginx.reload()
        snippet = self._effective_snippet()
        if _normalize_nginx_text(snippet) != _normalize_nginx_text(self._previous):
            raise NginxGatewayError(
                "effective nginx config does not match the rolled-back file"
            )
        self._last_plan = None

    def inspect(self) -> GatewayInspection:
        snippet = self._effective_snippet()
        surface = inspect_nginx_config(snippet)
        if self.config_path.is_file():
            on_disk = self.config_path.read_text(encoding="utf-8")
            if _normalize_nginx_text(snippet) != _normalize_nginx_text(on_disk):
                raise NginxGatewayError(
                    "effective nginx config does not match the managed file"
                )
        if self._last_plan is not None:
            expected = self._render(self._last_plan)
            if (
                _normalize_nginx_text(snippet) != _normalize_nginx_text(expected)
                or surface is not self._last_plan.wan_surface
            ):
                raise NginxGatewayError(
                    "managed nginx config drifted from the applied plan"
                )
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
