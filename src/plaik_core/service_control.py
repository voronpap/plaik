"""Privileged host finalization shared by CLI setup and the web installer.

The installer process is unprivileged and must not run systemd itself. It
writes a bounded request file. An already-active systemd path unit starts the
root oneshot, or an already-root CLI command performs the same function
in-process. The unprivileged installer never calls ``systemctl start``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import CoreSettings
from .host_inventory import discover_host_inventory
from .installer import InstallState, InstallStateStore
from .installer_config import InstallerConfigurationStore, PostgreSQLDatabase
from .postgresql_provision import PostgreSQLProvisionError, provision_local_postgresql
from .public_secrets import (
    publish_runtime_secret,
    read_private_secret_for_publication,
)
from .secret_store import LocalFileSecretProvider, SecretNotFoundError, SecretStoreError
from .storage import write_json_atomic


class ServiceControlError(RuntimeError):
    """A privileged installer host action failed without exposing secrets."""


WEB_SERVICE = "plaik-web.service"
ADMIN_SERVICE = "plaik-admin.service"
INSTALLER_SERVICE = "plaik-installer.service"
HANDOFF_NOT_STARTED = "not_started"
HANDOFF_PENDING = "pending"
HANDOFF_FAILED = "failed"
HANDOFF_READY = "ready"
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_PROVISION_FIELDS = (
    "host",
    "port",
    "database",
    "username",
    "runtime_username",
    "checkpoint_username",
)


def _system_root() -> Path:
    return Path(os.environ.get("PLAIK_SYSTEM_ROOT", "/")).resolve()


def _is_real_system_root() -> bool:
    return _system_root() == Path("/")


def _rooted(path: str) -> Path:
    root = _system_root()
    relative = Path(path.lstrip("/"))
    return Path("/") / relative if root == Path("/") else root / relative


def config_dir() -> Path:
    return Path(os.environ.get("PLAIK_CONFIG_DIR", str(_rooted("/etc/plaik"))))


def env_file() -> Path:
    return Path(os.environ.get("PLAIK_ENV_FILE", str(config_dir() / "plaik.env")))


def installer_env_file() -> Path:
    return Path(
        os.environ.get(
            "PLAIK_INSTALLER_ENV_FILE",
            str(config_dir() / "installer.env"),
        )
    )


def web_secrets_dir(settings: CoreSettings) -> Path:
    configured = os.environ.get("PLAIK_WEB_SECRETS_DIR")
    if configured:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute():
            raise ServiceControlError("PLAIK_WEB_SECRETS_DIR must be an absolute path")
        return candidate
    geteuid = getattr(os, "geteuid", lambda: None)
    if _is_real_system_root() and geteuid() == 0:
        return config_dir() / "web-secrets"
    return settings.data_dir / "web-secrets"


def systemd_dir() -> Path:
    return Path(
        os.environ.get("PLAIK_SYSTEMD_DIR", str(_rooted("/etc/systemd/system")))
    )


def command_path() -> Path:
    return Path(
        os.environ.get("PLAIK_COMMAND_PATH", str(_rooted("/usr/local/bin/plaik")))
    )


def request_dir(settings: CoreSettings) -> Path:
    return settings.data_dir / "run"


def finalize_request_path(settings: CoreSettings) -> Path:
    return request_dir(settings) / "finalize.request"


def provision_request_path(settings: CoreSettings) -> Path:
    return request_dir(settings) / "provision.request"


def provision_error_path(settings: CoreSettings) -> Path:
    return request_dir(settings) / "provision.error"


def handoff_state_path(settings: CoreSettings) -> Path:
    return settings.data_dir / "service-handoff.json"


def handoff_snapshot(settings: CoreSettings) -> dict[str, str]:
    if not handoff_state_path(settings).is_file():
        status = (
            HANDOFF_NOT_STARTED
            if InstallStateStore(settings.install_state_path).read() != InstallState.COMPLETED
            else HANDOFF_PENDING
        )
        return {"status": status, "detail": ""}
    payload = json.loads(handoff_state_path(settings).read_text(encoding="utf-8"))
    status = str(payload.get("status") or HANDOFF_PENDING)
    detail = str(payload.get("detail") or "")
    if status not in {HANDOFF_NOT_STARTED, HANDOFF_PENDING, HANDOFF_FAILED, HANDOFF_READY}:
        status = HANDOFF_FAILED
        detail = "service handoff state is invalid"
    return {"status": status, "detail": detail}


def handoff_is_ready(settings: CoreSettings) -> bool:
    return handoff_snapshot(settings)["status"] == HANDOFF_READY


def mark_handoff(settings: CoreSettings, status: str, detail: str = "") -> dict[str, str]:
    if status not in {HANDOFF_PENDING, HANDOFF_FAILED, HANDOFF_READY}:
        raise ServiceControlError("service handoff status is invalid")
    payload = {"status": status, "detail": detail}
    write_json_atomic(handoff_state_path(settings), payload)
    os.chmod(handoff_state_path(settings), 0o640)
    return payload


def confirm_service_handoff(settings: CoreSettings) -> None:
    """Require web/admin on, installer off, and installer token revoked."""

    if installer_env_file().is_file():
        raise ServiceControlError("installer token has not been revoked")
    shared = env_file()
    if shared.is_file() and any(
        line.strip().startswith("PLAIK_INSTALLER_TOKEN=")
        for line in shared.read_text(encoding="utf-8").splitlines()
    ):
        raise ServiceControlError("installer token has not been revoked")
    if not _is_real_system_root():
        return
    for unit, must_run in (
        (WEB_SERVICE, True),
        (ADMIN_SERVICE, True),
        (INSTALLER_SERVICE, False),
    ):
        if not _service_exists(unit):
            continue
        active = _systemctl("is-active", "--quiet", unit, check=False)
        running = active is not None and active.returncode == 0
        if must_run and not running:
            raise ServiceControlError("web and admin services are not running")
        if not must_run and running:
            raise ServiceControlError("installer service is still running")


def _service_exists(name: str) -> bool:
    return systemd_dir().joinpath(name).is_file()


def _systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str] | None:
    if not _is_real_system_root() or shutil.which("systemctl") is None:
        return None
    completed = subprocess.run(
        ["systemctl", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if check and completed.returncode != 0:
        raise ServiceControlError("systemctl action failed")
    return completed


def _write_request(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    os.chmod(path, 0o600)


def _strip_env_key(path: Path, key: str) -> None:
    if not path.is_file():
        return
    kept: list[str] = []
    changed = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key}="):
            changed = True
            continue
        kept.append(line)
    if not changed:
        return
    path.write_text(("\n".join(kept) + ("\n" if kept else "")), encoding="utf-8")


def revoke_installer_token() -> None:
    """Remove the installer credential from installer-only and shared env files."""

    try:
        installer = installer_env_file()
        if installer.is_file():
            installer.unlink()
        _strip_env_key(env_file(), "PLAIK_INSTALLER_TOKEN")
    except OSError:
        geteuid = getattr(os, "geteuid", lambda: None)
        if geteuid() == 0:
            raise ServiceControlError("installer token could not be revoked") from None


def publish_public_runtime_secret(settings: CoreSettings) -> None:
    """Copy the runtime DB secret into the public-only publication directory."""

    try:
        secret = read_private_secret_for_publication(
            settings.data_dir / "secrets",
            "database/runtime",
            version="v1",
        )
    except SecretNotFoundError:
        return
    except SecretStoreError as error:
        raise ServiceControlError("runtime secret could not be published") from error
    try:
        publish_runtime_secret(web_secrets_dir(settings), secret)
    except SecretStoreError as error:
        raise ServiceControlError("runtime secret could not be published") from error


_PUBLIC_READ_FILES = (
    "install-state.json",
    "installer-config.json",
    "active-themes.json",
    "packages.json",
    "package-permissions.json",
    "settings.json",
)
_PUBLIC_READ_DIRS = ("installed-packages",)
_PRIVATE_NAMES = frozenset(
    {
        "secrets",
        "identities.json",
        "sessions.json",
        "audit.jsonl",
        "installer-operations.jsonl",
        "package-inbox",
        "package-transactions",
        "platform.sqlite3",
        "trusted-package-signing-keys.json",
        "trusted-release-signing-keys.json",
        "jobs.json",
        "maintenance-state.json",
        "installer-operation",
        "extension-operation",
        "extensions",
    }
)
_SKIP_HANDOFF = frozenset({"public", "run"})


def public_state_dir(settings: CoreSettings) -> Path:
    return settings.data_dir / "public"


def apply_identity_isolation(settings: CoreSettings) -> None:
    """Split installer/admin/public state so the data root is not shared-writable."""

    data = settings.data_dir
    data.mkdir(parents=True, exist_ok=True)
    public = public_state_dir(settings)
    run = request_dir(settings)
    public.mkdir(parents=True, exist_ok=True)
    run.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(public, 0o750)
        os.chmod(run, 0o770)
    except OSError:
        pass
    geteuid = getattr(os, "geteuid", lambda: None)
    if geteuid() != 0:
        return
    import pwd

    installer_name = os.environ.get("PLAIK_INSTALLER_USER", "plaik-installer")
    admin_name = os.environ.get("PLAIK_ADMIN_USER", "plaik-admin")
    public_name = os.environ.get("PLAIK_PUBLIC_USER", "plaik-public")
    try:
        installer = pwd.getpwnam(installer_name)
        admin = pwd.getpwnam(admin_name)
        public_user = pwd.getpwnam(public_name)
    except KeyError:
        raise ServiceControlError("required PLAIK service identities are missing") from None

    os.chown(data, 0, admin.pw_gid)
    os.chmod(data, 0o771)
    os.chown(run, 0, installer.pw_gid)
    os.chmod(run, 0o770)
    os.chown(public, public_user.pw_uid, public_user.pw_gid)
    os.chmod(public, 0o750)

    for child in data.iterdir():
        if child.name in _SKIP_HANDOFF:
            continue
        if child.name in _PRIVATE_NAMES:
            _chown_tree(child, admin.pw_uid, admin.pw_gid)
            _chmod_private(child)
            continue
        if child.name in _PUBLIC_READ_FILES and child.is_file():
            os.chown(child, admin.pw_uid, public_user.pw_gid)
            os.chmod(child, 0o640)
            continue
        if child.name in _PUBLIC_READ_DIRS:
            _chmod_public_readable_tree(child, admin.pw_uid, public_user.pw_gid)
            _try_setfacl_public_read(child, public_name)
            continue
        _chown_tree(child, admin.pw_uid, admin.pw_gid)


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    os.lchown(path, uid, gid)
    if path.is_symlink() or not path.is_dir():
        return
    for child in path.iterdir():
        _chown_tree(child, uid, gid)


def _chmod_private(path: Path) -> None:
    if path.is_symlink():
        return
    if path.is_dir():
        os.chmod(path, 0o700)
        for child in path.iterdir():
            _chmod_private(child)
        return
    if path.is_file():
        os.chmod(path, 0o600)


def _chmod_public_readable_tree(path: Path, uid: int, gid: int) -> None:
    if path.is_symlink():
        return
    os.lchown(path, uid, gid)
    if path.is_dir():
        os.chmod(path, 0o2750)
        for child in path.iterdir():
            _chmod_public_readable_tree(child, uid, gid)
        return
    if path.is_file():
        os.chmod(path, 0o640)


def _try_setfacl_public_read(path: Path, public_user: str) -> None:
    if shutil.which("setfacl") is None:
        return
    subprocess.run(
        [
            "setfacl",
            "-m",
            f"u:{public_user}:r-x",
            "-d",
            "-m",
            f"u:{public_user}:r-x",
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def finalize_installed_services(settings: CoreSettings | None = None) -> None:
    """Enable Web/Admin, disable the installer, and revoke installer credentials.

    Idempotent: repeated calls after a completed installation succeed.
    """

    runtime = settings or CoreSettings()
    state = InstallStateStore(runtime.install_state_path).read()
    if state != InstallState.COMPLETED:
        raise ServiceControlError("service finalization requires a completed installation")
    mark_handoff(runtime, HANDOFF_PENDING)
    try:
        apply_identity_isolation(runtime)
        publish_public_runtime_secret(runtime)
        if _is_real_system_root():
            for name in (WEB_SERVICE, ADMIN_SERVICE):
                if _service_exists(name):
                    _systemctl("enable", "--now", name)
            if _service_exists(INSTALLER_SERVICE):
                _systemctl("disable", "--now", INSTALLER_SERVICE, check=False)
        revoke_installer_token()
        confirm_service_handoff(runtime)
        mark_handoff(runtime, HANDOFF_READY)
        finalize_request_path(runtime).unlink(missing_ok=True)
    except Exception as error:
        detail = (
            str(error)
            if isinstance(error, ServiceControlError)
            else "service finalization failed"
        )
        mark_handoff(runtime, HANDOFF_FAILED, detail)
        raise ServiceControlError(detail) from None


def _validated_provision_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) != set(_PROVISION_FIELDS):
        raise ServiceControlError("provision request fields are invalid")
    if any("password" in str(key).casefold() for key in payload):
        raise ServiceControlError("provision request must not contain secrets")
    host = str(payload["host"])
    if host not in _LOOPBACK:
        raise ServiceControlError("database creation is limited to loopback PostgreSQL clusters")
    port = int(payload["port"])
    if not 1 <= port <= 65535:
        raise ServiceControlError("PostgreSQL port is invalid")
    return {
        "host": host,
        "port": port,
        "database": str(payload["database"]),
        "username": str(payload["username"]),
        "runtime_username": str(payload["runtime_username"]),
        "checkpoint_username": str(payload["checkpoint_username"]),
    }


def provision_database_from_request(settings: CoreSettings | None = None) -> None:
    runtime = settings or CoreSettings()
    path = provision_request_path(runtime)
    error_path = provision_error_path(runtime)
    error_path.unlink(missing_ok=True)
    try:
        payload = _validated_provision_payload(json.loads(path.read_text(encoding="utf-8")))
        secrets = LocalFileSecretProvider(runtime.secrets_dir)
        migrator = secrets.read("database/migrator", version="v1").get_secret_value()
        runtime_secret = secrets.read("database/runtime", version="v1").get_secret_value()
        checkpoint = secrets.read("database/checkpoint", version="v1").get_secret_value()
        provision_local_postgresql(
            port=payload["port"],
            database=payload["database"],
            migrator_role=payload["username"],
            runtime_role=payload["runtime_username"],
            checkpoint_role=payload["checkpoint_username"],
            migrator_password=migrator,
            runtime_password=runtime_secret,
            checkpoint_password=checkpoint,
            inventory=discover_host_inventory(runtime),
        )
        path.unlink(missing_ok=True)
    except Exception as error:
        detail = (
            str(error)
            if isinstance(error, (ServiceControlError, PostgreSQLProvisionError, SecretStoreError))
            else "database provisioning failed"
        )
        error_path.write_text(detail, encoding="utf-8")
        os.chmod(error_path, 0o600)
        raise ServiceControlError(detail) from None


def run_privileged_action(action: str, settings: CoreSettings | None = None) -> None:
    if action not in PRIVILEGED_ACTIONS:
        raise ServiceControlError("unsupported privileged action")
    runtime = settings or CoreSettings()
    if action == "finalize-services":
        finalize_installed_services(runtime)
        return
    provision_database_from_request(runtime)


def _path_unit(action: str) -> str:
    return (
        "plaik-finalize.path"
        if action == "finalize-services"
        else "plaik-provision.path"
    )


def _path_helper_available(action: str) -> bool:
    return _is_real_system_root() and _service_exists(_path_unit(action))


def _path_helper_active(action: str) -> bool:
    completed = _systemctl("is-active", "--quiet", _path_unit(action), check=False)
    return completed is not None and completed.returncode == 0


def request_service_finalization(
    settings: CoreSettings,
    *,
    wait_seconds: float = 20,
) -> None:
    """Ask the privileged helper to finish systemd handoff after COMPLETED."""

    state = InstallStateStore(settings.install_state_path).read()
    if state != InstallState.COMPLETED:
        raise ServiceControlError("service finalization requires a completed installation")
    marker = finalize_request_path(settings)
    mark_handoff(settings, HANDOFF_PENDING)
    _write_request(marker, "requested\n")
    helper = _path_helper_available("finalize-services")
    try:
        _dispatch_or_run("finalize-services", settings)
        if marker.exists() and helper:
            _wait_until(lambda: not marker.exists(), wait_seconds, "service finalization")
        if not handoff_is_ready(settings):
            snapshot = handoff_snapshot(settings)
            raise ServiceControlError(
                snapshot["detail"] or "service finalization did not complete"
            )
    except ServiceControlError as error:
        if handoff_snapshot(settings)["status"] != HANDOFF_FAILED:
            mark_handoff(settings, HANDOFF_FAILED, str(error))
        raise


def request_database_provision(
    settings: CoreSettings,
    payload: dict[str, Any],
    *,
    wait_seconds: float = 30,
) -> None:
    validated = _validated_provision_payload(payload)
    path = provision_request_path(settings)
    error_path = provision_error_path(settings)
    error_path.unlink(missing_ok=True)
    write_json_atomic(path, validated)
    os.chmod(path, 0o600)
    helper = _path_helper_available("provision-database")
    _dispatch_or_run("provision-database", settings)
    if path.exists() and helper:

        def finished() -> bool:
            return (not path.exists()) or error_path.exists()

        _wait_until(finished, wait_seconds, "database provisioning")
    if error_path.exists():
        detail = (
            error_path.read_text(encoding="utf-8").strip()
            or "database provisioning failed"
        )
        error_path.unlink(missing_ok=True)
        raise ServiceControlError(detail)
    if path.exists() and helper:
        raise ServiceControlError("database provisioning did not complete")


def _dispatch_or_run(action: str, settings: CoreSettings) -> None:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        run_privileged_action(action, settings)
        return
    if _path_helper_available(action):
        if not _path_helper_active(action):
            raise ServiceControlError("privileged path helper is not running")
        return
    run_privileged_action(action, settings)


def _wait_until(predicate, wait_seconds: float, label: str) -> None:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    if not predicate():
        raise ServiceControlError(f"{label} timed out")
