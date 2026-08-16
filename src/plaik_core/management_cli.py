"""Terminal-first installation and host lifecycle CLI for PLAIK.

The terminal installer is deliberately an adapter over the existing installer
HTTP contract.  The Core installer state machine remains the single authority
for configuration, migrations, administrator bootstrap, themes and sealing.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import pwd
import secrets
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import __version__
from .config import CoreSettings
from .host_inventory import HostInventory, discover_host_inventory
from .installer import InstallState, InstallStateStore
from .installer_config import DeploymentMode, InstallerConfigurationStore
from .postgresql_provision import (
    PostgreSQLProvisionError,
    generate_role_secret,
    provision_local_postgresql,
)
from .requirements import RequirementCheck, SystemRequirements
from .secret_store import LocalFileSecretProvider
from .service_control import (
    ServiceControlError,
    finalize_installed_services,
    installer_env_file,
    run_privileged_action,
)


class PlaikCLIError(RuntimeError):
    """A user-facing PLAIK management command failed safely."""


_SERVICE_USER = os.environ.get("PLAIK_SERVICE_USER", "plaik-installer")
_ADMIN_USER = os.environ.get("PLAIK_ADMIN_USER", "plaik-admin")
_PUBLIC_USER = os.environ.get("PLAIK_PUBLIC_USER", "plaik-public")
_INSTALLER_URL = os.environ.get("PLAIK_INSTALLER_URL", "http://127.0.0.1:8765")


def _system_root() -> Path:
    return Path(os.environ.get("PLAIK_SYSTEM_ROOT", "/")).resolve()


def _rooted(path: str) -> Path:
    root = _system_root()
    relative = Path(path.lstrip("/"))
    return Path("/") / relative if root == Path("/") else root / relative


def _runtime_dir() -> Path:
    return Path(os.environ.get("PLAIK_RUNTIME_DIR", str(_rooted("/opt/plaik"))))


def _config_dir() -> Path:
    return Path(os.environ.get("PLAIK_CONFIG_DIR", str(_rooted("/etc/plaik"))))


def _log_dir() -> Path:
    return Path(os.environ.get("PLAIK_LOG_DIR", str(_rooted("/var/log/plaik"))))


def _env_file() -> Path:
    return Path(os.environ.get("PLAIK_ENV_FILE", str(_config_dir() / "plaik.env")))


def _installer_env_file() -> Path:
    return Path(
        os.environ.get("PLAIK_INSTALLER_ENV_FILE", str(installer_env_file()))
    )


def _systemd_dir() -> Path:
    return Path(
        os.environ.get(
            "PLAIK_SYSTEMD_DIR",
            str(_rooted("/etc/systemd/system")),
        )
    )


def _command_path() -> Path:
    return Path(os.environ.get("PLAIK_COMMAND_PATH", str(_rooted("/usr/local/bin/plaik"))))


def _load_env_file(path: Path | None = None) -> dict[str, str]:
    selected = path or _env_file()
    values: dict[str, str] = {}
    if not selected.is_file():
        return values
    for raw_line in selected.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value.startswith(('"', "'")) and value.endswith(value[:1]):
            value = value[1:-1]
        values[key] = value
    return values


def _apply_install_environment() -> dict[str, str]:
    values = _load_env_file()
    for key, value in values.items():
        os.environ.setdefault(key, value)
    return values


def _is_real_system_root() -> bool:
    return _system_root() == Path("/")


def _require_root() -> None:
    if not _is_real_system_root():
        return
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        raise PlaikCLIError("this command requires root privileges")


def _run(
    command: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=check,
            text=True,
            input=input_text,
            capture_output=True,
            env=env,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            detail = (error.stderr or error.stdout or "").strip()
        else:
            detail = str(error)
        raise PlaikCLIError(
            f"command failed: {' '.join(command)}" + (f" ({detail})" if detail else "")
        ) from None


def _systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str] | None:
    if not _is_real_system_root() or shutil.which("systemctl") is None:
        return None
    return _run(["systemctl", *arguments], check=check)


def _service_exists(name: str) -> bool:
    if not _is_real_system_root():
        return False
    return (_systemd_dir() / name).is_file()


def _service_active(name: str) -> bool:
    if not _service_exists(name):
        return False
    result = _systemctl("is-active", "--quiet", name, check=False)
    return result is not None and result.returncode == 0


def _ensure_installer_service() -> None:
    if not _service_exists("plaik-installer.service"):
        return
    if not _service_active("plaik-installer.service"):
        _systemctl("enable", "--now", "plaik-installer.service")


def _finalize_services() -> None:
    try:
        finalize_installed_services()
    except ServiceControlError as error:
        raise PlaikCLIError(str(error)) from None


class _InstallerClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = None
        headers = {
            "Accept": "application/json",
            "X-Installer-Token": self.token,
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                detail = json.loads(raw.decode("utf-8")).get("detail")
            except Exception:
                detail = None
            raise PlaikCLIError(
                f"installer API rejected {method} {path}: {detail or error.reason}"
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise PlaikCLIError(
                f"installer API is unavailable at {self.base_url}: {error}"
            ) from None
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PlaikCLIError("installer API returned invalid JSON") from None
        if not isinstance(value, dict):
            raise PlaikCLIError("installer API returned an invalid response")
        return value

    def get(self, path: str) -> dict[str, Any]:
        return self.request("GET", path)

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request("POST", path, payload)

    def put(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request("PUT", path, payload)


def _installer_token() -> str:
    value = os.environ.get("PLAIK_INSTALLER_TOKEN")
    if not value:
        value = _load_env_file(_installer_env_file()).get("PLAIK_INSTALLER_TOKEN")
    if not value:
        value = _load_env_file(_env_file()).get("PLAIK_INSTALLER_TOKEN")
    if not value:
        raise PlaikCLIError(
            "installer token is unavailable; expected PLAIK_INSTALLER_TOKEN or "
            f"{_installer_env_file()}"
        )
    return value


def _prompt(label: str, *, default: str | None = None, secret: bool = False) -> str:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        value = (
            getpass.getpass(f"{label}{suffix}: ")
            if secret
            else input(f"{label}{suffix}: ")
        )
        value = value.strip()
        if value:
            return value
        if default is not None:
            return default
        print("Value is required.", file=sys.stderr)


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes"}
    return False


def _print_host_state(items: list[dict[str, object]] | tuple[RequirementCheck, ...]) -> None:
    print("Host state:")
    for item in items:
        if isinstance(item, RequirementCheck):
            print(f"  - {item.id}: {item.detail}")
            continue
        print(f"  - {item.get('id')}: {item.get('detail')}")


def _prompt_port(database: dict[str, Any], default: int, *, non_interactive: bool) -> int:
    if "port" in database:
        port_raw = database.get("port")
    elif non_interactive:
        port_raw = default
    else:
        port_raw = _prompt("PostgreSQL port", default=str(default))
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        raise PlaikCLIError("PostgreSQL port must be an integer") from None
    if port < 1 or port > 65535:
        raise PlaikCLIError("PostgreSQL port must be an integer")
    return port


def _yes_no(label: str, *, default: bool = True) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    while True:
        value = input(label + suffix + ": ").strip().casefold()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False


def _default_timezone() -> str:
    timezone = Path("/etc/timezone")
    if timezone.is_file():
        value = timezone.read_text(encoding="utf-8").strip()
        if value:
            return value
    return "UTC"


def _setup_document(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PlaikCLIError(f"cannot read setup configuration: {error}") from None
    if not isinstance(value, dict):
        raise PlaikCLIError("setup configuration must be a TOML document")
    return value


def _section(document: dict[str, Any], name: str) -> dict[str, Any]:
    value = document.get(name, {})
    if not isinstance(value, dict):
        raise PlaikCLIError(f"[{name}] must be a TOML table")
    return value


def _value(
    table: dict[str, Any],
    name: str,
    *,
    non_interactive: bool,
    label: str,
    default: str | None = None,
    secret: bool = False,
) -> str:
    configured = table.get(name)
    if configured is not None:
        if not isinstance(configured, str) or not configured.strip():
            raise PlaikCLIError(f"{name} must be non-empty text")
        return configured.strip()
    if non_interactive:
        if default is not None:
            return default
        raise PlaikCLIError(f"missing required setup value: {name}")
    return _prompt(label, default=default, secret=secret)


def _secret_from_environment_or_prompt(
    table: dict[str, Any],
    env_field: str,
    *,
    default_env: str,
    non_interactive: bool,
    label: str,
) -> str:
    env_name = table.get(env_field, default_env)
    if not isinstance(env_name, str) or not env_name:
        raise PlaikCLIError(f"{env_field} must name an environment variable")
    value = os.environ.get(env_name)
    if value:
        return value
    if non_interactive:
        raise PlaikCLIError(f"required secret environment variable is not set: {env_name}")
    return _prompt(label, secret=True)


def _service_user_exists() -> bool:
    try:
        pwd.getpwnam(_SERVICE_USER)
    except KeyError:
        return False
    return True


def _write_secret_as_runtime_user(
    settings: CoreSettings,
    *,
    key: str,
    version: str,
    value: str,
) -> None:
    geteuid = getattr(os, "geteuid", None)
    if (
        _is_real_system_root()
        and geteuid is not None
        and geteuid() == 0
        and _service_user_exists()
        and shutil.which("runuser") is not None
    ):
        environment = os.environ.copy()
        environment["PLAIK_DATA_DIR"] = str(settings.data_dir)
        command = [
            "runuser",
            "-u",
            _SERVICE_USER,
            "--",
            sys.executable,
            "-m",
            "plaik_core.management_cli",
            "_secret-write",
            "--key",
            key,
            "--version",
            version,
        ]
        _run(command, input_text=value, env=environment)
        return
    LocalFileSecretProvider(settings.secrets_dir).write(key, value, version=version)


def _postgresql_source(
    database: dict[str, Any],
    inventory: HostInventory,
    *,
    non_interactive: bool,
) -> str:
    configured = database.get("source")
    if isinstance(configured, str) and configured.strip():
        choice = configured.strip().casefold()
    elif _truthy(database.get("provision")):
        choice = "create"
    elif non_interactive:
        choice = "manual"
    else:
        if inventory.suggested_database:
            default = "use-detected"
        elif any(item.process == "postgres" for item in inventory.listeners):
            default = "create"
        else:
            default = "manual"
        choice = _prompt(
            "PostgreSQL source (use-detected/create/manual/restore)",
            default=default,
        ).casefold()
    if choice not in {"use-detected", "create", "manual", "restore"}:
        raise PlaikCLIError(
            "PostgreSQL source must be use-detected, create, manual or restore"
        )
    if choice == "restore":
        raise PlaikCLIError(
            "this installer does not restore PostgreSQL dumps; "
            "choose create for an empty database or use-detected for a found empty database"
        )
    return choice


def _postgresql_payload(
    settings: CoreSettings,
    database: dict[str, Any],
    *,
    mode: str,
    non_interactive: bool,
) -> dict[str, Any]:
    inventory = discover_host_inventory(settings)
    if not non_interactive:
        _print_host_state(inventory.observations())
    source = _postgresql_source(
        database, inventory, non_interactive=non_interactive
    )
    suggested = inventory.suggested_listener
    default_port = suggested.port if suggested is not None else 5432
    host = "127.0.0.1"
    port = default_port
    name = inventory.suggested_database or "plaik"
    if source == "use-detected":
        if inventory.suggested_database is None or suggested is None:
            raise PlaikCLIError(
                "no empty local PLAIK database was detected; choose create or manual"
            )
        host = suggested.host
        port = suggested.port
        name = inventory.suggested_database
        print(f"Using detected empty database {name} on {host}:{port}")
    elif source == "create":
        host = _value(
            database,
            "host",
            non_interactive=non_interactive,
            label="PostgreSQL host",
            default="127.0.0.1",
        )
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise PlaikCLIError(
                "database creation is limited to loopback PostgreSQL clusters"
            )
        port = _prompt_port(database, default_port, non_interactive=non_interactive)
        name = _value(
            database,
            "database",
            non_interactive=non_interactive,
            label="PostgreSQL database",
            default="plaik",
        )
    else:
        host = _value(
            database,
            "host",
            non_interactive=non_interactive,
            label="PostgreSQL host",
            default="127.0.0.1",
        )
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise PlaikCLIError(
                "PostgreSQL host must be loopback in this release"
            )
        port = _prompt_port(database, default_port, non_interactive=non_interactive)
        name = _value(
            database,
            "database",
            non_interactive=non_interactive,
            label="PostgreSQL database",
            default="plaik",
        )

    migrator = _value(
        database,
        "username",
        non_interactive=non_interactive,
        label="PostgreSQL migration user",
        default="plaik_migrator",
    )
    runtime_username = None
    checkpoint_username = None
    if source == "create":
        migrator_secret = generate_role_secret()
        runtime_secret = generate_role_secret()
        checkpoint_secret = generate_role_secret()
    else:
        migrator_secret = _secret_from_environment_or_prompt(
            database,
            "password_env",
            default_env="PLAIK_DB_MIGRATOR_PASSWORD",
            non_interactive=non_interactive,
            label="PostgreSQL migration password",
        )
        runtime_secret = None
        checkpoint_secret = None
    if mode == DeploymentMode.PRODUCTION.value:
        runtime_username = _value(
            database,
            "runtime_username",
            non_interactive=non_interactive,
            label="PostgreSQL runtime user",
            default="plaik_runtime",
        )
        checkpoint_username = _value(
            database,
            "checkpoint_username",
            non_interactive=non_interactive,
            label="PostgreSQL checkpoint user",
            default="plaik_checkpoint",
        )
        if source != "create":
            runtime_secret = _secret_from_environment_or_prompt(
                database,
                "runtime_password_env",
                default_env="PLAIK_DB_RUNTIME_PASSWORD",
                non_interactive=non_interactive,
                label="PostgreSQL runtime password",
            )
            checkpoint_secret = _secret_from_environment_or_prompt(
                database,
                "checkpoint_password_env",
                default_env="PLAIK_DB_CHECKPOINT_PASSWORD",
                non_interactive=non_interactive,
                label="PostgreSQL checkpoint password",
            )

    if source == "create":
        if mode != DeploymentMode.PRODUCTION.value:
            raise PlaikCLIError(
                "installer database creation requires production PostgreSQL identities"
            )
        try:
            provision_local_postgresql(
                port=port,
                database=name,
                migrator_role=migrator,
                runtime_role=runtime_username or "",
                checkpoint_role=checkpoint_username or "",
                migrator_password=migrator_secret,
                runtime_password=runtime_secret or "",
                checkpoint_password=checkpoint_secret or "",
                inventory=inventory,
            )
        except PostgreSQLProvisionError as error:
            raise PlaikCLIError(str(error)) from None
        print(f"Created empty PostgreSQL database {name} on {host}:{port}")

    _write_secret_as_runtime_user(
        settings,
        key="database/migrator",
        version="v1",
        value=migrator_secret,
    )
    payload: dict[str, Any] = {
        "backend": "postgresql",
        "host": host,
        "port": port,
        "database": name,
        "username": migrator,
        "credential": {
            "provider": "local",
            "key": "database/migrator",
            "version": "v1",
        },
        "ssl_mode": _value(
            database,
            "ssl_mode",
            non_interactive=non_interactive,
            label="PostgreSQL SSL mode",
            default="require" if mode == DeploymentMode.PRODUCTION.value else "prefer",
        ),
    }
    if mode == DeploymentMode.PRODUCTION.value:
        _write_secret_as_runtime_user(
            settings,
            key="database/runtime",
            version="v1",
            value=runtime_secret or "",
        )
        _write_secret_as_runtime_user(
            settings,
            key="database/checkpoint",
            version="v1",
            value=checkpoint_secret or "",
        )
        payload.update(
            {
                "runtime_username": runtime_username,
                "runtime_credential": {
                    "provider": "local",
                    "key": "database/runtime",
                    "version": "v1",
                },
                "checkpoint_username": checkpoint_username,
                "checkpoint_credential": {
                    "provider": "local",
                    "key": "database/checkpoint",
                    "version": "v1",
                },
            }
        )
    return payload


def _build_configuration(
    settings: CoreSettings,
    document: dict[str, Any],
    *,
    non_interactive: bool,
) -> dict[str, Any]:
    site = _section(document, "site")
    database = _section(document, "database")

    mode = _value(
        site,
        "mode",
        non_interactive=non_interactive,
        label="Deployment mode (production/development/reference)",
        default="production",
    ).casefold()
    if mode not in {item.value for item in DeploymentMode}:
        raise PlaikCLIError("deployment mode must be production, development or reference")

    if mode == DeploymentMode.PRODUCTION.value:
        domain = _value(
            site,
            "domain",
            non_interactive=non_interactive,
            label="Domain",
        ).strip().rstrip(".")
        if "://" in domain or "/" in domain:
            raise PlaikCLIError("domain must be a hostname without scheme or path")
        public_url = f"https://{domain}"
    else:
        public_url = _value(
            site,
            "public_url",
            non_interactive=non_interactive,
            label="Public URL",
            default="http://127.0.0.1:8080",
        )

    backend_default = "postgresql" if mode == DeploymentMode.PRODUCTION.value else "sqlite"
    backend = _value(
        database,
        "backend",
        non_interactive=non_interactive,
        label="Database backend (postgresql/sqlite)",
        default=backend_default,
    ).casefold()

    installation_id = str(site.get("installation_id") or f"plaik-{secrets.token_hex(6)}")
    group_id = str(site.get("group_id") or "default-group")
    store_id = str(site.get("store_id") or "default-store")
    locale = _value(
        site,
        "locale",
        non_interactive=non_interactive,
        label="Locale",
        default="en-US",
    )
    timezone = _value(
        site,
        "timezone",
        non_interactive=non_interactive,
        label="Timezone",
        default=_default_timezone(),
    )

    if backend == "sqlite":
        if mode == DeploymentMode.PRODUCTION.value:
            raise PlaikCLIError("SQLite is not allowed for production installations")
        database_payload: dict[str, Any] = {
            "backend": "sqlite",
            "path": _value(
                database,
                "path",
                non_interactive=non_interactive,
                label="SQLite path relative to PLAIK data directory",
                default="platform.sqlite3",
            ),
        }
    elif backend == "postgresql":
        database_payload = _postgresql_payload(
            settings,
            database,
            mode=mode,
            non_interactive=non_interactive,
        )
    else:
        raise PlaikCLIError("database backend must be postgresql or sqlite")

    return {
        "schema_version": 1,
        "profile": str(site.get("profile") or "standard"),
        "mode": mode,
        "installation_id": installation_id,
        "group_id": group_id,
        "store_id": store_id,
        "locale": locale,
        "timezone": timezone,
        "public_url": public_url,
        "database": database_payload,
        "sealed": False,
        "sealed_at": None,
    }


def _admin_credentials(
    document: dict[str, Any],
    *,
    non_interactive: bool,
) -> tuple[str, str]:
    admin = _section(document, "admin")
    email = _value(
        admin,
        "email",
        non_interactive=non_interactive,
        label="Administrator email",
    )
    password = _secret_from_environment_or_prompt(
        admin,
        "password_env",
        default_env="PLAIK_ADMIN_PASSWORD",
        non_interactive=non_interactive,
        label="Administrator password",
    )
    return email, password


def _transition(client: _InstallerClient, state: InstallState) -> None:
    client.post("/api/install/transition", {"target": state.value})


def _print_requirements(client: _InstallerClient) -> None:
    report = client.get("/api/install/requirements")
    checks = report.get("checks", [])
    print("System requirements:")
    for check in checks:
        marker = "✓" if check.get("passed") else "✗"
        print(f"  {marker} {check.get('id')}: {check.get('detail')}")
    observations = report.get("observations") or []
    if observations:
        _print_host_state(observations)
    if report.get("passed") is not True:
        raise PlaikCLIError("system requirements are not satisfied")


def _setup(args: argparse.Namespace) -> int:
    _apply_install_environment()
    _require_root()
    settings = CoreSettings()
    local_state = InstallStateStore(settings.install_state_path).read()
    if local_state == InstallState.COMPLETED:
        print("PLAIK is already configured.")
        _finalize_services()
        return 0

    _ensure_installer_service()
    client = _InstallerClient(args.installer_url, _installer_token())
    document = _setup_document(args.config)

    while True:
        state = InstallState(client.get("/api/install/state")["state"])
        if state == InstallState.NOT_STARTED:
            _print_requirements(client)
            _transition(client, InstallState.REQUIREMENTS_CHECKED)
            continue
        if state == InstallState.REQUIREMENTS_CHECKED:
            existing = client.get("/api/install/configuration").get("configuration")
            if existing is None:
                configuration = _build_configuration(
                    settings,
                    document,
                    non_interactive=args.non_interactive,
                )
                client.put("/api/install/configuration", configuration)
            _transition(client, InstallState.CONFIGURED)
            continue
        if state == InstallState.CONFIGURED:
            print("Preparing database...")
            _transition(client, InstallState.DATABASE_READY)
            continue
        if state == InstallState.DATABASE_READY:
            email, password = _admin_credentials(
                document,
                non_interactive=args.non_interactive,
            )
            client.post("/api/install/admin", {"email": email, "password": password})
            _transition(client, InstallState.ADMIN_READY)
            continue
        if state == InstallState.ADMIN_READY:
            _transition(client, InstallState.THEME_READY)
            continue
        if state == InstallState.THEME_READY:
            _transition(client, InstallState.COMPLETED)
            continue
        if state == InstallState.COMPLETED:
            break
        raise PlaikCLIError(f"unsupported installer state: {state}")

    _finalize_services()
    configuration = InstallerConfigurationStore(settings.installer_config_path).require()
    print("PLAIK setup completed.")
    print(f"Public URL: {configuration.public_url}")
    return 0


def _status(args: argparse.Namespace) -> int:
    _apply_install_environment()
    settings = CoreSettings()
    state = InstallStateStore(settings.install_state_path).read()
    configuration = InstallerConfigurationStore(settings.installer_config_path).read()
    payload = {
        "version": __version__,
        "state": state.value,
        "data_dir": str(settings.data_dir),
        "public_url": str(configuration.public_url) if configuration else None,
        "services": {
            "installer": _service_active("plaik-installer.service"),
            "web": _service_active("plaik-web.service"),
            "admin": _service_active("plaik-admin.service"),
        },
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        print(f"PLAIK {payload['version']}")
        print(f"State: {payload['state']}")
        print(f"Data: {payload['data_dir']}")
        if payload["public_url"]:
            print(f"URL: {payload['public_url']}")
        if _is_real_system_root():
            for name, active in payload["services"].items():
                print(f"{name}: {'active' if active else 'inactive'}")
    return 0


def _doctor(_args: argparse.Namespace) -> int:
    _apply_install_environment()
    settings = CoreSettings()
    report = SystemRequirements(settings).inspect()
    failed = False
    for check in report.checks:
        marker = "✓" if check.passed else "✗"
        print(f"{marker} {check.id}: {check.detail}")
        failed = failed or not check.passed
    if report.observations:
        _print_host_state(report.observations)
    state = InstallStateStore(settings.install_state_path).read()
    if state == InstallState.COMPLETED and _is_real_system_root():
        for service in ("plaik-web.service", "plaik-admin.service"):
            active = _service_active(service)
            print(f"{'✓' if active else '✗'} {service}: {'active' if active else 'inactive'}")
            failed = failed or not active
    return 1 if failed else 0


def _remove_tree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.exists():
        shutil.rmtree(path)


def _chown_runtime_data(path: Path) -> None:
    if not _is_real_system_root() or not _service_user_exists():
        return
    account = pwd.getpwnam(_SERVICE_USER)
    os.chown(path, account.pw_uid, account.pw_gid)


def _reset(args: argparse.Namespace) -> int:
    _apply_install_environment()
    _require_root()
    settings = CoreSettings()
    configuration = InstallerConfigurationStore(settings.installer_config_path).read()
    if (
        configuration is not None
        and configuration.mode == DeploymentMode.PRODUCTION
        and not args.force_production
    ):
        raise PlaikCLIError(
            "refusing to reset a production installation without --force-production"
        )
    if not args.yes:
        answer = input("Reset PLAIK installation state and local data? Type RESET: ").strip()
        if answer != "RESET":
            raise PlaikCLIError("reset cancelled")

    for service in ("plaik-web.service", "plaik-admin.service", "plaik-installer.service"):
        if _service_exists(service):
            _systemctl("disable", "--now", service, check=False)

    _remove_tree(settings.data_dir)
    _remove_tree(settings.integrity_checkpoint_path.parent)
    if args.purge_backups:
        _remove_tree(settings.backups_dir)
        _remove_tree(settings.releases_dir)
    settings.data_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    _chown_runtime_data(settings.data_dir)

    if _service_exists("plaik-installer.service"):
        _systemctl("enable", "--now", "plaik-installer.service")
    print("PLAIK reset to NOT_STARTED.")
    return 0


def _uninstall_plan(settings: CoreSettings, *, purge: bool) -> list[Path]:
    paths = [
        _runtime_dir(),
        _command_path(),
        _systemd_dir() / "plaik-installer.service",
        _systemd_dir() / "plaik-web.service",
        _systemd_dir() / "plaik-admin.service",
        _systemd_dir() / "plaik-finalize.service",
        _systemd_dir() / "plaik-finalize.path",
        _systemd_dir() / "plaik-provision.service",
        _systemd_dir() / "plaik-provision.path",
    ]
    if purge:
        paths.extend(
            [
                _config_dir(),
                settings.data_dir,
                settings.integrity_checkpoint_path.parent,
                settings.backups_dir,
                settings.releases_dir,
                _log_dir(),
            ]
        )
    # Preserve order but remove duplicates caused by custom test layouts.
    return list(dict.fromkeys(path.resolve(strict=False) for path in paths))


def _uninstall(args: argparse.Namespace) -> int:
    _apply_install_environment()
    _require_root()
    settings = CoreSettings()
    paths = _uninstall_plan(settings, purge=args.purge)

    print("PLAIK uninstall plan:")
    for path in paths:
        print(f"  remove {path}")
    if not args.purge:
        print(f"  preserve {settings.data_dir}")
        print(f"  preserve {_config_dir()}")
    print("  external PostgreSQL databases and roles are never removed")

    if args.dry_run:
        return 0
    if not args.yes:
        required = "DELETE" if args.purge else "UNINSTALL"
        answer = input(f"Type {required} to continue: ").strip()
        if answer != required:
            raise PlaikCLIError("uninstall cancelled")

    for service in ("plaik-web.service", "plaik-admin.service", "plaik-installer.service"):
        if _service_exists(service):
            _systemctl("disable", "--now", service, check=False)

    # Remove the command symlink last among executable entry points.  The current
    # Python process has already imported all code needed to finish cleanup.
    for path in paths:
        _remove_tree(path)
    _systemctl("daemon-reload", check=False)

    if args.purge and _is_real_system_root():
        for account in (_SERVICE_USER, _ADMIN_USER, _PUBLIC_USER):
            try:
                pwd.getpwnam(account)
            except KeyError:
                continue
            if shutil.which("userdel"):
                _run(["userdel", account], check=False)
    print("PLAIK uninstalled." + (" Local PLAIK data purged." if args.purge else " Data preserved."))
    return 0


def _secret_write(args: argparse.Namespace) -> int:
    _apply_install_environment()
    value = sys.stdin.read()
    if not value:
        raise PlaikCLIError("secret input is empty")
    settings = CoreSettings()
    LocalFileSecretProvider(settings.secrets_dir).write(
        args.key,
        value,
        version=args.version,
    )
    return 0


def _privileged(args: argparse.Namespace) -> int:
    _apply_install_environment()
    _require_root()
    try:
        run_privileged_action(args.action)
    except ServiceControlError as error:
        raise PlaikCLIError(str(error)) from None
    return 0


def _print_installer_token(args: argparse.Namespace) -> int:
    _apply_install_environment()
    _require_root()
    path = _installer_env_file()
    if not path.is_file():
        raise PlaikCLIError(
            "installer token is not available; Stage 2 may already be complete"
        )
    token = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("PLAIK_INSTALLER_TOKEN="):
            token = line.split("=", 1)[1].strip()
            break
    if not token:
        raise PlaikCLIError("installer token is not available")
    print(token)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="plaik")
    parser.add_argument("--version", action="version", version=f"PLAIK {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    setup = commands.add_parser("setup", help="configure a newly installed PLAIK runtime")
    setup.add_argument("--config", type=Path, help="TOML setup configuration")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--installer-url", default=_INSTALLER_URL)
    setup.set_defaults(handler=_setup)

    status = commands.add_parser("status", help="show installation and service state")
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=_status)

    doctor = commands.add_parser("doctor", help="run local installation diagnostics")
    doctor.set_defaults(handler=_doctor)

    reset = commands.add_parser("reset", help="reset installation state but keep runtime installed")
    reset.add_argument("--yes", action="store_true")
    reset.add_argument("--force-production", action="store_true")
    reset.add_argument("--purge-backups", action="store_true")
    reset.set_defaults(handler=_reset)

    uninstall = commands.add_parser("uninstall", help="remove the PLAIK system runtime")
    uninstall.add_argument("--purge", action="store_true")
    uninstall.add_argument("--yes", action="store_true")
    uninstall.add_argument("--dry-run", action="store_true")
    uninstall.set_defaults(handler=_uninstall)

    hidden = commands.add_parser("_secret-write", help=argparse.SUPPRESS)
    hidden.add_argument("--key", required=True)
    hidden.add_argument("--version", required=True)
    hidden.set_defaults(handler=_secret_write)

    privileged = commands.add_parser("privileged", help=argparse.SUPPRESS)
    privileged.add_argument(
        "action",
        choices=("finalize-services", "provision-database"),
    )
    privileged.set_defaults(handler=_privileged)

    token = commands.add_parser(
        "installer-token",
        help="print the one-time Stage 2 installer token (root only)",
    )
    token.set_defaults(handler=_print_installer_token)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except PlaikCLIError as error:
        print(f"plaik: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("plaik: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
