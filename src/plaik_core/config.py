"""Core runtime paths and immutable startup settings."""

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
_ADMIN_PATH = re.compile(r"^/[a-z][a-z0-9-]{2,63}$")
_RESERVED_ADMIN_PATHS = {"/admin", "/api", "/install", "/panel", "/vrnpap"}
_INSTALLER_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43,256}$")


def _source_repository_root() -> Path | None:
    """Recognize the checked-out PLAIK runtime repository layout."""

    source_directory = PACKAGE_ROOT.parent
    if source_directory.name != "src":
        return None
    candidate = source_directory.parent
    if not (candidate / "pyproject.toml").is_file():
        return None
    if not (candidate / "resources" / "themes" / "default" / "manifest.json").is_file():
        return None
    return candidate


_SOURCE_REPOSITORY_ROOT = _source_repository_root()
REPOSITORY_ROOT = _SOURCE_REPOSITORY_ROOT or PACKAGE_ROOT


def _installed_data_dir() -> Path:
    """Return a user-writable data directory for an installed distribution."""

    home = Path.home()
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = Path(local_app_data).expanduser() if local_app_data else home / "AppData" / "Local"
        return base / "PLAIK"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "PLAIK"
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        candidate = Path(xdg_data_home).expanduser()
        if candidate.is_absolute():
            return candidate / "plaik"
    return home / ".local" / "share" / "plaik"


def _configured_data_dir() -> Path | None:
    """Return the deployment-owned data root when explicitly configured."""

    value = os.environ.get("PLAIK_DATA_DIR")
    if not value:
        return None
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise ValueError("PLAIK_DATA_DIR must be an absolute path")
    return candidate


def _default_data_dir() -> Path:
    configured = _configured_data_dir()
    if configured is not None:
        return configured
    if _SOURCE_REPOSITORY_ROOT is not None:
        return _SOURCE_REPOSITORY_ROOT / "data"
    return _installed_data_dir()


def _default_themes_dir() -> Path:
    if _SOURCE_REPOSITORY_ROOT is not None:
        return _SOURCE_REPOSITORY_ROOT / "resources" / "themes"
    return PACKAGE_ROOT / "_bundled" / "themes"


def _default_modules_dir() -> Path:
    return _default_data_dir() / "extensions" / "modules"


def _installer_token_from_environment() -> str | None:
    """Load the bootstrap token without copying it into diagnostics or repr."""

    value = os.environ.get("PLAIK_INSTALLER_TOKEN")
    return value if value else None


def _admin_path_from_environment() -> str:
    return os.environ.get("PLAIK_ADMIN_PATH") or "/control-center"


@dataclass(frozen=True, slots=True)
class CoreSettings:
    data_dir: Path = field(default_factory=_default_data_dir)
    themes_dir: Path = field(default_factory=_default_themes_dir)
    modules_dir: Path = field(default_factory=_default_modules_dir)
    installer_token: str | None = field(
        default_factory=_installer_token_from_environment,
        repr=False,
    )
    allow_unsafe_local_installer: bool = False
    admin_path: str = field(default_factory=_admin_path_from_environment)

    def __post_init__(self) -> None:
        if not self.data_dir.is_absolute():
            raise ValueError("PLAIK data directory must be absolute")
        if not _ADMIN_PATH.fullmatch(self.admin_path):
            raise ValueError("invalid Admin path")
        if self.admin_path in _RESERVED_ADMIN_PATHS:
            raise ValueError("reserved Admin path cannot be configured")
        if self.installer_token is not None:
            if not _INSTALLER_TOKEN.fullmatch(self.installer_token):
                raise ValueError(
                    "installer token must be a 43-256 character URL-safe secret"
                )
            if len(set(self.installer_token)) < 12:
                raise ValueError("installer token does not meet the entropy floor")

    @property
    def install_state_path(self) -> Path:
        return self.data_dir / "install-state.json"

    @property
    def remote_control_path(self) -> Path:
        return self.data_dir / "remote-control.json"

    @property
    def remote_control_pairing_path(self) -> Path:
        return self.data_dir / "remote-control.pairing.json"

    @property
    def package_registry_path(self) -> Path:
        return self.data_dir / "packages.json"

    @property
    def package_permission_catalog_path(self) -> Path:
        return self.data_dir / "package-permissions.json"

    @property
    def active_themes_path(self) -> Path:
        return self.data_dir / "active-themes.json"

    @property
    def installer_config_path(self) -> Path:
        return self.data_dir / "installer-config.json"

    @property
    def scoped_settings_path(self) -> Path:
        return self.data_dir / "settings.json"

    @property
    def database_path(self) -> Path:
        return self.data_dir / "platform.sqlite3"

    @property
    def identity_registry_path(self) -> Path:
        return self.data_dir / "identities.json"

    @property
    def sessions_registry_path(self) -> Path:
        return self.data_dir / "sessions.json"

    @property
    def audit_log_path(self) -> Path:
        return self.data_dir / "audit.jsonl"

    @property
    def operation_journal_path(self) -> Path:
        return self.data_dir / "installer-operations.jsonl"

    @property
    def maintenance_state_path(self) -> Path:
        return self.data_dir / "maintenance-state.json"

    @property
    def jobs_registry_path(self) -> Path:
        return self.data_dir / "jobs.json"

    @property
    def package_artifacts_dir(self) -> Path:
        return self.data_dir / "packages"

    @property
    def package_inbox_dir(self) -> Path:
        return self.data_dir / "package-inbox"

    @property
    def installed_packages_dir(self) -> Path:
        return self.data_dir / "installed-packages"

    @property
    def package_transactions_dir(self) -> Path:
        return self.data_dir / "package-transactions"

    @property
    def trusted_package_signing_keys_path(self) -> Path:
        return self.data_dir / "trusted-package-signing-keys.json"

    @property
    def trusted_release_signing_keys_path(self) -> Path:
        return self.data_dir / "trusted-release-signing-keys.json"

    @property
    def install_operation_lock_path(self) -> Path:
        return self.data_dir / "installer-operation"

    @property
    def extension_operation_lock_path(self) -> Path:
        return self.data_dir / "extension-operation"

    @property
    def secrets_dir(self) -> Path:
        value = os.environ.get("PLAIK_SECRETS_DIR")
        if not value:
            return self.data_dir / "secrets"
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            raise ValueError("PLAIK_SECRETS_DIR must be an absolute path")
        return candidate

    @property
    def integrity_checkpoint_path(self) -> Path:
        return (
            self.data_dir.parent
            / f".{self.data_dir.name}-integrity"
            / "journal-heads.jsonl"
        )

    @property
    def backups_dir(self) -> Path:
        return self.data_dir.parent / f"{self.data_dir.name}-backups"

    @property
    def releases_dir(self) -> Path:
        return self.data_dir.parent / f"{self.data_dir.name}-releases"
