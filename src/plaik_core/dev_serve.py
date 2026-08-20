"""DEV-only source serving. Must not run against a production data directory."""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Iterable

from plaik_sdk.package_fs import load_package_manifest

from . import __version__
from .config import CoreSettings, _source_repository_root
from .installer import InstallState, InstallStateStore
from .packages import PackageRegistry, PackageStatus

_PRODUCTION_PREFIXES = (
    Path("/opt/plaik"),
    Path("/var/lib/plaik"),
    Path("/etc/plaik"),
    Path("/var/log/plaik"),
)
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
_OFFICIAL_MODULES = ("catalog", "inventory", "pricing", "search", "seo")


class DevServeError(RuntimeError):
    """A development serve command refused to start."""


def require_loopback_host(host: str) -> str:
    if host not in _LOOPBACK:
        raise DevServeError("dev server must bind loopback only")
    return host


def require_source_checkout() -> Path:
    root = _source_repository_root()
    if root is None:
        raise DevServeError("plaik dev serve requires an editable source checkout of plaik")
    return root


def _production_prefix(resolved: Path) -> Path | None:
    for prefix in _PRODUCTION_PREFIXES:
        if resolved == prefix or prefix in resolved.parents:
            return prefix
    return None


def refuse_production_path(path: Path, *, what: str = "PLAIK_DATA_DIR") -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_absolute():
        raise DevServeError(f"{what} must be absolute")
    prefix = _production_prefix(resolved)
    if prefix is not None:
        raise DevServeError(f"refusing to use production {what} under {prefix}")
    return resolved


def require_dev_data_dir(path: Path) -> Path:
    return refuse_production_path(path, what="PLAIK_DATA_DIR")


def watch_directories(plaik_root: Path) -> list[Path]:
    watched = [
        plaik_root / "src",
        plaik_root / "resources",
    ]
    workspace = plaik_root.parent
    sdk = workspace / "plaik-sdk" / "src"
    packages = workspace / "plaik-packages"
    if sdk.is_dir():
        watched.append(sdk)
    if packages.is_dir():
        watched.append(packages)
    return [path for path in watched if path.exists()]


def official_module_sources(packages_root: Path) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    for package_id in _OFFICIAL_MODULES:
        source = packages_root / package_id
        if (source / "extension.py").is_file() and (source / "manifest.json").is_file():
            mapping[package_id] = source
    return mapping


def mount_dev_package_sources(
    installed_packages_dir: Path, sources: dict[str, Path]
) -> list[str]:
    """DEV-only: accept bind-mounted source trees. Never create package symlinks.

    Core web projection rejects symlinked package roots. Live source on Linux is
    a bind mount (see plaik-internal ops/dev bind-packages). Missing targets are
    an operator error, not a reason to weaken that check.
    """

    installed_packages_dir = refuse_production_path(
        installed_packages_dir, what="installed-packages"
    )
    installed_packages_dir.mkdir(parents=True, exist_ok=True)
    mounted: list[str] = []
    for package_id, source in sources.items():
        target = installed_packages_dir / package_id
        source = source.resolve()
        if target.is_symlink():
            target.unlink()
        elif target.exists():
            marker = target / "extension.py"
            source_marker = source / "extension.py"
            if marker.is_file() and source_marker.is_file() and marker.samefile(source_marker):
                mounted.append(package_id)
                continue
            raise DevServeError(
                f"installed-packages/{package_id} exists and is not a DEV source mount"
            )
        raise DevServeError(
            f"installed-packages/{package_id} is not a bind-mounted source tree"
        )
    return mounted


def register_mounted_packages(settings: CoreSettings, mounted: Iterable[str]) -> list[str]:
    """Record mounted source packages as enabled. DEV-only; no signature bypass in production."""

    refuse_production_path(settings.data_dir, what="PLAIK_DATA_DIR")
    registry = PackageRegistry(
        settings.package_registry_path,
        core_version=__version__,
        protected_ids={"default"},
    )
    records = registry.records()
    to_install = []
    enabled: list[str] = []
    for package_id in mounted:
        package_root = settings.installed_packages_dir / package_id
        if package_root.is_symlink():
            raise DevServeError(
                f"installed-packages/{package_id} is a symlink; bind-mount source trees instead"
            )
        manifest = load_package_manifest(package_root)
        existing = records.get(package_id)
        if existing is None:
            to_install.append(manifest)
        elif existing.manifest.version != manifest.version:
            raise DevServeError(
                f"{package_id} registry version {existing.manifest.version} "
                f"does not match source {manifest.version}; resync required"
            )
    if to_install:
        registry.install_many(to_install)
        records = registry.records()
    for package_id in mounted:
        record = records[package_id]
        if record.status != PackageStatus.ENABLED:
            registry.enable(package_id)
        enabled.append(package_id)
        records = registry.records()
    return enabled


def bootstrap_reference_install(settings: CoreSettings, *, public_url: str) -> None:
    """Drive the existing installer contract in-process. Not a second installer."""

    try:
        from fastapi.testclient import TestClient
    except RuntimeError as error:
        raise DevServeError(
            "dev bootstrap needs httpx in the DEV virtualenv (pip install httpx)"
        ) from error

    from .applications import create_installer_app

    store = InstallStateStore(settings.install_state_path)
    if store.read() == InstallState.COMPLETED:
        return
    password = os.environ.get("PLAIK_DEV_ADMIN_PASSWORD") or secrets.token_urlsafe(18)
    unsafe = CoreSettings(
        data_dir=settings.data_dir,
        themes_dir=settings.themes_dir,
        system_fallback_dir=settings.system_fallback_dir,
        modules_dir=settings.modules_dir,
        allow_unsafe_local_installer=True,
        admin_path=settings.admin_path,
    )
    client = TestClient(create_installer_app(unsafe))

    def _require(response, label: str) -> None:
        if response.status_code != 200:
            raise DevServeError(f"dev bootstrap failed at {label}: {response.status_code}")

    _require(
        client.post("/api/install/transition", json={"target": "requirements_checked"}),
        "requirements_checked",
    )
    payload = {
        "profile": "platform",
        "mode": "development",
        "installation_id": "plaik-dev",
        "group_id": "dev-group",
        "store_id": "dev-store",
        "locale": "uk-UA",
        "timezone": "Europe/Kyiv",
        "public_url": public_url,
        "database": {"backend": "sqlite", "path": "platform.sqlite3"},
    }
    _require(client.put("/api/install/configuration", json=payload), "configuration")
    _require(
        client.post("/api/install/transition", json={"target": "configured"}),
        "configured",
    )
    _require(
        client.post("/api/install/transition", json={"target": "database_ready"}),
        "database_ready",
    )
    _require(
        client.post(
            "/api/install/admin",
            json={"email": "dev@example.test", "password": password},
        ),
        "admin",
    )
    for target in ("admin_ready", "theme_ready", "completed"):
        _require(
            client.post("/api/install/transition", json={"target": target}),
            target,
        )
    secret_path = settings.data_dir / "dev-admin-password.txt"
    secret_path.write_text(password + "\n", encoding="utf-8")
    secret_path.chmod(0o600)


def ensure_dev_package_trust_store(settings: CoreSettings) -> Path:
    """Create a DEV-only package trust snapshot so Admin can list the registry.

    Production installers provision this file as an operator-managed store.
    ``plaik dev serve`` is not a second installer; it only fills the gap when
    the file is missing so GET /api/admin/packages is not 503.
    """

    path = settings.trusted_package_signing_keys_path
    if path.is_file():
        return path
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from plaik_contracts import PackageType

    public = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "keys": {
                    "publisher.plaik-dev": {
                        "public_key": base64.urlsafe_b64encode(public)
                        .decode("ascii")
                        .rstrip("="),
                        "packages": ["*"],
                        "types": [item.value for item in PackageType],
                        "revoked": False,
                        "transfers_from": [],
                    }
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def prepare_dev_runtime(
    *,
    data_dir: Path,
    packages_root: Path | None,
    public_url: str,
    bootstrap: bool,
) -> tuple[CoreSettings, list[str], list[Path]]:
    plaik_root = require_source_checkout()
    data_dir = require_dev_data_dir(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    os.environ["PLAIK_DEV"] = "1"
    os.environ["PLAIK_DATA_DIR"] = str(data_dir)
    settings = CoreSettings(data_dir=data_dir)
    state = InstallStateStore(settings.install_state_path).read()
    if state != InstallState.COMPLETED:
        if not bootstrap:
            raise DevServeError(
                "dev data directory is not installed; rerun with --bootstrap once"
            )
        bootstrap_reference_install(settings, public_url=public_url)
    ensure_dev_package_trust_store(settings)
    mounted: list[str] = []
    if packages_root is not None and packages_root.is_dir():
        sources = official_module_sources(packages_root)
        mounted = mount_dev_package_sources(settings.installed_packages_dir, sources)
        if mounted:
            register_mounted_packages(settings, mounted)
    return settings, mounted, watch_directories(plaik_root)
