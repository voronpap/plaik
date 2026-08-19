"""Persistent projection of enabled package declarations into Web hooks."""

from __future__ import annotations

import stat
import threading
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath

from plaik_contracts import PackageManifest, PackageType

from .hooks import HookBinding, HookRegistry
from .packages import PackageRecord, PackageStatus
from .slots import SlotBinding, SlotRegistry


class WebExtensionError(RuntimeError):
    """An enabled package cannot be projected into the Web safely."""


def validate_staged_web(
    staging: Path,
    manifest: PackageManifest,
    *,
    allowed_hooks: set[str] | frozenset[str],
    allowed_slots: set[str] | frozenset[str] = frozenset(),
) -> None:
    """Reject invalid hook/slot declarations before a package filesystem commit."""

    if manifest.type not in {PackageType.MODULE, PackageType.INTEGRATION}:
        if manifest.web.hooks or manifest.web.slots:
            raise WebExtensionError("package type cannot declare web hooks or slots")
        return
    for declaration in manifest.web.hooks:
        if declaration.hook not in allowed_hooks:
            raise WebExtensionError("package declares an unknown web hook")
        _require_regular_template(
            Path(staging) / "web",
            declaration.template,
        )
    for declaration in manifest.web.slots:
        if declaration.slot not in allowed_slots:
            raise WebExtensionError("package declares an unknown web slot")
        _require_regular_template(
            Path(staging) / "web",
            declaration.template,
        )


def project_enabled_hooks(
    records: Mapping[str, PackageRecord],
    installed_packages_dir: Path,
    *,
    allowed_hooks: set[str] | frozenset[str],
) -> HookRegistry:
    """Rebuild the process-local hook registry solely from durable package state."""

    registry = HookRegistry(set(allowed_hooks))
    root = Path(installed_packages_dir)
    for package_id, record in sorted(records.items()):
        if record.status != PackageStatus.ENABLED or record.manifest.type not in {
            PackageType.MODULE,
            PackageType.INTEGRATION,
        }:
            continue
        package_root = root / package_id
        if package_root.is_symlink() or not package_root.is_dir():
            raise WebExtensionError("enabled package files are unavailable")
        for declaration in record.manifest.web.hooks:
            if declaration.hook not in allowed_hooks:
                raise WebExtensionError(
                    "enabled package declares an unknown web hook"
                )
            _require_regular_template(
                package_root / "web",
                declaration.template,
            )
            registry.register(
                HookBinding(
                    hook=declaration.hook,
                    module_id=package_id,
                    template=declaration.template,
                    position=declaration.position,
                )
            )
    return registry


def project_enabled_slots(
    records: Mapping[str, PackageRecord],
    installed_packages_dir: Path,
    *,
    allowed_slots: set[str] | frozenset[str],
) -> SlotRegistry:
    """Rebuild the process-local slot registry solely from durable package state."""

    registry = SlotRegistry(set(allowed_slots))
    root = Path(installed_packages_dir)
    for package_id, record in sorted(records.items()):
        if record.status != PackageStatus.ENABLED or record.manifest.type not in {
            PackageType.MODULE,
            PackageType.INTEGRATION,
        }:
            continue
        package_root = root / package_id
        if package_root.is_symlink() or not package_root.is_dir():
            raise WebExtensionError("enabled package files are unavailable")
        for declaration in record.manifest.web.slots:
            if declaration.slot not in allowed_slots:
                raise WebExtensionError(
                    "enabled package declares an unknown web slot"
                )
            _require_regular_template(
                package_root / "web",
                declaration.template,
            )
            registry.register(
                SlotBinding(
                    slot=declaration.slot,
                    module_id=package_id,
                    template=declaration.template,
                    position=declaration.position,
                )
            )
    return registry


def web_projection_fingerprint(
    records: Mapping[str, PackageRecord],
) -> tuple[tuple[str, str, str], ...]:
    """Durable identity of the enabled-package set that drives Web SSR."""

    return tuple(
        sorted(
            (package_id, record.status.value, record.manifest.version)
            for package_id, record in records.items()
        )
    )


class LiveWebProjection:
    """Rebuild process-local hook/slot registries when durable package state changes.

    Admin and Web are separate processes. ``deactivate_owner`` on Admin's Core
    registries cannot update Web SSR. Web re-reads ``PackageRegistry.records()``
    and rebuilds from ENABLED packages only.
    """

    def __init__(
        self,
        *,
        records: Callable[[], Mapping[str, PackageRecord]],
        installed_packages_dir: Path,
        allowed_hooks: set[str] | frozenset[str],
        allowed_slots: set[str] | frozenset[str] = frozenset(),
    ) -> None:
        self._records = records
        self._installed_packages_dir = Path(installed_packages_dir)
        self._allowed_hooks = frozenset(allowed_hooks)
        self._allowed_slots = frozenset(allowed_slots)
        self._lock = threading.Lock()
        self._fingerprint: tuple[tuple[str, str, str], ...] | None = None
        self._hooks = HookRegistry(set(self._allowed_hooks))
        self._slots = SlotRegistry(set(self._allowed_slots))
        self.version = 0
        self.refresh()

    @property
    def hook_registry(self) -> HookRegistry:
        return self._hooks

    @property
    def slot_registry(self) -> SlotRegistry:
        return self._slots

    def capture(self) -> tuple[HookRegistry, SlotRegistry, int]:
        with self._lock:
            records = self._records()
            fingerprint = web_projection_fingerprint(records)
            if fingerprint != self._fingerprint:
                hooks = project_enabled_hooks(
                    records,
                    self._installed_packages_dir,
                    allowed_hooks=self._allowed_hooks,
                )
                slots = project_enabled_slots(
                    records,
                    self._installed_packages_dir,
                    allowed_slots=self._allowed_slots,
                )
                self._hooks = hooks
                self._slots = slots
                self._fingerprint = fingerprint
                self.version += 1
            return self._hooks, self._slots, self.version

    def refresh(self) -> int:
        return self.capture()[2]


def _require_regular_template(root: Path, relative: str) -> Path:
    relative_path = PurePosixPath(relative)
    if (
        not isinstance(relative, str)
        or not relative
        or relative_path.is_absolute()
        or relative_path.as_posix() != relative
        or "\\" in relative
        or ":" in relative
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        raise WebExtensionError("declared web template is unsafe")

    current = Path(root)
    try:
        root_metadata = current.lstat()
    except OSError:
        raise WebExtensionError("declared web template is missing") from None
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise WebExtensionError("declared web template is unsafe")

    parts = relative_path.parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError:
            raise WebExtensionError("declared web template is missing") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise WebExtensionError("declared web template is unsafe")
        if index == len(parts) - 1:
            if not stat.S_ISREG(metadata.st_mode):
                raise WebExtensionError("declared web template is unsafe")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise WebExtensionError("declared web template is unsafe")
    return current
