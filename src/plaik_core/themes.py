"""Theme discovery, activation and template resolution."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath

from pydantic import BaseModel, ConfigDict, ValidationError

from plaik_contracts import PackageManifest, ThemeManifest

from .storage import exclusive_file_lock, read_json, write_json_atomic


_STORE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_HOOK_NAME = re.compile(r"^[a-z][A-Za-z0-9]*$")
_THEME_JSON_FIELDS = {"parent", "layouts", "assets", "hooks", "theme_api", "slots"}
_MAX_THEME_PRESENTATION_BYTES = 256 * 1024
_WINDOWS_RESERVED_BASENAMES = {
    "aux",
    "con",
    "conin$",
    "conout$",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


class ActiveThemeSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    active: str
    previous: str | None = None
    updated_at: datetime | None = None


class ThemeRegistry:
    def __init__(
        self,
        root: Path,
        additional_roots: tuple[Path, ...] = (),
        enabled_package_ids: Callable[[], set[str]] | None = None,
    ) -> None:
        if enabled_package_ids is not None and not callable(enabled_package_ids):
            raise TypeError("enabled package id provider must be callable")
        self.root = Path(root)
        self.roots = (self.root, *(Path(item) for item in additional_roots))
        self.enabled_package_ids = enabled_package_ids
        self._themes: dict[str, ThemeManifest] = {}
        self._locations: dict[str, Path] = {}

    def _parse_theme_directory(self, directory: Path) -> ThemeManifest | None:
        directory = Path(directory)
        manifest_path = directory / "manifest.json"
        if not directory.is_dir() or not manifest_path.is_file():
            return None
        if directory.is_symlink() or manifest_path.is_symlink():
            raise ValueError("theme discovery does not follow symlinks")
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("type") != "theme":
            return None
        try:
            manifest = ThemeManifest.model_validate(raw)
        except ValidationError:
            package = PackageManifest.model_validate(raw)
            theme_path = directory / "theme.json"
            if not theme_path.is_file() or theme_path.is_symlink():
                raise ValueError(
                    f"installed theme {package.id!r} is missing theme.json"
                ) from None
            theme_data = json.loads(theme_path.read_text(encoding="utf-8"))
            if not isinstance(theme_data, dict) or set(theme_data) - _THEME_JSON_FIELDS:
                raise ValueError(
                    f"installed theme {package.id!r} has invalid theme.json"
                )
            manifest = ThemeManifest.model_validate(
                {
                    "id": package.id,
                    "type": "theme",
                    "version": package.version,
                    "name": package.name,
                    "core": package.core,
                    **theme_data,
                }
            )
        _safe_package_id(manifest.id)
        _validate_theme_presentation_paths(manifest)
        if manifest.id != directory.name:
            raise ValueError(
                f"theme directory {directory.name!r} does not match manifest id {manifest.id!r}"
            )
        return manifest

    def _read_theme_manifest(self, theme_id: str) -> ThemeManifest | None:
        """Load a parent from registry roots, never from the discover cache."""

        for root in self.roots:
            parsed = self._parse_theme_directory(Path(root) / theme_id)
            if parsed is not None:
                return parsed
        return None

    def discover(self) -> dict[str, ThemeManifest]:
        themes: dict[str, ThemeManifest] = {}
        locations: dict[str, Path] = {}
        enabled_ids: set[str] | None = None
        if self.enabled_package_ids is not None:
            supplied_ids = self.enabled_package_ids()
            if not isinstance(supplied_ids, (set, frozenset)) or not all(
                isinstance(package_id, str) for package_id in supplied_ids
            ):
                raise ValueError("enabled package id provider returned invalid data")
            enabled_ids = set(supplied_ids)
        for root_index, root in enumerate(self.roots):
            if not root.is_dir():
                continue
            for directory in sorted(root.iterdir()):
                if (
                    root_index > 0
                    and enabled_ids is not None
                    and directory.name not in enabled_ids
                ):
                    continue
                manifest_path = directory / "manifest.json"
                if directory.is_dir() and manifest_path.is_file():
                    manifest = self._parse_theme_directory(directory)
                    if manifest is None:
                        continue
                    if manifest.id in themes:
                        raise ValueError(f"duplicate theme id: {manifest.id}")
                    themes[manifest.id] = manifest
                    locations[manifest.id] = directory
        self._themes = themes
        self._locations = locations
        self._validate_inheritance()
        return dict(themes)

    def validate_candidate(
        self,
        path: Path,
        package_manifest: PackageManifest,
        available_theme_ids: set[str],
    ) -> ThemeManifest:
        """Validate one staged theme without scanning unrelated installations."""

        candidate = Path(path)
        package = PackageManifest.model_validate(package_manifest)
        if package.type != "theme":
            raise ValueError("theme candidate requires a theme package manifest")
        _safe_package_id(package.id)
        if candidate.is_symlink() or not candidate.is_dir():
            raise ValueError("theme candidate must be a regular directory")
        if not isinstance(available_theme_ids, (set, frozenset)) or not all(
            isinstance(theme_id, str) for theme_id in available_theme_ids
        ):
            raise ValueError("available theme ids are invalid")
        theme_path = candidate / "theme.json"
        if theme_path.is_symlink() or not theme_path.is_file():
            raise ValueError(f"installed theme {package.id!r} is missing theme.json")
        try:
            if theme_path.stat().st_size > _MAX_THEME_PRESENTATION_BYTES:
                raise ValueError("theme presentation manifest is too large")
            theme_data = json.loads(theme_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("theme presentation manifest is invalid") from error
        if not isinstance(theme_data, dict) or set(theme_data) - _THEME_JSON_FIELDS:
            raise ValueError("theme presentation manifest is invalid")
        try:
            manifest = ThemeManifest.model_validate(
                {
                    "id": package.id,
                    "type": "theme",
                    "version": package.version,
                    "name": package.name,
                    "core": package.core,
                    **theme_data,
                }
            )
        except ValidationError as error:
            raise ValueError("theme presentation manifest is invalid") from error
        if manifest.parent is not None:
            _safe_package_id(manifest.parent)
            if manifest.parent not in available_theme_ids:
                raise ValueError(
                    f"theme {manifest.id} requires missing parent {manifest.parent}"
                )
            parent = self._read_theme_manifest(manifest.parent)
            if parent is None:
                raise ValueError(
                    f"theme {manifest.id} requires missing parent {manifest.parent}"
                )
            if parent.parent is not None:
                raise ValueError(
                    f"theme {manifest.id} inheritance depth exceeds 1"
                )
        if len(manifest.layouts) != len(set(manifest.layouts)):
            raise ValueError("theme candidate contains duplicate layouts")
        for layout in manifest.layouts:
            _validate_safe_path_segment(layout, error="invalid theme layout")
            layout_file = _contained_file(
                candidate / "templates" / "layouts",
                Path(f"{layout}.html"),
            )
            if layout_file is None:
                raise ValueError(f"theme layout file is missing: {layout}")
        if len(manifest.hooks) != len(set(manifest.hooks)) or any(
            not _HOOK_NAME.fullmatch(hook) for hook in manifest.hooks
        ):
            raise ValueError("theme candidate contains invalid hooks")
        asset_paths = (*manifest.assets.css, *manifest.assets.js)
        if len(asset_paths) != len(set(asset_paths)):
            raise ValueError("theme candidate contains duplicate assets")
        for asset in manifest.assets.css:
            self._validate_candidate_asset(candidate, asset, suffix=".css")
        for asset in manifest.assets.js:
            self._validate_candidate_asset(candidate, asset, suffix=".js")
        return manifest

    @staticmethod
    def _validate_candidate_asset(candidate: Path, value: str, *, suffix: str) -> None:
        relative = _safe_relative_path(value, error="invalid theme asset path")
        if relative.suffix.casefold() != suffix:
            raise ValueError("theme asset has an invalid type")
        if _contained_file(candidate, relative) is None:
            raise ValueError(f"theme asset file is missing: {value}")

    def get(self, theme_id: str) -> ThemeManifest | None:
        return self._themes.get(theme_id)

    def require_default(self) -> ThemeManifest:
        themes = self.discover()
        try:
            return themes["default"]
        except KeyError as error:
            raise RuntimeError("bundled default theme is missing") from error

    def path(self, theme_id: str) -> Path:
        if not self._themes:
            self.discover()
        try:
            return self._locations[theme_id]
        except KeyError as error:
            raise KeyError(f"theme not found: {theme_id}") from error

    def list(self) -> list[dict]:
        return [theme.model_dump(mode="json") for theme in self._themes.values()]

    def inheritance_chain(self, theme_id: str) -> list[ThemeManifest]:
        if not self._themes:
            self.discover()
        chain: list[ThemeManifest] = []
        current = self._themes.get(theme_id)
        if current is None:
            raise KeyError(f"theme not found: {theme_id}")
        while current is not None:
            chain.append(current)
            current = self._themes.get(current.parent) if current.parent else None
        return chain

    def _validate_inheritance(self) -> None:
        for theme in self._themes.values():
            seen: set[str] = set()
            current = theme
            while current.parent:
                if current.parent not in self._themes:
                    raise ValueError(
                        f"theme {current.id} requires missing parent {current.parent}"
                    )
                if current.parent in seen or current.parent == theme.id:
                    raise ValueError(f"theme inheritance cycle involving {theme.id}")
                parent = self._themes[current.parent]
                if parent.parent is not None:
                    raise ValueError(
                        f"theme {theme.id} inheritance depth exceeds 1"
                    )
                seen.add(current.parent)
                current = parent


class ActiveThemeStore:
    """Atomic pre-database store; later migrated to platform settings in DB."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def get(self, store_id: str) -> str:
        return self.selection(store_id).active

    def selection(self, store_id: str) -> ActiveThemeSelection:
        store_id = _validate_store_id(store_id)
        data = self._read()
        value = data["stores"].get(store_id)
        if value is None:
            return ActiveThemeSelection(active="default")
        if isinstance(value, str):
            return ActiveThemeSelection(active=value)
        return ActiveThemeSelection.model_validate(value)

    def set(
        self,
        store_id: str,
        theme_id: str,
        *,
        now: datetime | None = None,
    ) -> ActiveThemeSelection:
        store_id = _validate_store_id(store_id)
        theme_id = _safe_package_id(theme_id)
        timestamp = _as_utc(now or datetime.now(UTC))
        with exclusive_file_lock(self.path):
            data = self._read()
            current_value = data["stores"].get(store_id)
            current = (
                ActiveThemeSelection(active="default")
                if current_value is None
                else ActiveThemeSelection(active=current_value)
                if isinstance(current_value, str)
                else ActiveThemeSelection.model_validate(current_value)
            )
            if current.active == theme_id:
                return current
            updated = ActiveThemeSelection(
                active=theme_id,
                previous=current.active,
                updated_at=timestamp,
            )
            data["stores"][store_id] = updated.model_dump(mode="json")
            self._write(data)
            return updated

    def rollback(
        self,
        store_id: str,
        *,
        now: datetime | None = None,
    ) -> ActiveThemeSelection:
        store_id = _validate_store_id(store_id)
        timestamp = _as_utc(now or datetime.now(UTC))
        with exclusive_file_lock(self.path):
            data = self._read()
            current_value = data["stores"].get(store_id)
            if current_value is None or isinstance(current_value, str):
                raise RuntimeError("no previous theme is available")
            current = ActiveThemeSelection.model_validate(current_value)
            if current.previous is None:
                raise RuntimeError("no previous theme is available")
            updated = ActiveThemeSelection(
                active=current.previous,
                previous=current.active,
                updated_at=timestamp,
            )
            data["stores"][store_id] = updated.model_dump(mode="json")
            self._write(data)
            return updated

    def restore(self, store_id: str, selection: ActiveThemeSelection) -> None:
        store_id = _validate_store_id(store_id)
        selection = ActiveThemeSelection.model_validate(selection)
        with exclusive_file_lock(self.path):
            data = self._read()
            if (
                selection.active == "default"
                and selection.previous is None
                and selection.updated_at is None
            ):
                data["stores"].pop(store_id, None)
            else:
                data["stores"][store_id] = selection.model_dump(mode="json")
            self._write(data)

    def _read(self) -> dict:
        data = read_json(self.path, {"version": 2, "stores": {}})
        if not isinstance(data, dict) or not isinstance(data.get("stores"), dict):
            raise RuntimeError("active theme registry is malformed")
        version = data.get("version", 1)
        if version not in {1, 2}:
            raise RuntimeError("unsupported active theme registry version")
        return {"version": 2, "stores": dict(data["stores"])}

    def _write(self, data: dict) -> None:
        write_json_atomic(
            self.path,
            {"version": 2, "stores": dict(sorted(data["stores"].items()))},
        )


class ThemeManager:
    def __init__(self, registry: ThemeRegistry, state: ActiveThemeStore) -> None:
        self.registry = registry
        self.state = state

    def active(self, store_id: str = "default") -> ThemeManifest:
        self.registry.discover()
        theme_id = self.state.get(store_id)
        theme = self.registry.get(theme_id)
        if theme is None:
            raise KeyError(f"theme not found: {theme_id}")
        return theme

    def activate(self, theme_id: str, store_id: str = "default") -> ThemeManifest:
        self.registry.require_default()
        theme = self.registry.get(theme_id)
        if theme is None:
            raise KeyError(f"theme not found: {theme_id}")
        self.state.set(store_id, theme_id)
        return theme

    def rollback(self, store_id: str = "default") -> ThemeManifest:
        selection = self.state.selection(store_id)
        if selection.previous is None:
            raise RuntimeError("no previous theme is available")
        self.registry.require_default()
        previous = self.registry.get(selection.previous)
        if previous is None:
            raise RuntimeError("previous theme is no longer installed")
        self.registry.inheritance_chain(previous.id)
        self.state.rollback(store_id)
        return previous


class TemplateResolver:
    """PrestaShop-style lookup without allowing path traversal."""

    def __init__(
        self,
        registry: ThemeRegistry,
        modules_root: Path,
        additional_modules_roots: tuple[Path, ...] = (),
    ) -> None:
        self.registry = registry
        self.modules_root = Path(modules_root)
        self.modules_roots = (
            self.modules_root,
            *(Path(item) for item in additional_modules_roots),
        )

    def resolve_module_template(
        self,
        *,
        theme_id: str,
        module_id: str,
        template: str,
        system_fallback: Path | None = None,
    ) -> Path | None:
        safe_template = self._safe_relative(template)
        safe_module_id = self._safe_segment(module_id)
        for theme in self.registry.inheritance_chain(theme_id):
            candidate = self._contained_file(
                self.registry.path(theme.id) / "modules" / safe_module_id,
                safe_template,
            )
            if candidate is not None:
                return candidate
        for root in self.modules_roots:
            module_template = self._contained_file(
                root / safe_module_id / "web",
                safe_template,
            )
            if module_template is not None:
                return module_template
        if system_fallback and system_fallback.is_file():
            return system_fallback
        return None

    @staticmethod
    def _safe_segment(value: str) -> str:
        _validate_safe_path_segment(value, error="invalid package path segment")
        return value

    @staticmethod
    def _safe_relative(value: str) -> Path:
        return _safe_relative_path(value, error="invalid relative template path")

    @staticmethod
    def _contained_file(base: Path, relative: Path) -> Path | None:
        return _contained_file(base, relative)


def _validate_store_id(value: str) -> str:
    if not isinstance(value, str) or not _STORE_ID.fullmatch(value):
        raise ValueError("invalid theme store id")
    return value


def _safe_package_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 64
        or value == "system-fallback"
        or not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", value)
    ):
        raise ValueError("invalid theme id")
    _validate_safe_path_segment(value, error="invalid theme id")
    return value


def _validate_safe_path_segment(value: str, *, error: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or ":" in value
        or len(value) > 255
        or value.rstrip(" .") != value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError(error)
    windows_path = PureWindowsPath(value)
    if windows_path.is_absolute() or windows_path.drive or len(windows_path.parts) != 1:
        raise ValueError(error)
    device_basename = value.split(".", 1)[0].rstrip(" .").casefold()
    if device_basename in _WINDOWS_RESERVED_BASENAMES:
        raise ValueError(error)


def _safe_relative_path(value: str, *, error: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError(error)
    windows_path = PureWindowsPath(value)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or not path.parts
        or path.as_posix() != value
    ):
        raise ValueError(error)
    for part in path.parts:
        _validate_safe_path_segment(part, error=error)
    return Path(*path.parts)


def _contained_file(base: Path, relative: Path) -> Path | None:
    try:
        resolved_base = base.resolve(strict=False)
        candidate = (base / relative).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not candidate.is_relative_to(resolved_base) or not candidate.is_file():
        return None
    return candidate


def _validate_theme_presentation_paths(manifest: ThemeManifest) -> None:
    if len(manifest.layouts) != len(set(manifest.layouts)):
        raise ValueError("theme contains duplicate layouts")
    for layout in manifest.layouts:
        _validate_safe_path_segment(layout, error="invalid theme layout")
    if len(manifest.hooks) != len(set(manifest.hooks)) or any(
        not _HOOK_NAME.fullmatch(hook) for hook in manifest.hooks
    ):
        raise ValueError("theme contains invalid hooks")
    asset_paths = (*manifest.assets.css, *manifest.assets.js)
    if len(asset_paths) != len(set(asset_paths)):
        raise ValueError("theme contains duplicate assets")
    for asset in manifest.assets.css:
        relative = _safe_relative_path(asset, error="invalid theme asset path")
        if relative.suffix.casefold() != ".css":
            raise ValueError("theme asset has an invalid type")
    for asset in manifest.assets.js:
        relative = _safe_relative_path(asset, error="invalid theme asset path")
        if relative.suffix.casefold() != ".js":
            raise ValueError("theme asset has an invalid type")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("theme timestamp must be timezone-aware")
    return value.astimezone(UTC)
