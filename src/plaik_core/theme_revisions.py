"""Theme API v1 revisioned configuration: draft, validate, prepare, preview, publish."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from plaik_contracts import (
    PageTemplate,
    ThemeConfigurationRevision,
    ThemeManifest,
    ThemePreset,
    ThemeSettingsSchema,
    ThemeSettingsValues,
    validate_theme_settings,
)
from plaik_contracts.theme_configuration import (
    MAX_PRESETS,
    RevisionStatus,
    ThemeCacheIdentity,
    require_revision_id,
)
from plaik_contracts.theme_composition import (
    MAX_DEFINITION_BYTES,
    MAX_PAGE_TEMPLATE_BYTES,
)

from .slots import SlotRegistry
from .storage import exclusive_file_lock, read_json, write_json_atomic
from .theme_composition import (
    ThemeCompositionError,
    complete_composition_catalog,
    load_theme_composition_catalog,
    resolve_page_template,
)
from .themes import ThemeRegistry, _validate_store_id


MAX_SETTINGS_SCHEMA_BYTES = MAX_DEFINITION_BYTES
MAX_PRESET_BYTES = MAX_PAGE_TEMPLATE_BYTES


class ThemeRevisionError(ValueError):
    """Theme configuration revision is invalid or cannot change state."""


@dataclass(frozen=True, slots=True)
class ThemeConfigurationCatalog:
    schema: ThemeSettingsSchema | None
    presets: dict[str, ThemePreset]


class _StoreRevisionState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = 1
    published: str | None = None
    previous: str | None = None


class ThemeRevisionStore:
    """Atomic per-store revision index and immutable prepared revision files."""

    def __init__(self, path: Path, *, theme_registry: ThemeRegistry) -> None:
        self.path = Path(path)
        self.theme_registry = theme_registry

    def draft(
        self,
        store_id: str,
        *,
        theme_id: str,
        settings: ThemeSettingsValues | dict | None = None,
        pages: dict[str, PageTemplate] | None = None,
        preset_id: str | None = None,
        now: datetime | None = None,
    ) -> ThemeConfigurationRevision:
        store_id = _validate_store_id(store_id)
        manifest = self._require_theme(theme_id)
        revision = ThemeConfigurationRevision(
            revision_id=secrets.token_hex(8),
            theme_id=manifest.id,
            theme_version=manifest.version,
            theme_api=manifest.theme_api or 1,
            status=RevisionStatus.DRAFT,
            settings=_coerce_settings(settings),
            pages=dict(pages or {}),
            preset_id=preset_id,
            created_at=_as_utc(now or datetime.now(UTC)),
        )
        self._write_revision(store_id, revision)
        return revision

    def update_draft(
        self,
        store_id: str,
        revision_id: str,
        *,
        settings: ThemeSettingsValues | dict | None = None,
        pages: dict[str, PageTemplate] | None = None,
        preset_id: str | None = None,
    ) -> ThemeConfigurationRevision:
        store_id = _validate_store_id(store_id)
        revision = self.get(store_id, revision_id)
        if revision.status is not RevisionStatus.DRAFT:
            raise ThemeRevisionError("only draft revisions can be updated")
        updated = revision.model_copy(
            update={
                "settings": _coerce_settings(settings)
                if settings is not None
                else revision.settings,
                "pages": dict(pages) if pages is not None else revision.pages,
                "preset_id": preset_id if preset_id is not None else revision.preset_id,
            }
        )
        self._write_revision(store_id, updated)
        return updated

    def validate(self, store_id: str, revision_id: str) -> ThemeConfigurationRevision:
        store_id = _validate_store_id(store_id)
        revision = self.get(store_id, revision_id)
        if revision.status is RevisionStatus.PREPARED:
            raise ThemeRevisionError("prepared revisions are immutable")
        resolved = self._require_valid(store_id, revision)
        updated = resolved.model_copy(update={"status": RevisionStatus.VALIDATED})
        self._write_revision(store_id, updated)
        return updated

    def prepare(
        self,
        store_id: str,
        revision_id: str,
        *,
        slot_registry: SlotRegistry | None = None,
        now: datetime | None = None,
    ) -> ThemeConfigurationRevision:
        store_id = _validate_store_id(store_id)
        revision = self.get(store_id, revision_id)
        if revision.status is RevisionStatus.PREPARED:
            return revision
        if revision.status is not RevisionStatus.VALIDATED:
            raise ThemeRevisionError("revision must be validated before prepare")
        resolved = self._require_valid(store_id, revision, slot_registry=slot_registry)
        updated = resolved.model_copy(
            update={
                "status": RevisionStatus.PREPARED,
                "prepared_at": _as_utc(now or datetime.now(UTC)),
            }
        )
        self._write_revision(store_id, updated)
        return updated

    def preview(self, store_id: str, revision_id: str) -> ThemeConfigurationRevision:
        store_id = _validate_store_id(store_id)
        revision = self.get(store_id, revision_id)
        if revision.status is not RevisionStatus.PREPARED:
            raise ThemeRevisionError("preview requires a prepared revision")
        return revision

    def publish(self, store_id: str, revision_id: str) -> ThemeConfigurationRevision:
        store_id = _validate_store_id(store_id)
        require_revision_id(revision_id)
        with exclusive_file_lock(self._state_path(store_id)):
            revision = self.get(store_id, revision_id)
            if revision.status is not RevisionStatus.PREPARED:
                raise ThemeRevisionError("publish requires a prepared revision")
            state = self._read_state(store_id)
            if state.published == revision.revision_id:
                return revision
            self._write_state(
                store_id,
                _StoreRevisionState(
                    published=revision.revision_id,
                    previous=state.published,
                ),
            )
            return revision

    def rollback(self, store_id: str) -> ThemeConfigurationRevision:
        store_id = _validate_store_id(store_id)
        with exclusive_file_lock(self._state_path(store_id)):
            state = self._read_state(store_id)
            if state.previous is None:
                raise ThemeRevisionError("no previous published revision")
            previous = self.get(store_id, state.previous)
            self._write_state(
                store_id,
                _StoreRevisionState(
                    published=previous.revision_id,
                    previous=state.published,
                ),
            )
            return previous

    def published(self, store_id: str) -> ThemeConfigurationRevision | None:
        store_id = _validate_store_id(store_id)
        state = self._read_state(store_id)
        if state.published is None:
            return None
        return self.get(store_id, state.published)

    def get(self, store_id: str, revision_id: str) -> ThemeConfigurationRevision:
        store_id = _validate_store_id(store_id)
        require_revision_id(revision_id)
        path = self._revision_path(store_id, revision_id)
        try:
            payload = read_json(path, None)
        except (OSError, ValueError) as error:
            raise ThemeRevisionError("revision is missing or unsafe") from error
        if payload is None:
            raise ThemeRevisionError("revision is missing or unsafe")
        try:
            return ThemeConfigurationRevision.model_validate(payload)
        except ValidationError as error:
            raise ThemeRevisionError("revision is invalid") from error

    def cache_identity(
        self,
        *,
        store_id: str,
        revision: ThemeConfigurationRevision,
        locale: str,
        page_type: str,
        slot_registry: SlotRegistry,
    ) -> ThemeCacheIdentity:
        store_id = _validate_store_id(store_id)
        return ThemeCacheIdentity(
            store_id=store_id,
            theme_id=revision.theme_id,
            theme_version=revision.theme_version,
            revision_id=revision.revision_id,
            locale=locale,
            page_type=page_type,
            slots_generation=slots_generation(slot_registry),
        )

    def _require_valid(
        self,
        store_id: str,
        revision: ThemeConfigurationRevision,
        *,
        slot_registry: SlotRegistry | None = None,
    ) -> ThemeConfigurationRevision:
        manifest = self._require_theme(revision.theme_id)
        if manifest.version != revision.theme_version:
            raise ThemeRevisionError("revision theme version does not match")
        if (manifest.theme_api or 1) != revision.theme_api:
            raise ThemeRevisionError("revision Theme API version does not match")
        directory = self.theme_registry.path(manifest.id)
        catalog = load_theme_configuration_catalog(directory, manifest)
        settings = revision.settings
        pages = dict(revision.pages)
        if revision.preset_id is not None:
            preset = catalog.presets.get(revision.preset_id)
            if preset is None:
                raise ThemeRevisionError("unknown preset")
            settings = ThemeSettingsValues(
                values={**preset.settings, **revision.settings.values},
                responsive=revision.settings.responsive,
            )
            pages = {**preset.pages, **revision.pages}
        if catalog.schema is None:
            if settings.values or settings.responsive:
                raise ThemeRevisionError("theme settings schema is missing")
            resolved_settings = ThemeSettingsValues()
        else:
            try:
                resolved_settings = validate_theme_settings(settings, catalog.schema)
            except ValueError as error:
                raise ThemeRevisionError(str(error)) from error
        composition = load_theme_composition_catalog(directory, manifest)
        if manifest.parent:
            parent = self._require_theme(manifest.parent)
            composition = complete_composition_catalog(
                composition,
                load_theme_composition_catalog(
                    self.theme_registry.path(parent.id), parent
                ),
            )
        else:
            composition = complete_composition_catalog(composition)
        chain_slots = set(manifest.slots)
        if manifest.parent:
            chain_slots.update(self._require_theme(manifest.parent).slots)
        for page_type, page in pages.items():
            try:
                resolve_page_template(
                    page_type,
                    page,
                    composition,
                    chain_slots=chain_slots,
                    slot_registry=slot_registry,
                    theme_id=manifest.id,
                )
            except ThemeCompositionError as error:
                raise ThemeRevisionError(str(error)) from error
        return revision.model_copy(update={"settings": resolved_settings, "pages": pages})

    def _require_theme(self, theme_id: str) -> ThemeManifest:
        self.theme_registry.discover()
        theme = self.theme_registry.get(theme_id)
        if theme is None:
            raise ThemeRevisionError("theme is unavailable")
        if theme.theme_api is None:
            raise ThemeRevisionError("theme configuration requires Theme API v1")
        return theme

    def _state_path(self, store_id: str) -> Path:
        return self.path / store_id / "state.json"

    def _revision_path(self, store_id: str, revision_id: str) -> Path:
        return self.path / store_id / "revisions" / f"{revision_id}.json"

    def _read_state(self, store_id: str) -> _StoreRevisionState:
        payload = read_json(self._state_path(store_id), {"version": 1})
        try:
            return _StoreRevisionState.model_validate(payload)
        except ValidationError as error:
            raise ThemeRevisionError("revision index is invalid") from error

    def _write_state(self, store_id: str, state: _StoreRevisionState) -> None:
        write_json_atomic(self._state_path(store_id), state.model_dump(mode="json"))

    def _write_revision(
        self, store_id: str, revision: ThemeConfigurationRevision
    ) -> None:
        path = self._revision_path(store_id, revision.revision_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        if revision.status is RevisionStatus.PREPARED and path.exists():
            existing = self.get(store_id, revision.revision_id)
            if existing.status is RevisionStatus.PREPARED:
                raise ThemeRevisionError("prepared revisions are immutable")
        write_json_atomic(path, revision.model_dump(mode="json"))


def load_theme_configuration_catalog(
    directory: Path, manifest: ThemeManifest
) -> ThemeConfigurationCatalog:
    directory = Path(directory)
    if not manifest.settings_schema and not manifest.presets:
        _reject_unexpected_configuration(directory)
        return ThemeConfigurationCatalog(None, {})
    schema = None
    if manifest.settings_schema:
        try:
            payload = _load_json(
                directory, Path("settings.json"), max_bytes=MAX_SETTINGS_SCHEMA_BYTES
            )
            schema = ThemeSettingsSchema.model_validate(payload)
        except (ThemeCompositionError, ValidationError) as error:
            raise ThemeRevisionError("theme settings schema is invalid") from error
    elif (directory / "settings.json").exists():
        raise ThemeRevisionError("undeclared configuration file")
    presets: dict[str, ThemePreset] = {}
    for preset_id in manifest.presets:
        try:
            payload = _load_json(
                directory,
                Path("presets") / f"{preset_id}.json",
                max_bytes=MAX_PRESET_BYTES,
            )
            preset = ThemePreset.model_validate(payload)
        except (ThemeCompositionError, ValidationError) as error:
            raise ThemeRevisionError("theme preset is invalid") from error
        if preset.id != preset_id:
            raise ThemeRevisionError("preset id does not match file")
        presets[preset_id] = preset
    _reject_undeclared_presets(directory / "presets", set(manifest.presets))
    if len(presets) > MAX_PRESETS:
        raise ThemeRevisionError("too many presets")
    return ThemeConfigurationCatalog(schema, presets)


def validate_candidate_configuration(
    directory: Path, manifest: ThemeManifest
) -> None:
    load_theme_configuration_catalog(directory, manifest)


def validate_installed_configuration(
    themes: dict[str, ThemeManifest], locations: dict[str, Path]
) -> None:
    for theme_id, manifest in themes.items():
        load_theme_configuration_catalog(locations[theme_id], manifest)


def slots_generation(slot_registry: SlotRegistry) -> str:
    items: list[str] = []
    for slot_id in sorted(slot_registry.allowed_slots):
        for binding in slot_registry.bindings(slot_id):
            items.append(
                f"{binding.slot}:{binding.module_id}:{binding.template}:{binding.position}"
            )
    digest = hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()
    return digest[:32]


def _coerce_settings(value: ThemeSettingsValues | dict | None) -> ThemeSettingsValues:
    if value is None:
        return ThemeSettingsValues()
    if isinstance(value, ThemeSettingsValues):
        return value
    try:
        return ThemeSettingsValues.model_validate(value)
    except ValidationError as error:
        raise ThemeRevisionError("theme settings are invalid") from error


def _load_json(directory: Path, relative: Path, *, max_bytes: int) -> dict:
    from .theme_composition import _read_declared_json

    payload, _size = _read_declared_json(directory, relative, max_bytes=max_bytes)
    return payload


def _reject_unexpected_configuration(directory: Path) -> None:
    for relative in (Path("settings.json"), Path("presets")):
        if (Path(directory) / relative).exists():
            raise ThemeRevisionError("undeclared configuration file")


def _reject_undeclared_presets(directory: Path, declared: set[str]) -> None:
    path = Path(directory)
    if not path.exists():
        if declared:
            raise ThemeRevisionError("theme preset is invalid")
        return
    extra: list[str] = []
    for child in sorted(path.iterdir()):
        if child.is_symlink() or not child.is_file():
            raise ThemeRevisionError("theme preset is invalid")
        if not child.name.endswith(".json"):
            extra.append(child.name)
            continue
        preset_id = child.name[: -len(".json")]
        if preset_id not in declared:
            extra.append(preset_id)
    if extra:
        raise ThemeRevisionError("undeclared configuration file")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
