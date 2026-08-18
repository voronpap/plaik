"""Theme API v1 page/section/block composition validation and resolution.

Slots resolve through the existing SlotRegistry. This module does not create a
second slot path and does not rewrite hooks into slots.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import ValidationError

from plaik_contracts import (
    BlockDefinition,
    PageTemplate,
    SectionDefinition,
    ThemeManifest,
)
from plaik_contracts.theme_composition import (
    MAX_COMPOSITION_BYTES,
    MAX_DEFINITION_BYTES,
    MAX_PAGE_TEMPLATE_BYTES,
    BlockInstance,
    reject_block_type_cycles,
    validate_settings_against_schema,
)

from .slots import SlotRegistry

MAX_JSON_NESTING_DEPTH = 32
MAX_COMPOSITION_TEMPLATE_BYTES = 64 * 1024


class ThemeCompositionError(ValueError):
    """Theme composition is invalid and must fail closed."""


@dataclass(frozen=True, slots=True)
class BoundBlockDefinition:
    theme_id: str
    definition: BlockDefinition


@dataclass(frozen=True, slots=True)
class BoundSectionDefinition:
    theme_id: str
    definition: SectionDefinition


@dataclass(frozen=True, slots=True)
class ThemeCompositionCatalog:
    sections: dict[str, BoundSectionDefinition]
    blocks: dict[str, BoundBlockDefinition]
    pages: dict[str, PageTemplate]

    def empty(self) -> bool:
        return not (self.sections or self.blocks or self.pages)


@dataclass(frozen=True, slots=True)
class ResolvedBlock:
    id: str
    type: str
    theme_id: str
    template: str
    settings: dict[str, str | int | bool]
    slots: tuple[str, ...]
    blocks: tuple[ResolvedBlock, ...]


@dataclass(frozen=True, slots=True)
class ResolvedSection:
    id: str
    type: str
    theme_id: str
    template: str
    settings: dict[str, str | int | bool]
    slots: tuple[str, ...]
    blocks: tuple[ResolvedBlock, ...]


@dataclass(frozen=True, slots=True)
class ResolvedPage:
    page_type: str
    theme_id: str
    schema_version: int
    sections: tuple[ResolvedSection, ...]


def load_theme_composition_catalog(
    directory: Path, manifest: ThemeManifest
) -> ThemeCompositionCatalog:
    """Load declared composition files for one theme directory."""

    directory = Path(directory)
    if not (manifest.page_templates or manifest.sections or manifest.blocks):
        _reject_unexpected_composition_dirs(directory)
        return ThemeCompositionCatalog({}, {}, {})

    total_bytes = 0
    sections: dict[str, BoundSectionDefinition] = {}
    for type_id in manifest.sections:
        payload, size = _read_declared_json(
            directory,
            Path("sections") / f"{type_id}.json",
            max_bytes=MAX_DEFINITION_BYTES,
        )
        total_bytes = _add_bytes(total_bytes, size)
        try:
            definition = SectionDefinition.model_validate(payload)
        except ValidationError as error:
            raise ThemeCompositionError("section definition is invalid") from error
        if definition.type != type_id:
            raise ThemeCompositionError("section type does not match file")
        total_bytes = _add_bytes(
            total_bytes, _require_template_file(directory, definition.template)
        )
        sections[type_id] = BoundSectionDefinition(manifest.id, definition)
    _reject_undeclared_json(directory / "sections", set(manifest.sections))

    blocks: dict[str, BoundBlockDefinition] = {}
    for type_id in manifest.blocks:
        payload, size = _read_declared_json(
            directory,
            Path("blocks") / f"{type_id}.json",
            max_bytes=MAX_DEFINITION_BYTES,
        )
        total_bytes = _add_bytes(total_bytes, size)
        try:
            definition = BlockDefinition.model_validate(payload)
        except ValidationError as error:
            raise ThemeCompositionError("block definition is invalid") from error
        if definition.type != type_id:
            raise ThemeCompositionError("block type does not match file")
        total_bytes = _add_bytes(
            total_bytes, _require_template_file(directory, definition.template)
        )
        blocks[type_id] = BoundBlockDefinition(manifest.id, definition)
    _reject_undeclared_json(directory / "blocks", set(manifest.blocks))

    pages: dict[str, PageTemplate] = {}
    for page_type in manifest.page_templates:
        payload, size = _read_declared_json(
            directory,
            Path("templates") / "pages" / f"{page_type}.json",
            max_bytes=MAX_PAGE_TEMPLATE_BYTES,
        )
        total_bytes = _add_bytes(total_bytes, size)
        try:
            page = PageTemplate.model_validate(payload)
        except ValidationError as error:
            raise ThemeCompositionError("page template is invalid") from error
        pages[page_type] = page
    _reject_undeclared_json(directory / "templates" / "pages", set(manifest.page_templates))
    return ThemeCompositionCatalog(sections, blocks, pages)


def finalize_composition_catalog(
    catalog: ThemeCompositionCatalog,
) -> ThemeCompositionCatalog:
    """Reject cyclic or dangling allowed_blocks on a complete catalog."""

    try:
        reject_block_type_cycles(
            {type_id: bound.definition for type_id, bound in catalog.blocks.items()}
        )
    except ValueError as error:
        raise ThemeCompositionError(str(error)) from error
    known_blocks = set(catalog.blocks)
    for bound in (*catalog.sections.values(), *catalog.blocks.values()):
        unknown = sorted(set(bound.definition.allowed_blocks) - known_blocks)
        if unknown:
            raise ThemeCompositionError("unknown block type")
    return catalog


def merge_composition_catalogs(
    child: ThemeCompositionCatalog, parent: ThemeCompositionCatalog
) -> ThemeCompositionCatalog:
    return finalize_composition_catalog(
        ThemeCompositionCatalog(
            {**parent.sections, **child.sections},
            {**parent.blocks, **child.blocks},
            {**parent.pages, **child.pages},
        )
    )


def complete_composition_catalog(
    catalog: ThemeCompositionCatalog,
    parent: ThemeCompositionCatalog | None = None,
) -> ThemeCompositionCatalog:
    if parent is None:
        return finalize_composition_catalog(catalog)
    return merge_composition_catalogs(catalog, parent)


def validate_catalog(
    catalog: ThemeCompositionCatalog,
    chain_slots: set[str] | frozenset[str],
    slot_registry: SlotRegistry | None = None,
) -> None:
    if catalog.empty():
        return
    registry_slots = None if slot_registry is None else slot_registry.allowed_slots
    for bound in (*catalog.sections.values(), *catalog.blocks.values()):
        _require_known_slots(bound.definition.slots, chain_slots, registry_slots)
    for page_type, page in catalog.pages.items():
        resolve_page_template(
            page_type,
            page,
            catalog,
            chain_slots=chain_slots,
            slot_registry=slot_registry,
            theme_id="validate",
        )


def resolve_page_template(
    page_type: str,
    page: PageTemplate,
    catalog: ThemeCompositionCatalog,
    *,
    chain_slots: set[str] | frozenset[str],
    slot_registry: SlotRegistry | None = None,
    theme_id: str,
) -> ResolvedPage:
    registry_slots = None if slot_registry is None else slot_registry.allowed_slots
    resolved_sections: list[ResolvedSection] = []
    for section_id in page.order:
        instance = page.sections[section_id]
        bound = catalog.sections.get(instance.type)
        if bound is None:
            raise ThemeCompositionError("unknown section type")
        _require_known_slots(bound.definition.slots, chain_slots, registry_slots)
        try:
            settings = validate_settings_against_schema(
                instance.settings, bound.definition.settings
            )
        except ValueError as error:
            raise ThemeCompositionError(str(error)) from error
        blocks = _resolve_blocks(
            instance.blocks,
            instance.block_order,
            allowed_types=bound.definition.allowed_blocks,
            max_blocks=bound.definition.max_blocks,
            remaining_depth=bound.definition.max_block_nesting_depth,
            catalog=catalog,
            chain_slots=chain_slots,
            registry_slots=registry_slots,
        )
        if instance.enabled:
            resolved_sections.append(
                ResolvedSection(
                    id=section_id,
                    type=instance.type,
                    theme_id=bound.theme_id,
                    template=bound.definition.template,
                    settings=settings,
                    slots=bound.definition.slots,
                    blocks=blocks,
                )
            )
    return ResolvedPage(
        page_type=page_type,
        theme_id=theme_id,
        schema_version=page.schema_version,
        sections=tuple(resolved_sections),
    )


def validate_installed_themes(
    themes: dict[str, ThemeManifest],
    locations: dict[str, Path],
) -> None:
    catalogs = {
        theme_id: load_theme_composition_catalog(locations[theme_id], manifest)
        for theme_id, manifest in themes.items()
    }
    for theme in themes.values():
        parent_catalog = catalogs[theme.parent] if theme.parent else None
        merged = complete_composition_catalog(catalogs[theme.id], parent_catalog)
        chain_slots = set(theme.slots)
        if theme.parent:
            chain_slots.update(themes[theme.parent].slots)
        validate_catalog(merged, chain_slots)


def validate_candidate_composition(
    directory: Path,
    manifest: ThemeManifest,
    *,
    parent_directory: Path | None = None,
    parent_manifest: ThemeManifest | None = None,
) -> None:
    catalog = load_theme_composition_catalog(directory, manifest)
    chain_slots = set(manifest.slots)
    parent_catalog = None
    if parent_manifest is not None:
        if parent_directory is None:
            raise ThemeCompositionError("theme parent composition is unavailable")
        parent_catalog = load_theme_composition_catalog(
            parent_directory, parent_manifest
        )
        chain_slots.update(parent_manifest.slots)
    validate_catalog(complete_composition_catalog(catalog, parent_catalog), chain_slots)


class PageTemplateResolver:
    """Resolve a declared page type through the active theme inheritance chain.

    Runtime resolution requires SlotRegistry. Install-time catalog validation
    checks theme-declared slots without a registry because packages are not
    projected yet.
    """

    def __init__(self, theme_registry: Any, slot_registry: SlotRegistry) -> None:
        if not isinstance(slot_registry, SlotRegistry):
            raise TypeError("page template resolution requires SlotRegistry")
        self.theme_registry = theme_registry
        self.slot_registry = slot_registry

    def catalog_for(self, theme_id: str) -> ThemeCompositionCatalog:
        chain = self.theme_registry.inheritance_chain(theme_id)
        merged = ThemeCompositionCatalog({}, {}, {})
        for theme in reversed(chain):
            loaded = load_theme_composition_catalog(
                self.theme_registry.path(theme.id), theme
            )
            merged = merge_composition_catalogs(loaded, merged)
        return merged

    def resolve(
        self,
        theme_id: str,
        page_type: str,
        *,
        pages: dict[str, PageTemplate] | None = None,
    ) -> ResolvedPage:
        from plaik_contracts.theme_composition import require_composition_id

        require_composition_id(page_type, error="invalid page type")
        catalog = self.catalog_for(theme_id)
        page = (pages or {}).get(page_type) or catalog.pages.get(page_type)
        if page is None:
            raise ThemeCompositionError("unknown page template")
        chain_slots = {
            slot_id
            for theme in self.theme_registry.inheritance_chain(theme_id)
            for slot_id in theme.slots
        }
        return resolve_page_template(
            page_type,
            page,
            catalog,
            chain_slots=chain_slots,
            slot_registry=self.slot_registry,
            theme_id=theme_id,
        )


def _resolve_blocks(
    instances: dict[str, BlockInstance],
    order: tuple[str, ...],
    *,
    allowed_types: tuple[str, ...],
    max_blocks: int,
    remaining_depth: int,
    catalog: ThemeCompositionCatalog,
    chain_slots: set[str] | frozenset[str],
    registry_slots: frozenset[str] | None,
) -> tuple[ResolvedBlock, ...]:
    if not instances:
        return ()
    if remaining_depth < 1:
        raise ThemeCompositionError("block nesting exceeds the allowed depth")
    if len(instances) > max_blocks:
        raise ThemeCompositionError("too many blocks")
    allowed = set(allowed_types)
    resolved: list[ResolvedBlock] = []
    for instance_id in order:
        block = instances[instance_id]
        if block.type not in allowed:
            raise ThemeCompositionError("unknown block type")
        bound = catalog.blocks.get(block.type)
        if bound is None:
            raise ThemeCompositionError("unknown block type")
        _require_known_slots(bound.definition.slots, chain_slots, registry_slots)
        try:
            settings = validate_settings_against_schema(
                block.settings, bound.definition.settings
            )
        except ValueError as error:
            raise ThemeCompositionError(str(error)) from error
        if block.blocks:
            children = _resolve_blocks(
                block.blocks,
                block.block_order,
                allowed_types=bound.definition.allowed_blocks,
                max_blocks=bound.definition.max_blocks,
                remaining_depth=min(
                    remaining_depth - 1, bound.definition.max_nesting_depth
                ),
                catalog=catalog,
                chain_slots=chain_slots,
                registry_slots=registry_slots,
            )
        else:
            children = ()
        if block.enabled:
            resolved.append(
                ResolvedBlock(
                    id=instance_id,
                    type=block.type,
                    theme_id=bound.theme_id,
                    template=bound.definition.template,
                    settings=settings,
                    slots=bound.definition.slots,
                    blocks=children,
                )
            )
    return tuple(resolved)


def _require_known_slots(
    slots: tuple[str, ...],
    chain_slots: set[str] | frozenset[str],
    registry_slots: frozenset[str] | None,
) -> None:
    for slot_id in slots:
        if slot_id not in chain_slots:
            raise ThemeCompositionError("unknown slot")
        if registry_slots is not None and slot_id not in registry_slots:
            raise ThemeCompositionError("unknown slot")


def _add_bytes(total: int, size: int) -> int:
    total += size
    if total > MAX_COMPOSITION_BYTES:
        raise ThemeCompositionError("composition document is too large")
    return total


def _openat_flags(*, directory: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _openat_regular_file(base: Path, relative: Path) -> int:
    """Open a contained regular file; every path component uses O_NOFOLLOW."""

    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ThemeCompositionError("composition file is missing or unsafe")
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute():
        raise ThemeCompositionError("composition file is missing or unsafe")
    owned: list[int] = []
    file_fd: int | None = None
    try:
        current = os.open(base, _openat_flags(directory=True))
        owned.append(current)
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            nxt = os.open(part, _openat_flags(directory=not last), dir_fd=current)
            if last:
                file_fd = nxt
            else:
                owned.append(nxt)
                current = nxt
        if file_fd is None:
            raise ThemeCompositionError("composition file is missing or unsafe")
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(file_fd)
            file_fd = None
            raise ThemeCompositionError("composition file is missing or unsafe")
        return file_fd
    except OSError as error:
        if file_fd is not None:
            os.close(file_fd)
            file_fd = None
        raise ThemeCompositionError("composition file is missing or unsafe") from error
    finally:
        for descriptor in owned:
            os.close(descriptor)


def assert_contained_regular_file(base: Path, relative: Path) -> None:
    """Verify one contained regular file; every path component uses O_NOFOLLOW."""

    descriptor = _openat_regular_file(base, relative)
    os.close(descriptor)


def read_bounded_contained_text(base: Path, relative: Path, max_bytes: int) -> str:
    """Read one contained UTF-8 file through descriptor-anchored O_NOFOLLOW."""

    _, validate_segment = _theme_file_helpers()
    for part in Path(relative).parts:
        validate_segment(part, error="invalid composition path")
    descriptor = _openat_regular_file(base, relative)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size > max_bytes:
            raise ThemeCompositionError("composition document is too large")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(max_bytes + 1)
        after = os.fstat(descriptor)
        if (
            len(payload) > max_bytes
            or len(payload) != metadata.st_size
            or after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
        ):
            raise ThemeCompositionError("composition file is missing or unsafe")
        try:
            return payload.decode("utf-8")
        except UnicodeError as error:
            raise ThemeCompositionError("composition document is invalid") from error
    finally:
        os.close(descriptor)


def read_bounded_regular_text(path: Path, max_bytes: int) -> str:
    """Last-component O_NOFOLLOW read for already-resolved layout files."""

    target = Path(path)
    return read_bounded_contained_text(target.parent, Path(target.name), max_bytes)


def _json_nesting_too_deep(text: str, limit: int) -> bool:
    depth = 0
    in_string = False
    escape = False
    for char in text:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > limit:
                return True
        elif char in "}]":
            if depth:
                depth -= 1
    return False


def _read_declared_json(
    directory: Path, relative: Path, *, max_bytes: int
) -> tuple[dict[str, Any], int]:
    text = read_bounded_contained_text(directory, relative, max_bytes)
    if _json_nesting_too_deep(text, MAX_JSON_NESTING_DEPTH):
        raise ThemeCompositionError("composition document is invalid")
    try:
        payload = json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except RecursionError as error:
        raise ThemeCompositionError("composition document is invalid") from error
    except (ValueError, json.JSONDecodeError) as error:
        raise ThemeCompositionError("composition document is invalid") from error
    if not isinstance(payload, dict):
        raise ThemeCompositionError("composition document is invalid")
    return payload, len(text.encode("utf-8"))


def _require_template_file(directory: Path, template: str) -> int:
    relative = Path("templates") / Path(*PurePosixPath(template).parts)
    text = read_bounded_contained_text(
        directory, relative, MAX_COMPOSITION_TEMPLATE_BYTES
    )
    return len(text.encode("utf-8"))


def _reject_undeclared_json(directory: Path, declared: set[str]) -> None:
    path = Path(directory)
    if not path.exists():
        if declared:
            raise ThemeCompositionError("composition file is missing or unsafe")
        return
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ThemeCompositionError("composition file is missing or unsafe") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ThemeCompositionError("composition file is missing or unsafe")
    extra: list[str] = []
    for child in sorted(path.iterdir()):
        try:
            child_meta = child.lstat()
        except OSError as error:
            raise ThemeCompositionError("composition file is missing or unsafe") from error
        if stat.S_ISLNK(child_meta.st_mode) or not stat.S_ISREG(child_meta.st_mode):
            raise ThemeCompositionError("composition file is missing or unsafe")
        if not child.name.endswith(".json"):
            extra.append(child.name)
            continue
        type_id = child.name[: -len(".json")]
        if type_id not in declared:
            extra.append(type_id)
    if extra:
        raise ThemeCompositionError("undeclared composition file")


def _reject_unexpected_composition_dirs(directory: Path) -> None:
    for relative in (Path("sections"), Path("blocks"), Path("templates") / "pages"):
        path = Path(directory) / relative
        if path.exists():
            raise ThemeCompositionError("undeclared composition file")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("duplicate json key")
        payload[key] = value
    return payload


def _reject_json_constant(_value: str) -> Any:
    raise ValueError("invalid json")


def _theme_file_helpers():
    from . import themes

    return themes._contained_file, themes._validate_safe_path_segment
