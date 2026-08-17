"""Sandboxed web SSR with theme-first resolution."""

from __future__ import annotations

import copy
import html
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from jinja2 import StrictUndefined, select_autoescape
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup
from pydantic import BaseModel, ConfigDict

from .hooks import HookRegistry
from .slots import SlotRegistry
from .themes import TemplateResolver, ThemeManager, ThemeRegistry


_MUTATING_METHODS = frozenset(
    {
        "add",
        "append",
        "clear",
        "discard",
        "extend",
        "insert",
        "pop",
        "popitem",
        "remove",
        "reverse",
        "setdefault",
        "sort",
        "update",
    }
)
_SAFE_CALLABLE_ATTRS = frozenset(
    {
        "casefold",
        "copy",
        "count",
        "endswith",
        "find",
        "format",
        "get",
        "index",
        "isalnum",
        "isalpha",
        "isdigit",
        "isspace",
        "items",
        "join",
        "keys",
        "lower",
        "lstrip",
        "replace",
        "rfind",
        "rindex",
        "rstrip",
        "split",
        "startswith",
        "strip",
        "title",
        "upper",
        "values",
    }
)


class WebSandboxedEnvironment(SandboxedEnvironment):
    """Deny mutating and arbitrary callable attributes on template context objects."""

    def is_safe_attribute(self, obj: Any, attr: str, value: Any) -> bool:
        if attr in _MUTATING_METHODS:
            return False
        if not super().is_safe_attribute(obj, attr, value):
            return False
        if callable(value) and attr not in _SAFE_CALLABLE_ATTRS:
            return False
        return True


class WebRenderError(RuntimeError):
    """A web theme or module template could not be rendered safely."""


class RenderedWeb(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    store_id: str
    theme_id: str
    layout: str
    html: str
    asset_urls: tuple[str, ...]
    source: str = "theme"


class WebRenderer:
    """Resolve the active theme before loading layout, hooks or assets."""

    RESERVED_CONTEXT = {
        "hook",
        "slot",
        "locale",
        "page",
        "store_id",
        "theme_assets",
        "theme_id",
    }

    def __init__(
        self,
        *,
        theme_manager: ThemeManager,
        theme_registry: ThemeRegistry,
        hook_registry: HookRegistry,
        template_resolver: TemplateResolver,
        slot_registry: SlotRegistry | None = None,
        system_fallback_root: Path | None = None,
        asset_url_prefix: str = "/themes",
    ) -> None:
        self.theme_manager = theme_manager
        self.theme_registry = theme_registry
        self.hook_registry = hook_registry
        self.slot_registry = slot_registry or SlotRegistry(set())
        self.template_resolver = template_resolver
        self.system_fallback_root = (
            Path(system_fallback_root) if system_fallback_root is not None else None
        )
        self.asset_url_prefix = asset_url_prefix.rstrip("/")
        self.environment = WebSandboxedEnvironment(
            autoescape=select_autoescape(
                enabled_extensions=("html", "xml"),
                default_for_string=True,
                default=True,
            ),
            undefined=StrictUndefined,
            enable_async=False,
        )

    def render(
        self,
        *,
        store_id: str,
        locale: str,
        page_title: str,
        layout: str = "full-width",
        context: dict[str, Any] | None = None,
    ) -> RenderedWeb:
        safe_layout = _safe_layout(layout)
        extra_context = copy.deepcopy(dict(context or {}))
        overlap = sorted(self.RESERVED_CONTEXT & set(extra_context))
        if overlap:
            raise WebRenderError("web context overrides reserved names")

        # Theme selection is deliberately the first stateful lookup in SSR.
        try:
            active = self.theme_manager.active(store_id)
        except KeyError:
            return self._render_system_fallback(
                store_id=store_id,
                locale=locale,
                page_title=page_title,
            )
        chain = self.theme_registry.inheritance_chain(active.id)
        layout_path = self._resolve_layout(chain, safe_layout)
        if layout_path is None:
            return self._render_system_fallback(
                store_id=store_id,
                locale=locale,
                page_title=page_title,
            )
        asset_urls = self._asset_urls(chain)

        def render_hook(name: str) -> Markup:
            fragments: list[str] = []
            for binding in self.hook_registry.bindings(name):
                template_path = self.template_resolver.resolve_module_template(
                    theme_id=active.id,
                    module_id=binding.module_id,
                    template=binding.template,
                )
                if template_path is None:
                    raise WebRenderError("module web template is missing")
                fragments.append(
                    self._render_template(
                        template_path,
                        {
                            **extra_context,
                            "locale": locale,
                            "store_id": store_id,
                            "theme_id": active.id,
                            "page": {"title": page_title},
                        },
                    )
                )
            return Markup("".join(fragments))

        declared_slots = {
            slot_id
            for theme in chain
            for slot_id in theme.slots
        }

        def render_slot(name: str) -> Markup:
            if name not in declared_slots:
                raise WebRenderError("unknown slot")
            fragments: list[str] = []
            for binding in self.slot_registry.bindings(name):
                template_path = self.template_resolver.resolve_module_template(
                    theme_id=active.id,
                    module_id=binding.module_id,
                    template=binding.template,
                )
                if template_path is None:
                    raise WebRenderError("module web template is missing")
                fragments.append(
                    self._render_template(
                        template_path,
                        {
                            **extra_context,
                            "locale": locale,
                            "store_id": store_id,
                            "theme_id": active.id,
                            "page": {"title": page_title},
                        },
                    )
                )
            return Markup("".join(fragments))

        def render_assets(kind: str) -> Markup:
            if kind not in {"css", "js"}:
                raise WebRenderError("unknown theme asset kind")
            matching = [
                url
                for url in asset_urls
                if (kind == "css" and url.endswith(".css"))
                or (kind == "js" and url.endswith(".js"))
            ]
            if kind == "css":
                return Markup(
                    "".join(
                        f'<link rel="stylesheet" href="{html.escape(url, quote=True)}">'
                        for url in matching
                    )
                )
            return Markup(
                "".join(
                    f'<script src="{html.escape(url, quote=True)}" defer></script>'
                    for url in matching
                )
            )

        rendered = self._render_template(
            layout_path,
            {
                **extra_context,
                "locale": locale,
                "store_id": store_id,
                "theme_id": active.id,
                "page": {"title": page_title},
                "hook": render_hook,
                "slot": render_slot,
                "theme_assets": render_assets,
            },
        )
        return RenderedWeb(
            store_id=store_id,
            theme_id=active.id,
            layout=safe_layout,
            html=rendered,
            asset_urls=asset_urls,
            source="theme",
        )

    def asset_path(self, theme_id: str, relative_path: str) -> Path:
        safe_theme = _safe_segment(theme_id)
        safe_relative = _safe_relative(relative_path)
        themes = self.theme_registry.discover()
        theme = themes.get(safe_theme)
        if theme is None:
            raise WebRenderError("web theme is unavailable")
        declared = set(theme.assets.css) | set(theme.assets.js)
        if safe_relative not in declared:
            raise WebRenderError("theme asset is not declared")
        base = self.theme_registry.path(safe_theme)
        path = _contained_file(
            base,
            Path(*PurePosixPath(safe_relative).parts),
        )
        if path is None:
            raise WebRenderError("declared theme asset is missing or unsafe")
        return path

    def _resolve_layout(self, chain, layout: str) -> Path | None:
        for theme in chain:
            if layout not in theme.layouts:
                continue
            candidate = _regular_layout_file(
                self.theme_registry.path(theme.id),
                Path("templates") / "layouts" / f"{layout}.html",
            )
            if candidate is not None:
                return candidate
        return None

    def _render_system_fallback(
        self,
        *,
        store_id: str,
        locale: str,
        page_title: str,
    ) -> RenderedWeb:
        if self.system_fallback_root is None:
            raise WebRenderError("web layout is unavailable")
        layout = _regular_layout_file(
            self.system_fallback_root,
            Path("layout.html"),
            missing="unavailable",
        )
        if layout is None:
            raise WebRenderError("web layout is unavailable")
        rendered = self._render_template(
            layout,
            {
                "locale": locale,
                "store_id": store_id,
                "page": {"title": page_title},
            },
        )
        return RenderedWeb(
            store_id=store_id,
            theme_id="system-fallback",
            layout="system-fallback",
            html=rendered,
            asset_urls=(),
            source="system-fallback",
        )

    def _asset_urls(self, chain) -> tuple[str, ...]:
        urls: list[str] = []
        seen: set[tuple[str, str]] = set()
        for theme in reversed(chain):
            for asset in (*theme.assets.css, *theme.assets.js):
                safe_asset = _safe_relative(asset)
                key = (theme.id, safe_asset)
                if key in seen:
                    continue
                path = _contained_file(
                    self.theme_registry.path(theme.id),
                    Path(*PurePosixPath(safe_asset).parts),
                )
                if path is None:
                    raise WebRenderError("declared theme asset is missing or unsafe")
                urls.append(f"{self.asset_url_prefix}/{theme.id}/{safe_asset}")
                seen.add(key)
        return tuple(urls)

    def _render_template(self, path: Path, context: dict[str, Any]) -> str:
        try:
            source = path.read_text(encoding="utf-8")
            template = self.environment.from_string(source)
            return template.render(copy.deepcopy(context))
        except WebRenderError:
            raise
        except Exception:
            raise WebRenderError("web template rendering failed") from None


def _safe_layout(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise WebRenderError("invalid web layout")
    return _safe_segment(value)


def _safe_segment(value: str) -> str:
    path = PurePosixPath(value)
    if (
        len(path.parts) != 1
        or value in {"", ".", ".."}
        or "\\" in value
        or "\x00" in value
    ):
        raise WebRenderError("invalid web path segment")
    return value


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in value
        or "\x00" in value
    ):
        raise WebRenderError("invalid web relative path")
    return path.as_posix()


def _regular_layout_file(
    root: Path,
    relative: Path,
    *,
    missing: str = "missing",
) -> Path | None:
    """Return a regular layout file, failing closed on any symlink ancestor."""

    path = _walk_regular_file(root, relative)
    if path is not None:
        return path
    if _path_has_symlink(Path(root), relative):
        raise WebRenderError("web layout is unsafe")
    if missing == "unavailable":
        return None
    return None


def _contained_file(base: Path, relative: Path) -> Path | None:
    """Return one regular file without following any symlink from base."""

    return _walk_regular_file(base, relative)


def _walk_regular_file(root: Path, relative: Path) -> Path | None:
    current = Path(root)
    try:
        metadata = current.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return None
    parts = Path(relative).parts
    if not parts:
        return None
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            return None
        if index == len(parts) - 1:
            if not stat.S_ISREG(metadata.st_mode):
                return None
            return current
        if not stat.S_ISDIR(metadata.st_mode):
            return None
    return None


def _path_has_symlink(root: Path, relative: Path) -> bool:
    current = Path(root)
    try:
        if stat.S_ISLNK(current.lstat().st_mode):
            return True
    except OSError:
        return False
    for part in Path(relative).parts:
        current = current / part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                return True
        except OSError:
            return False
    return False
