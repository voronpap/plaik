"""Sandboxed web SSR with theme-first resolution."""

from __future__ import annotations

import html
from pathlib import Path, PurePosixPath
from typing import Any

from jinja2 import StrictUndefined, select_autoescape
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup
from pydantic import BaseModel, ConfigDict

from .hooks import HookRegistry
from .themes import TemplateResolver, ThemeManager, ThemeRegistry


class WebRenderError(RuntimeError):
    """A web theme or module template could not be rendered safely."""


class RenderedWeb(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    store_id: str
    theme_id: str
    layout: str
    html: str
    asset_urls: tuple[str, ...]


class WebRenderer:
    """Resolve the active theme before loading layout, hooks or assets."""

    RESERVED_CONTEXT = {
        "hook",
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
        asset_url_prefix: str = "/themes",
    ) -> None:
        self.theme_manager = theme_manager
        self.theme_registry = theme_registry
        self.hook_registry = hook_registry
        self.template_resolver = template_resolver
        self.asset_url_prefix = asset_url_prefix.rstrip("/")
        self.environment = SandboxedEnvironment(
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
        extra_context = dict(context or {})
        overlap = sorted(self.RESERVED_CONTEXT & set(extra_context))
        if overlap:
            raise WebRenderError("web context overrides reserved names")

        # Theme selection is deliberately the first stateful lookup in SSR.
        active = self.theme_manager.active(store_id)
        chain = self.theme_registry.inheritance_chain(active.id)
        layout_path = self._resolve_layout(chain, safe_layout)
        if layout_path is None:
            raise WebRenderError("web layout is unavailable")
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
                "theme_assets": render_assets,
            },
        )
        return RenderedWeb(
            store_id=store_id,
            theme_id=active.id,
            layout=safe_layout,
            html=rendered,
            asset_urls=asset_urls,
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
            candidate = _contained_file(
                self.theme_registry.path(theme.id) / "templates" / "layouts",
                Path(f"{layout}.html"),
            )
            if candidate is not None:
                return candidate
        default = self.theme_registry.get("default")
        if default is not None and layout in default.layouts:
            candidate = _contained_file(
                self.theme_registry.path("default") / "templates" / "layouts",
                Path(f"{layout}.html"),
            )
            if candidate is not None:
                return candidate
        return None

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
            return template.render(context)
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


def _contained_file(base: Path, relative: Path) -> Path | None:
    """Resolve one regular file without allowing a symlink escape from base."""

    try:
        resolved_base = Path(base).resolve(strict=True)
        candidate = (Path(base) / relative).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not candidate.is_relative_to(resolved_base) or not candidate.is_file():
        return None
    return candidate
