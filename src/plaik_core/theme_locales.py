"""Fail-closed theme locale catalogs. Copy is presentation-only."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .theme_composition import ThemeCompositionError, read_bounded_contained_text

MAX_LOCALE_BYTES = 32 * 1024
MAX_LOCALE_KEYS = 256
MAX_LOCALE_VALUE_LENGTH = 500
LOCALE_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
LOCALE_TAG_PATTERN = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")


class ThemeLocaleError(ThemeCompositionError):
    """Theme locale catalog is missing or unsafe."""


def load_theme_strings(directory: Path, locale: str) -> dict[str, str]:
    """Load one bounded locale map from locales/<tag>.json via openat."""

    directory = Path(directory)
    locales_dir = directory / "locales"
    try:
        locales_dir.lstat()
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise ThemeLocaleError("theme locale catalog is missing or unsafe") from error

    for candidate in _locale_candidates(locale):
        relative = Path("locales") / f"{candidate}.json"
        try:
            text = read_bounded_contained_text(directory, relative, MAX_LOCALE_BYTES)
        except ThemeCompositionError:
            continue
        return _parse_locale_map(text)
    raise ThemeLocaleError("theme locale catalog is missing or unsafe")


def _locale_candidates(locale: str) -> tuple[str, ...]:
    if not isinstance(locale, str) or not LOCALE_TAG_PATTERN.fullmatch(locale):
        raise ThemeLocaleError("theme locale catalog is missing or unsafe")
    parts = locale.replace("_", "-").split("-")
    candidates = ["-".join(parts[:index]).lower() for index in range(len(parts), 0, -1)]
    if "en" not in candidates:
        candidates.append("en")
    seen: list[str] = []
    for item in candidates:
        if item not in seen:
            seen.append(item)
    return tuple(seen)


def _parse_locale_map(text: str) -> dict[str, str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise ThemeLocaleError("theme locale catalog is invalid") from error
    if not isinstance(payload, dict) or len(payload) > MAX_LOCALE_KEYS:
        raise ThemeLocaleError("theme locale catalog is invalid")
    parsed: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not LOCALE_KEY_PATTERN.fullmatch(key):
            raise ThemeLocaleError("theme locale catalog is invalid")
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ThemeLocaleError("theme locale catalog is invalid")
        if len(value) > MAX_LOCALE_VALUE_LENGTH:
            raise ThemeLocaleError("theme locale catalog is invalid")
        parsed[key] = value
    return parsed
