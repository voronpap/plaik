"""Domain-neutral Admin JSON command payload bounds.

Core authenticates, authorizes the declared permission, and passes a bounded
JSON object to the package handler. It does not interpret command bodies.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

MAX_COMMAND_JSON_BYTES = 1024 * 1024
MAX_COMMAND_JSON_DEPTH = 16
MAX_COMMAND_JSON_KEYS = 512
MAX_COMMAND_JSON_ITEMS = 4096
MAX_COMMAND_JSON_KEY_BYTES = 128


class CommandPayloadError(ValueError):
    """The command JSON object failed size, depth, or type bounds."""

    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def parse_command_json(raw: bytes) -> dict[str, Any]:
    """Decode a request body into a bounded JSON object. Empty means {}."""

    if not raw:
        return {}
    if len(raw) > MAX_COMMAND_JSON_BYTES:
        raise CommandPayloadError(
            "command payload exceeds the size limit", status_code=413
        )
    try:
        payload = json.loads(raw, parse_constant=_reject_json_constant)
    except RecursionError:
        raise CommandPayloadError("command payload exceeds the depth limit") from None
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        raise CommandPayloadError("command payload must be a JSON object") from error
    if not isinstance(payload, dict):
        raise CommandPayloadError("command payload must be a JSON object")
    return snapshot_command_json(payload)


def snapshot_command_json(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Copy a mapping through JSON so handlers cannot return host objects."""

    if not isinstance(payload, Mapping):
        raise CommandPayloadError("command result must be a JSON object")
    _validate_command_json_structure(payload)
    try:
        encoded = json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(encoded.encode("utf-8")) > MAX_COMMAND_JSON_BYTES:
            raise CommandPayloadError(
                "command payload exceeds the size limit", status_code=413
            )
        decoded = json.loads(encoded, parse_constant=_reject_json_constant)
    except CommandPayloadError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as error:
        raise CommandPayloadError("command payload must be JSON-safe") from error
    if not isinstance(decoded, dict):
        raise CommandPayloadError("command result must be a JSON object")
    return decoded


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _validate_command_json_structure(payload: Mapping[str, Any]) -> None:
    stack: list[tuple[Any, int]] = [(payload, 1)]
    seen: set[int] = set()
    key_count = 0
    item_count = 0
    while stack:
        current, depth = stack.pop()
        item_count += 1
        if item_count > MAX_COMMAND_JSON_ITEMS:
            raise CommandPayloadError("command payload exceeds the item limit")
        if depth > MAX_COMMAND_JSON_DEPTH:
            raise CommandPayloadError("command payload exceeds the depth limit")
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                raise CommandPayloadError("command payload must be acyclic")
            seen.add(identity)
            for key, nested in current.items():
                if not isinstance(key, str):
                    raise CommandPayloadError("command field names must be strings")
                try:
                    key_bytes = len(key.encode("utf-8"))
                except UnicodeError:
                    raise CommandPayloadError("command field name is invalid") from None
                if not 1 <= key_bytes <= MAX_COMMAND_JSON_KEY_BYTES:
                    raise CommandPayloadError("command field name is invalid")
                key_count += 1
                if key_count > MAX_COMMAND_JSON_KEYS:
                    raise CommandPayloadError("command payload exceeds the key limit")
                stack.append((nested, depth + 1))
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in seen:
                raise CommandPayloadError("command payload must be acyclic")
            seen.add(identity)
            stack.extend((nested, depth + 1) for nested in current)
