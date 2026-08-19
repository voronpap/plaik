"""Ordered web hook bindings between themes and modules."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath


HOOK_PATTERN = re.compile(r"^[a-z][A-Za-z0-9]*$")
MODULE_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
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


@dataclass(frozen=True, slots=True)
class HookBinding:
    hook: str
    module_id: str
    template: str
    position: int = 100


class HookRegistry:
    def __init__(self, allowed_hooks: set[str]) -> None:
        invalid = sorted(hook for hook in allowed_hooks if not HOOK_PATTERN.fullmatch(hook))
        if invalid:
            raise ValueError(f"invalid hook names: {invalid}")
        self.allowed_hooks = frozenset(allowed_hooks)
        self._bindings: set[HookBinding] = set()
        self._inactive_owners: set[str] = set()
        self._lock = threading.RLock()

    def register(self, binding: HookBinding) -> None:
        if binding.hook not in self.allowed_hooks:
            raise ValueError(f"unknown hook: {binding.hook}")
        if not isinstance(binding.module_id, str) or not MODULE_PATTERN.fullmatch(
            binding.module_id
        ):
            raise ValueError("invalid module id")
        _validate_path_segment(binding.module_id, error="invalid module id")
        if not _is_safe_relative_path(binding.template):
            raise ValueError("invalid template")
        with self._lock:
            self._bindings.add(binding)

    def bindings(self, hook: str) -> list[HookBinding]:
        if hook not in self.allowed_hooks:
            raise ValueError(f"unknown hook: {hook}")
        with self._lock:
            return sorted(
                (
                    binding
                    for binding in self._bindings
                    if binding.hook == hook
                    and binding.module_id not in self._inactive_owners
                ),
                key=lambda binding: (binding.position, binding.module_id, binding.template),
            )

    def deactivate_owner(self, owner: str) -> int:
        return self._set_owner_active(owner, False)

    def activate_owner(self, owner: str) -> int:
        return self._set_owner_active(owner, True)

    def _set_owner_active(self, owner: str, active: bool) -> int:
        if not isinstance(owner, str) or not MODULE_PATTERN.fullmatch(owner):
            raise ValueError("invalid module id")
        _validate_path_segment(owner, error="invalid module id")
        with self._lock:
            matching = sum(1 for binding in self._bindings if binding.module_id == owner)
            currently_active = owner not in self._inactive_owners
            if currently_active == active:
                return 0
            if active:
                self._inactive_owners.discard(owner)
            else:
                self._inactive_owners.add(owner)
            return matching


def _is_safe_relative_path(value: str) -> bool:
    if not isinstance(value, str) or not value or len(value) > 1024:
        return False
    posix_path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or not posix_path.parts
        or posix_path.as_posix() != value
    ):
        return False
    try:
        for part in posix_path.parts:
            _validate_path_segment(part, error="invalid template")
    except ValueError:
        return False
    return True


def _validate_path_segment(value: str, *, error: str) -> None:
    if (
        not value
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
