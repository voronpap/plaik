"""Theme API v1 dotted UI slot registry.

HookRegistry remains the compatibility path for camelCase web hooks.
SlotRegistry is the authoritative path for new Theme API v1 contributions.
Core never rewrites a hook name into a slot id.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass

from plaik_contracts.theme_api import SLOT_ID_PATTERN, require_public_slot_id

from .hooks import MODULE_PATTERN, _is_safe_relative_path, _validate_path_segment

_SLOT_ID = re.compile(SLOT_ID_PATTERN)


@dataclass(frozen=True, slots=True)
class SlotBinding:
    slot: str
    module_id: str
    template: str
    position: int = 100


class SlotRegistry:
    def __init__(self, allowed_slots: set[str]) -> None:
        invalid = sorted(
            slot_id for slot_id in allowed_slots if not _SLOT_ID.fullmatch(slot_id)
        )
        if invalid:
            raise ValueError(f"invalid slot names: {invalid}")
        for slot_id in allowed_slots:
            require_public_slot_id(slot_id)
        self.allowed_slots = frozenset(allowed_slots)
        self._bindings: set[SlotBinding] = set()
        self._inactive_owners: set[str] = set()
        self._lock = threading.RLock()

    def register(self, binding: SlotBinding) -> None:
        if binding.slot not in self.allowed_slots:
            raise ValueError(f"unknown slot: {binding.slot}")
        if not isinstance(binding.module_id, str) or not MODULE_PATTERN.fullmatch(
            binding.module_id
        ):
            raise ValueError("invalid module id")
        _validate_path_segment(binding.module_id, error="invalid module id")
        if not _is_safe_relative_path(binding.template) or not binding.template.endswith(
            ".html"
        ):
            raise ValueError("invalid template")
        with self._lock:
            self._bindings.add(binding)

    def bindings(self, slot: str) -> list[SlotBinding]:
        if slot not in self.allowed_slots:
            raise ValueError(f"unknown slot: {slot}")
        with self._lock:
            return sorted(
                (
                    binding
                    for binding in self._bindings
                    if binding.slot == slot
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
