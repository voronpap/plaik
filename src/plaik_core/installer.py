"""Persistent, forward-only installer state machine."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from .storage import exclusive_file_lock, read_json, write_json_atomic


class InstallState(StrEnum):
    NOT_STARTED = "not_started"
    REQUIREMENTS_CHECKED = "requirements_checked"
    CONFIGURED = "configured"
    DATABASE_READY = "database_ready"
    ADMIN_READY = "admin_ready"
    THEME_READY = "theme_ready"
    COMPLETED = "completed"


INSTALL_SEQUENCE = tuple(InstallState)


class InvalidInstallTransition(ValueError):
    """Raised when an installer state transition violates the contract."""


class InstallStateStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> InstallState:
        data = read_json(
            self.path,
            {"state": InstallState.NOT_STARTED.value},
        )
        return InstallState(data["state"])

    def validate_transition(self, target: InstallState) -> InstallState:
        current = self.read()
        if target == current:
            return current
        current_index = INSTALL_SEQUENCE.index(current)
        expected = INSTALL_SEQUENCE[current_index + 1] if current_index + 1 < len(INSTALL_SEQUENCE) else None
        if target != expected:
            raise InvalidInstallTransition(
                f"cannot transition from {current.value} to {target.value}; "
                f"expected {expected.value if expected else 'no further transition'}"
            )
        return current

    def advance(self, target: InstallState) -> InstallState:
        with exclusive_file_lock(self.path):
            current = self.validate_transition(target)
            if target == current:
                return current
            self._write_unlocked(target)
            return target

    def _write(self, state: InstallState) -> None:
        with exclusive_file_lock(self.path):
            self._write_unlocked(state)

    def _write_unlocked(self, state: InstallState) -> None:
        write_json_atomic(self.path, {"state": state.value})
