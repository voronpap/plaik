"""Executable system preflight for Platform installation."""

from __future__ import annotations

import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import CoreSettings


MINIMUM_PYTHON = (3, 12)
DEFAULT_MINIMUM_FREE_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class RequirementCheck:
    id: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class RequirementReport:
    checks: tuple[RequirementCheck, ...]
    observations: tuple[RequirementCheck, ...] = ()
    inventory: dict[str, object] | None = None

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    def require(self) -> None:
        failed = [check for check in self.checks if not check.passed]
        if failed:
            details = "; ".join(f"{check.id}: {check.detail}" for check in failed)
            raise RequirementsNotMet(details)


class RequirementsNotMet(RuntimeError):
    """Raised when Platform cannot be installed on the current host."""


class SystemRequirements:
    def __init__(
        self,
        settings: CoreSettings,
        *,
        minimum_free_bytes: int = DEFAULT_MINIMUM_FREE_BYTES,
        python_version: tuple[int, int] | None = None,
    ) -> None:
        if minimum_free_bytes < 0:
            raise ValueError("minimum_free_bytes must be non-negative")
        self.settings = settings
        self.minimum_free_bytes = minimum_free_bytes
        self.python_version = python_version or sys.version_info[:2]

    def inspect(self) -> RequirementReport:
        from .host_inventory import discover_host_inventory

        inventory = discover_host_inventory(self.settings)
        return RequirementReport(
            checks=(
                self._python_check(),
                self._data_directory_check(),
                self._free_space_check(),
                self._default_theme_check(),
            ),
            observations=inventory.observations(),
            inventory=inventory.public_inventory(),
        )

    def _python_check(self) -> RequirementCheck:
        passed = self.python_version >= MINIMUM_PYTHON
        current = ".".join(str(part) for part in self.python_version)
        required = ".".join(str(part) for part in MINIMUM_PYTHON)
        return RequirementCheck(
            id="python",
            passed=passed,
            detail=f"Python {current}; required >= {required}",
        )

    def _data_directory_check(self) -> RequirementCheck:
        try:
            self.settings.data_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=self.settings.data_dir):
                pass
        except OSError as error:
            return RequirementCheck("data_directory", False, str(error))
        return RequirementCheck(
            "data_directory", True, f"writable: {self.settings.data_dir}"
        )

    def _free_space_check(self) -> RequirementCheck:
        try:
            free = shutil.disk_usage(self.settings.data_dir).free
        except OSError as error:
            return RequirementCheck("free_space", False, str(error))
        return RequirementCheck(
            "free_space",
            free >= self.minimum_free_bytes,
            f"{free} bytes available; required >= {self.minimum_free_bytes}",
        )

    def _default_theme_check(self) -> RequirementCheck:
        default_theme = self.settings.themes_dir / "default"
        manifest = default_theme / "manifest.json"
        try:
            theme_metadata = default_theme.lstat()
            manifest_metadata = manifest.lstat()
        except FileNotFoundError:
            return RequirementCheck(
                "default_theme",
                False,
                f"manifest missing: {manifest}",
            )
        except OSError:
            return RequirementCheck(
                "default_theme",
                False,
                f"manifest unavailable: {manifest}",
            )
        if not stat.S_ISDIR(theme_metadata.st_mode) or not stat.S_ISREG(
            manifest_metadata.st_mode
        ):
            return RequirementCheck(
                "default_theme",
                False,
                f"manifest unsafe: {manifest}",
            )
        return RequirementCheck(
            "default_theme",
            True,
            f"manifest found: {manifest}",
        )
