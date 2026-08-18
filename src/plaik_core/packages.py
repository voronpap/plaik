"""Atomic package registry and lifecycle state machine."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from plaik_contracts import PackageManifest

from .dependencies import (
    DependencyResolutionError,
    resolve_capabilities,
    resolve_install_order,
    version_matches,
)
from .storage import read_json, write_json_atomic


RESERVED_PACKAGE_IDS = frozenset({"system-fallback"})

# Keys written by completed 0.2.x registries and removed from PackageManifest.
_LEGACY_MANIFEST_KEYS = frozenset({"capabilities"})


def _legacy_record_payload(record: object) -> object:
    if not isinstance(record, dict):
        return record
    manifest = record.get("manifest")
    if not isinstance(manifest, dict):
        return record
    cleaned = {
        key: value
        for key, value in manifest.items()
        if key not in _LEGACY_MANIFEST_KEYS
    }
    if cleaned == manifest:
        return record
    return {**record, "manifest": cleaned}


class PackageLifecycleError(RuntimeError):
    """A package lifecycle operation would violate registry invariants."""


class PackageStatus(StrEnum):
    INSTALLED = "installed"
    ENABLED = "enabled"
    DISABLED = "disabled"


class PackageRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: PackageManifest
    status: PackageStatus


class PackageRegistry:
    def __init__(
        self,
        path: Path,
        *,
        core_version: str,
        protected_ids: set[str] | None = None,
    ) -> None:
        self.path = path
        self.core_version = core_version
        self.protected_ids = frozenset(protected_ids or set())

    def records(self) -> dict[str, PackageRecord]:
        data = read_json(self.path, {"packages": {}})
        return {
            package_id: PackageRecord.model_validate(_legacy_record_payload(record))
            for package_id, record in data.get("packages", {}).items()
        }

    def install_many(self, manifests: list[PackageManifest]) -> list[PackageRecord]:
        records = self.records()
        reserved = sorted(
            manifest.id for manifest in manifests if manifest.id in RESERVED_PACKAGE_IDS
        )
        if reserved:
            raise PackageLifecycleError(f"package id is reserved: {reserved}")
        duplicate = sorted(manifest.id for manifest in manifests if manifest.id in records)
        if duplicate:
            raise PackageLifecycleError(f"packages already installed: {duplicate}")
        installed = {package_id: record.manifest for package_id, record in records.items()}
        order = resolve_install_order(
            manifests,
            core_version=self.core_version,
            installed=installed,
        )
        created: list[PackageRecord] = []
        for manifest in order:
            record = PackageRecord(manifest=manifest, status=PackageStatus.INSTALLED)
            records[manifest.id] = record
            created.append(record)
        self._write(records)
        return created

    def enable(self, package_id: str) -> PackageRecord:
        records = self.records()
        record = self._require(records, package_id)
        for dependency in record.manifest.dependencies:
            if dependency.optional:
                continue
            target = records.get(dependency.package_id)
            if target is None or target.status != PackageStatus.ENABLED:
                raise PackageLifecycleError(
                    f"cannot enable {package_id}: dependency "
                    f"{dependency.package_id} is not enabled"
                )
            if not version_matches(target.manifest.version, dependency.version):
                raise PackageLifecycleError(
                    f"cannot enable {package_id}: dependency "
                    f"{dependency.package_id} has incompatible version"
                )
        enabled = {
            other_id: other.manifest
            for other_id, other in records.items()
            if other.status == PackageStatus.ENABLED or other_id == package_id
        }
        try:
            resolve_capabilities(enabled)
        except DependencyResolutionError as error:
            raise PackageLifecycleError(
                f"cannot enable {package_id}: {error}"
            ) from error
        updated = record.model_copy(update={"status": PackageStatus.ENABLED})
        records[package_id] = updated
        self._write(records)
        return updated

    def disable(self, package_id: str) -> PackageRecord:
        records = self.records()
        record = self._require(records, package_id)
        dependents = self._required_dependents(records, package_id, enabled_only=True)
        if dependents:
            raise PackageLifecycleError(
                f"cannot disable {package_id}: enabled dependents {sorted(dependents)}"
            )
        remaining = {
            other_id: other.manifest
            for other_id, other in records.items()
            if other.status == PackageStatus.ENABLED and other_id != package_id
        }
        try:
            resolve_capabilities(remaining)
        except DependencyResolutionError as error:
            raise PackageLifecycleError(
                f"cannot disable {package_id}: {error}"
            ) from error
        updated = record.model_copy(update={"status": PackageStatus.DISABLED})
        records[package_id] = updated
        self._write(records)
        return updated

    def quarantine(self, package_id: str) -> PackageRecord:
        """Emergency containment without cascading repair or deletion.

        Dependency consistency is intentionally not repaired here: enabled
        dependants may become non-runnable and must fail closed until an audited
        operator recovery. The protected default package cannot be quarantined.
        """

        records = self.records()
        record = self._require(records, package_id)
        if package_id in self.protected_ids:
            raise PackageLifecycleError(f"package is protected: {package_id}")
        updated = record.model_copy(update={"status": PackageStatus.DISABLED})
        records[package_id] = updated
        self._write(records)
        return updated

    def uninstall(self, package_id: str) -> PackageRecord:
        records = self.records()
        record = self._require(records, package_id)
        if package_id in self.protected_ids:
            raise PackageLifecycleError(f"package is protected: {package_id}")
        if record.status == PackageStatus.ENABLED:
            raise PackageLifecycleError(f"disable package before uninstall: {package_id}")
        dependents = self._required_dependents(records, package_id, enabled_only=False)
        if dependents:
            raise PackageLifecycleError(
                f"cannot uninstall {package_id}: installed dependents {sorted(dependents)}"
            )
        del records[package_id]
        self._write(records)
        return record

    def _write(self, records: dict[str, PackageRecord]) -> None:
        write_json_atomic(
            self.path,
            {
                "packages": {
                    package_id: record.model_dump(mode="json")
                    for package_id, record in sorted(records.items())
                }
            },
        )

    @staticmethod
    def _require(records: dict[str, PackageRecord], package_id: str) -> PackageRecord:
        try:
            return records[package_id]
        except KeyError as error:
            raise PackageLifecycleError(f"package is not installed: {package_id}") from error

    @staticmethod
    def _required_dependents(
        records: dict[str, PackageRecord], package_id: str, *, enabled_only: bool
    ) -> list[str]:
        dependents: list[str] = []
        for other_id, other in records.items():
            if enabled_only and other.status != PackageStatus.ENABLED:
                continue
            if any(
                dependency.package_id == package_id and not dependency.optional
                for dependency in other.manifest.dependencies
            ):
                dependents.append(other_id)
        return dependents
