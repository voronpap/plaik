"""Atomic package registry and lifecycle state machine."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from plaik_contracts import PackageManifest

from .dependencies import resolve_install_order, version_matches
from .storage import read_json, write_json_atomic


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
            package_id: PackageRecord.model_validate(record)
            for package_id, record in data.get("packages", {}).items()
        }

    def install_many(self, manifests: list[PackageManifest]) -> list[PackageRecord]:
        records = self.records()
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
        updated = record.model_copy(update={"status": PackageStatus.DISABLED})
        records[package_id] = updated
        self._write(records)
        return updated

    def quarantine(self, package_id: str) -> PackageRecord:
        """Emergency containment without cascading repair or deletion."""

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
