"""Durable catalog of package-declared permissions.

Core registers namespaced permissions from signed manifests during package
transactions. Disabling a package keeps history but marks permissions inactive;
uninstall retains auditable records unless an explicit retention policy removes
them later.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from plaik_contracts import PackageManifest, PackagePermissionDeclaration

from .storage import exclusive_file_lock, read_json, write_json_atomic


class PackageDeclarationError(RuntimeError):
    """A package declaration failed ownership, presence or catalog checks."""


class PermissionCatalogError(PackageDeclarationError):
    """A package permission catalog mutation was rejected."""


class PermissionCatalogStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    RETAINED = "retained"


class PermissionCatalogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    permission_id: str
    package_id: str
    package_version: str
    description: str = ""
    dangerous: bool = False
    status: PermissionCatalogStatus = PermissionCatalogStatus.ACTIVE


class PermissionCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    permissions: dict[str, PermissionCatalogEntry] = Field(default_factory=dict)


class PackagePermissionCatalog:
    """Sole writer for the package permission declaration registry."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def entries(self) -> dict[str, PermissionCatalogEntry]:
        return dict(self._read().permissions)

    def active_permissions(self, package_id: str | None = None) -> frozenset[str]:
        active = {
            permission_id
            for permission_id, entry in self.entries().items()
            if entry.status == PermissionCatalogStatus.ACTIVE
            and (package_id is None or entry.package_id == package_id)
        }
        return frozenset(active)

    def sync_manifest(
        self,
        manifest: PackageManifest,
        *,
        active: bool,
    ) -> tuple[PermissionCatalogEntry, ...]:
        """Replace the package's declared permissions with the signed set."""

        declarations = tuple(manifest.permissions)
        validate_package_permission_ownership(manifest.id, declarations)
        with exclusive_file_lock(self.path):
            catalog = self._read()
            for permission_id, entry in list(catalog.permissions.items()):
                if entry.package_id != manifest.id:
                    continue
                if permission_id not in {item.id for item in declarations}:
                    catalog.permissions[permission_id] = entry.model_copy(
                        update={"status": PermissionCatalogStatus.RETAINED}
                    )
            written: list[PermissionCatalogEntry] = []
            status = (
                PermissionCatalogStatus.ACTIVE
                if active
                else PermissionCatalogStatus.INACTIVE
            )
            for declaration in declarations:
                existing = catalog.permissions.get(declaration.id)
                if (
                    existing is not None
                    and existing.package_id != manifest.id
                ):
                    raise PermissionCatalogError(
                        f"permission already owned by {existing.package_id}"
                    )
                entry = PermissionCatalogEntry(
                    permission_id=declaration.id,
                    package_id=manifest.id,
                    package_version=manifest.version,
                    description=declaration.description,
                    dangerous=declaration.dangerous,
                    status=status,
                )
                catalog.permissions[declaration.id] = entry
                written.append(entry)
            self._write(catalog)
            return tuple(written)

    def set_package_active(self, package_id: str, *, active: bool) -> int:
        with exclusive_file_lock(self.path):
            catalog = self._read()
            changed = 0
            target = (
                PermissionCatalogStatus.ACTIVE
                if active
                else PermissionCatalogStatus.INACTIVE
            )
            for permission_id, entry in list(catalog.permissions.items()):
                if entry.package_id != package_id:
                    continue
                if entry.status == PermissionCatalogStatus.RETAINED:
                    continue
                if entry.status != target:
                    catalog.permissions[permission_id] = entry.model_copy(
                        update={"status": target}
                    )
                    changed += 1
            if changed:
                self._write(catalog)
            return changed

    def retain_package(self, package_id: str) -> int:
        """Keep permission history after uninstall without granting authority."""

        with exclusive_file_lock(self.path):
            catalog = self._read()
            changed = 0
            for permission_id, entry in list(catalog.permissions.items()):
                if entry.package_id != package_id:
                    continue
                if entry.status != PermissionCatalogStatus.RETAINED:
                    catalog.permissions[permission_id] = entry.model_copy(
                        update={"status": PermissionCatalogStatus.RETAINED}
                    )
                    changed += 1
            if changed:
                self._write(catalog)
            return changed

    def is_effective(self, permission_id: str) -> bool:
        entry = self.entries().get(permission_id)
        return entry is not None and entry.status == PermissionCatalogStatus.ACTIVE

    def _read(self) -> PermissionCatalog:
        raw = read_json(self.path, {"version": 1, "permissions": {}})
        return PermissionCatalog.model_validate(raw)

    def _write(self, catalog: PermissionCatalog) -> None:
        write_json_atomic(self.path, catalog.model_dump(mode="json"))


def validate_package_permission_ownership(
    package_id: str,
    declarations: tuple[PackagePermissionDeclaration, ...] | list[PackagePermissionDeclaration],
) -> None:
    for declaration in declarations:
        if declaration.id.startswith("core.") or declaration.id == "*":
            raise PermissionCatalogError("core.* permissions are reserved")
        if not declaration.id.startswith(f"{package_id}."):
            raise PermissionCatalogError(
                "permission id must use its package-owned namespace"
            )


def validate_manifest_declaration_files(
    staging: Path,
    manifest: PackageManifest,
) -> None:
    """Fail closed when declared migration SQL files are missing from staging."""

    for migration in manifest.migrations:
        path = staging / migration.path
        if not path.is_file() or path.is_symlink():
            raise PackageDeclarationError(
                f"declared migration file is missing: {migration.path}"
            )
        try:
            path.resolve().relative_to(staging.resolve())
        except ValueError as error:
            raise PackageDeclarationError(
                f"declared migration escapes package root: {migration.path}"
            ) from error
