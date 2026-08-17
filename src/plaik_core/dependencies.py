"""Deterministic package dependency resolution."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from plaik_contracts import PackageManifest


class DependencyResolutionError(ValueError):
    """Missing, conflicting, incompatible or cyclic packages."""


def version_matches(version: str, specifier: str) -> bool:
    return specifier == "*" or Version(version) in SpecifierSet(specifier)


def resolve_install_order(
    manifests: Iterable[PackageManifest],
    *,
    core_version: str,
    installed: Mapping[str, PackageManifest] | None = None,
) -> list[PackageManifest]:
    candidates: dict[str, PackageManifest] = {}
    for manifest in manifests:
        if manifest.id in candidates:
            raise DependencyResolutionError(f"duplicate package: {manifest.id}")
        candidates[manifest.id] = manifest

    installed_packages = dict(installed or {})
    for package_id, manifest in installed_packages.items():
        if package_id != manifest.id:
            raise DependencyResolutionError(
                f"installed package identity mismatch: {package_id}"
            )

    # Candidates replace same-ID installed manifests. Validate the complete
    # graph that would exist after the operation, not only declarations from
    # the incoming batch: installed conflicts/dependents and cycles crossing
    # the installed/candidate boundary are part of the resulting state too.
    all_packages = {**installed_packages, **candidates}

    for manifest in all_packages.values():
        if not version_matches(core_version, manifest.core):
            raise DependencyResolutionError(
                f"{manifest.id} {manifest.version} requires Core {manifest.core}; "
                f"current Core is {core_version}"
            )
        for conflict in manifest.conflicts:
            other = all_packages.get(conflict.package_id)
            if other and version_matches(other.version, conflict.version):
                raise DependencyResolutionError(
                    f"{manifest.id} conflicts with {other.id} {other.version}"
                )
        for dependency in manifest.dependencies:
            target = all_packages.get(dependency.package_id)
            if target is None:
                if dependency.optional:
                    continue
                raise DependencyResolutionError(
                    f"{manifest.id} requires missing package "
                    f"{dependency.package_id} {dependency.version}"
                )
            if not version_matches(target.version, dependency.version):
                raise DependencyResolutionError(
                    f"{manifest.id} requires {dependency.package_id} {dependency.version}; "
                    f"found {target.version}"
                )

    resolve_capabilities(all_packages)

    visiting: set[str] = set()
    visited: set[str] = set()
    ordered: list[PackageManifest] = []

    def visit(package_id: str, trail: tuple[str, ...]) -> None:
        if package_id in visited:
            return
        if package_id in visiting:
            cycle = " -> ".join((*trail, package_id))
            raise DependencyResolutionError(f"dependency cycle: {cycle}")
        visiting.add(package_id)
        manifest = all_packages[package_id]
        for dependency in manifest.dependencies:
            if dependency.package_id not in all_packages:
                # Missing required dependencies were rejected above and missing
                # optional dependencies do not participate in the graph.
                continue
            visit(dependency.package_id, (*trail, package_id))
        visiting.remove(package_id)
        visited.add(package_id)
        if package_id in candidates:
            ordered.append(candidates[package_id])

    for package_id in sorted(candidates):
        visit(package_id, ())
    return ordered


def resolve_capabilities(packages: Mapping[str, PackageManifest]) -> None:
    """Fail closed when a required shared capability is not provided.

    Capability ids are interchangeable contracts. Several packages may provide
    the same id; Core accepts any matching version and does not select a winner
    or interpret the capability's business meaning.
    """

    provided: dict[str, list[tuple[str, str]]] = {}
    for manifest in packages.values():
        for capability in manifest.provides:
            provided.setdefault(capability.id, []).append(
                (manifest.id, capability.version)
            )

    for manifest in packages.values():
        for requirement in manifest.requires:
            providers = provided.get(requirement.id, [])
            if any(
                version_matches(version, requirement.version)
                for _owner, version in providers
            ):
                continue
            if requirement.optional:
                continue
            if providers:
                owner, version = min(providers)
                found = f"{owner} {version}"
                if len(providers) > 1:
                    found = f"{found} (+{len(providers) - 1})"
                raise DependencyResolutionError(
                    f"{manifest.id} requires capability {requirement.id} "
                    f"{requirement.version}; found {found}"
                )
            raise DependencyResolutionError(
                f"{manifest.id} requires missing capability {requirement.id} "
                f"{requirement.version}"
            )