"""Composition of trust, package transactions, themes and Web hooks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from plaik_contracts import PackageManifest, PackageType

from .config import CoreSettings
from .installer_config import InstallerConfiguration, PostgreSQLDatabase
from .operation_journal import OperationJournal
from .package_artifacts import Ed25519SignatureVerifier, PackageArtifactVerifier
from .package_declarations import (
    PackageDeclarationError,
    validate_manifest_declaration_files,
)
from .package_lifecycle import (
    PackageMigrationApplier,
    TransactionalPackageError,
    TransactionalPackageManager,
)
from .package_migrations import OwnerConnectionFactory
from .package_postgresql_coordinator import PackagePostgreSQLPreparedCoordinator
from .package_sql_lifecycle import CrashAtomicPackageManager, PackageSQLCoordinator
from .packages import PackageRecord, PackageStatus
from .postgresql import PostgreSQLAdapter
from .signing_keys import load_package_trust_policy
from .web_extensions import validate_staged_web
from .themes import ThemeManager, ThemeRegistry


_PACKAGE_SQL_SQLITE_DISABLED = (
    "package SQL migrations require the PostgreSQL crash-atomic coordinator"
)
_PACKAGE_SQL_OWNER_REQUIRED = (
    "package SQL migrations require an owner-authenticated PostgreSQL connection factory"
)


def build_package_sql_coordinator(
    *,
    configuration: Callable[[], InstallerConfiguration],
    postgresql_adapter: Callable[[], PostgreSQLAdapter],
    owner_connect: OwnerConnectionFactory | None,
) -> PackageSQLCoordinator | None:
    """Compose the PostgreSQL 2PC participant, or keep non-PostgreSQL fail-closed."""

    configured = configuration()
    if not isinstance(configured.database, PostgreSQLDatabase):
        return None
    if owner_connect is None:
        raise TransactionalPackageError(_PACKAGE_SQL_OWNER_REQUIRED)
    adapter = postgresql_adapter()
    return PackagePostgreSQLPreparedCoordinator(
        adapter.connect,
        owner_connect,
        lock_connect=adapter.connect,
    )


def build_package_migration_applier(
    *,
    configuration: Callable[[], InstallerConfiguration],
    postgresql_adapter: Callable[[], PostgreSQLAdapter],
    owner_connect: OwnerConnectionFactory | None,
) -> PackageMigrationApplier:
    """Compatibility boundary for the legacy early-commit callback.

    Package SQL must no longer be executed through this callback. PostgreSQL SQL
    is composed through ``build_package_sql_coordinator`` and
    ``CrashAtomicPackageManager``; SQLite remains explicitly unsupported.
    """

    del postgresql_adapter, owner_connect

    def apply(package_root: Path, manifest: PackageManifest) -> None:
        del package_root
        if not manifest.migrations:
            return
        configured = configuration()
        if isinstance(configured.database, PostgreSQLDatabase):
            raise TransactionalPackageError(
                "package SQL must use the crash-atomic PostgreSQL coordinator"
            )
        raise TransactionalPackageError(_PACKAGE_SQL_SQLITE_DISABLED)

    return apply


def build_package_manager(
    runtime: CoreSettings,
    *,
    core_version: str,
    operations: OperationJournal,
    theme_registry: ThemeRegistry,
    theme_manager: ThemeManager,
    store_id_provider: Callable[[], str],
    migration_applier: PackageMigrationApplier | None = None,
    sql_coordinator: PackageSQLCoordinator | None = None,
    occupancy_reset: Callable[[str], None] | None = None,
) -> TransactionalPackageManager:
    """Build one mutation-scoped manager from a fresh package trust snapshot."""

    if migration_applier is not None and sql_coordinator is not None:
        raise TransactionalPackageError(
            "package SQL cannot compose legacy and crash-atomic executors together"
        )

    policy = load_package_trust_policy(runtime.trusted_package_signing_keys_path)
    verifier = PackageArtifactVerifier(
        Ed25519SignatureVerifier(policy.public_keys),
        authorization=policy.authorizes,
    )

    def allowed_hooks() -> set[str]:
        hooks: set[str] = set()
        for theme in theme_registry.discover().values():
            hooks.update(theme.hooks)
        return hooks

    def allowed_slots() -> set[str]:
        slots: set[str] = set()
        for theme in theme_registry.discover().values():
            slots.update(theme.slots)
        return slots

    def available_themes(
        records: Mapping[str, PackageRecord],
        *,
        enabled_only: bool,
    ) -> set[str]:
        return {
            "default",
            *(
                package_id
                for package_id, record in records.items()
                if record.manifest.type == PackageType.THEME
                and (not enabled_only or record.status == PackageStatus.ENABLED)
            ),
        }

    def validate_stage(
        staging: Path,
        manifest: PackageManifest,
        before: Mapping[str, PackageRecord],
    ) -> None:
        try:
            validate_manifest_declaration_files(staging, manifest)
            if manifest.type == PackageType.THEME:
                existing = before.get(manifest.id)
                theme_registry.validate_candidate(
                    staging,
                    manifest,
                    available_themes(
                        before,
                        enabled_only=(
                            existing is not None
                            and existing.status == PackageStatus.ENABLED
                        ),
                    ),
                )
            else:
                validate_staged_web(
                    staging,
                    manifest,
                    allowed_hooks=allowed_hooks(),
                    allowed_slots=allowed_slots(),
                )
        except PackageDeclarationError as error:
            raise TransactionalPackageError(str(error)) from None
        except Exception:
            raise TransactionalPackageError(
                "package presentation contract is invalid"
            ) from None

    def validate_state(
        action: str,
        package_id: str,
        record: PackageRecord,
        records: Mapping[str, PackageRecord],
    ) -> None:
        try:
            if record.manifest.type == PackageType.THEME:
                if action in {"disable", "uninstall"} and (
                    theme_manager.state.get(store_id_provider()) == package_id
                ):
                    raise TransactionalPackageError(
                        "active theme cannot be disabled or uninstalled"
                    )
                if action == "enable":
                    theme_registry.validate_candidate(
                        runtime.installed_packages_dir / package_id,
                        record.manifest,
                        available_themes(records, enabled_only=True),
                    )
            elif action == "enable":
                package_root = runtime.installed_packages_dir / package_id
                validate_manifest_declaration_files(package_root, record.manifest)
                validate_staged_web(
                    package_root,
                    record.manifest,
                    allowed_hooks=allowed_hooks(),
                    allowed_slots=allowed_slots(),
                )
        except TransactionalPackageError:
            raise
        except PackageDeclarationError as error:
            raise TransactionalPackageError(str(error)) from None
        except Exception:
            raise TransactionalPackageError(
                "package cannot enter the requested runtime state"
            ) from None

    manager_type = CrashAtomicPackageManager if sql_coordinator is not None else TransactionalPackageManager
    manager_kwargs = dict(
        registry_path=runtime.package_registry_path,
        packages_root=runtime.installed_packages_dir,
        transaction_root=runtime.package_transactions_dir,
        core_version=core_version,
        artifact_verifier=verifier,
        operation_journal=operations,
        protected_ids={"default"},
        signer_transition_authorizer=lambda package_id, package_type, previous, next_: (
            policy.authorizes_transfer(
                package_id=package_id,
                package_type=package_type,
                previous_key_id=previous,
                next_key_id=next_,
            )
        ),
        stage_validator=validate_stage,
        state_validator=validate_state,
        migration_applier=migration_applier,
        occupancy_reset=occupancy_reset,
        lock_target=runtime.extension_operation_lock_path,
    )
    if sql_coordinator is not None:
        manager_kwargs["sql_coordinator"] = sql_coordinator
    return manager_type(**manager_kwargs)
