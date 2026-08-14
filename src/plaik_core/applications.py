"""Independent Installer, Admin and Web ASGI compositions."""

from __future__ import annotations

import logging
import threading
from collections import Counter
from dataclasses import asdict

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .app import create_app as create_core_app
from .audit import AuditOutcome
from .config import CoreSettings
from .hooks import HookRegistry
from .installer import InstallState
from .observability import (
    CorrelationMiddleware,
    DiagnosticRegistry,
    StructuredEventLogger,
)
from .operation_journal import OperationStatus
from .operational_safety import (
    MaintenanceActive,
    OperationalSafetyError,
    ShutdownBarrier,
)
from .package_artifacts import PackageArtifactError
from .package_composition import build_package_manager, build_package_migration_applier
from .package_lifecycle import (
    PackageLifecycleResult,
    TransactionalPackageError,
    TransactionalPackageManager,
)
from .packages import PackageStatus
from .signing_keys import SigningKeyStoreError
from .storage import exclusive_file_lock
from .web import WebRenderError, WebRenderer
from .web_extensions import project_enabled_hooks
from .theme_operations import ThemeActivationCoordinator, ThemeOperationError
from .themes import TemplateResolver


_LOG = logging.getLogger("plaik.runtime")


class ThemeActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    theme_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")


class PackageArtifactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    artifact: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}\.zip$")


class PackageStateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    package_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")


class MaintenanceEnterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    reason: str = Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")
    expected_generation: int = Field(ge=0)


class MaintenanceExitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    expected_generation: int = Field(ge=1)


class EmergencyPackageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    package_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    expected_generation: int = Field(ge=1)


class PackageCommitEvidencePending(RuntimeError):
    """The package commit is durable but its final audit/checkpoint must retry."""


def _instrument(application: FastAPI) -> None:
    logger = StructuredEventLogger(_LOG.info)
    application.state.structured_logger = logger
    application.add_middleware(CorrelationMiddleware, logger=logger)
    shutdown = ShutdownBarrier()
    application.state.shutdown_barrier = shutdown

    @application.middleware("http")
    async def durable_shutdown_barrier(request: Request, call_next):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return await call_next(request)
        try:
            with shutdown.durable_work():
                return await call_next(request)
        except OperationalSafetyError:
            return JSONResponse(
                status_code=503,
                content={"detail": "service is shutting down"},
                headers={"Cache-Control": "no-store"},
            )

    def drain_for_shutdown() -> None:
        if not shutdown.begin_shutdown(20):
            _LOG.error("bounded shutdown drain expired")

    application.router.add_event_handler("shutdown", drain_for_shutdown)


def _safe_validation(application: FastAPI) -> None:
    @application.exception_handler(RequestValidationError)
    async def safe_validation_error(
        _request: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        details = [
            {
                "type": item.get("type", "validation_error"),
                "loc": item.get("loc", ()),
                "msg": "invalid input",
            }
            for item in error.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": details})


def _copy_state(source: FastAPI, destination: FastAPI) -> None:
    composition = getattr(source.state, "core_composition", source)
    object.__setattr__(destination.state, "_state", source.state._state)
    destination.state.core_composition = composition


def _copy_routes(source: FastAPI, destination: FastAPI, prefixes: tuple[str, ...]) -> None:
    for route in source.router.routes:
        paths = [getattr(route, "path", "")]
        included_router = getattr(route, "original_router", None)
        if included_router is not None:
            paths.extend(
                getattr(candidate, "path", "")
                for candidate in included_router.routes
            )
        if any(
            path == prefix or path.startswith(prefix + "/")
            for path in paths
            for prefix in prefixes
        ):
            destination.router.routes.append(route)


class _InitializeBeforeRouting:
    """Run a thread-safe composition initializer before Starlette route matching."""

    def __init__(self, app, *, initializer) -> None:
        self.app = app
        self.initializer = initializer

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            self.initializer()
        except Exception:
            response = JSONResponse(
                status_code=503,
                content={"detail": "Admin security services are unavailable"},
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def create_installer_app(settings: CoreSettings | None = None) -> FastAPI:
    """Create the bootstrap-only application surface."""

    runtime = settings or CoreSettings()
    core = create_core_app(runtime)
    application = FastAPI(
        title="PLAIK Installer",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    _safe_validation(application)
    _copy_state(core, application)
    _copy_routes(core, application, ("/health", "/api/install"))

    @application.get("/", response_class=HTMLResponse, include_in_schema=False)
    def installer_shell(request: Request) -> HTMLResponse:
        application.state.require_installer_access(request)
        if application.state.install_store.read() == InstallState.COMPLETED:
            raise HTTPException(status_code=410, detail="installer is closed")
        return HTMLResponse(_INSTALLER_HTML, headers={"Cache-Control": "no-store"})

    _instrument(application)
    return application


def create_admin_app(settings: CoreSettings | None = None) -> FastAPI:
    """Create the theme-independent Admin application surface."""

    runtime = settings or CoreSettings()
    core = create_core_app(runtime)
    application = FastAPI(
        title="PLAIK Admin",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    _safe_validation(application)
    _copy_state(core, application)

    @application.get("/health")
    def admin_health(response: Response) -> dict:
        state = application.state.install_store.read()
        if state != InstallState.COMPLETED:
            response.status_code = 503
            return {"status": "unavailable", "reason": "installation_incomplete"}
        try:
            maintenance = core.state.maintenance_safety_service().state()
            if maintenance.active:
                response.status_code = 503
                return {
                    "status": "maintenance",
                    "generation": maintenance.generation,
                }
            return core.state.health_check()
        except Exception:
            response.status_code = 503
            return {"status": "unavailable", "reason": "core_not_ready"}

    @application.get(runtime.admin_path, response_class=HTMLResponse)
    def admin_shell() -> HTMLResponse:
        if application.state.install_store.read() != InstallState.COMPLETED:
            raise HTTPException(status_code=503, detail="installation is incomplete")
        return HTMLResponse(_ADMIN_HTML, headers={"Cache-Control": "no-store"})

    if application.state.install_store.read() == InstallState.COMPLETED:
        auth = core.state.http_auth_service()
        application.include_router(auth.router)
        sessions, audit, operations = core.state.security_services(
            create_missing=False
        )
        del sessions
        jobs = core.state.job_queue
        diagnostics = DiagnosticRegistry()
        diagnostics.register(
            "core.installation",
            lambda: (
                application.state.install_store.read() == InstallState.COMPLETED,
                "core.installation.ready",
            ),
        )
        diagnostics.register(
            "core.audit",
            lambda: (bool(audit.verify()), "core.audit.verified"),
        )
        diagnostics.register(
            "core.operations",
            lambda: (
                operations.verify().pending_count == 0,
                "core.operations.verified",
            ),
        )
        diagnostics.register(
            "core.theme",
            lambda: (
                application.state.theme_registry.require_default().id == "default",
                "core.theme.default",
            ),
        )
        diagnostics.register(
            "core.cache",
            lambda: (
                core.state.cache.stats().entries >= 0,
                "core.cache.ready",
            ),
        )
        def require_enabled_theme(theme_id: str) -> None:
            record = application.state.package_registry.records().get(theme_id)
            if (
                record is None
                or record.manifest.type != "theme"
                or record.status != "enabled"
            ):
                raise ThemeOperationError("theme package is not enabled")

        theme_operations = ThemeActivationCoordinator(
            manager=application.state.theme_manager,
            audit=audit,
            operations=operations,
            lock_path=runtime.extension_operation_lock_path,
            target_validator=require_enabled_theme,
        )
        theme_operations.recover()
        application.state.job_queue = jobs
        application.state.diagnostics = diagnostics
        application.state.theme_operations = theme_operations

        def package_manager() -> TransactionalPackageManager:
            try:
                owner_connect = getattr(application.state, "package_owner_connect", None)
                migration_applier = build_package_migration_applier(
                    configuration=lambda: application.state.configuration_store.require(),
                    postgresql_adapter=core.state.postgresql_adapter,
                    owner_connect=owner_connect,
                )
                manager = build_package_manager(
                    runtime,
                    core_version=__version__,
                    operations=operations,
                    theme_registry=application.state.theme_registry,
                    theme_manager=application.state.theme_manager,
                    store_id_provider=lambda: (
                        application.state.configuration_store.require().store_id
                    ),
                    migration_applier=migration_applier,
                )
                manager.recover()
                reconcile_package_audits(manager)
            except (
                SigningKeyStoreError,
                PackageArtifactError,
                TransactionalPackageError,
                ValueError,
            ):
                raise SigningKeyStoreError(
                    "package trust or recovery service is unavailable"
                ) from None
            return manager

        def reconcile_package_audits(manager: TransactionalPackageManager) -> None:
            with exclusive_file_lock(runtime.data_dir / "package-audit-reconciliation"):
                events = audit.events()
                completed = {
                    event.metadata.get("operation_id")
                    for event in events
                    if event.action in {
                        "package.install",
                        "package.update",
                        "package.enable",
                        "package.disable",
                        "package.uninstall",
                    }
                    and event.outcome == AuditOutcome.SUCCESS
                }
                requested = {
                    event.metadata.get("operation_id"): event
                    for event in events
                    if event.action.endswith(".requested")
                    and event.action.startswith("package.")
                }
                records = manager.records()
                appended = False
                for identifier, state in operations.states().items():
                    if (
                        state.status != OperationStatus.SUCCEEDED
                        or not state.action.startswith("package.")
                        or state.action.endswith(".requested")
                        or identifier in completed
                    ):
                        continue
                    request_event = requested.get(identifier)
                    if request_event is None:
                        raise TransactionalPackageError(
                            "succeeded package operation has no request audit"
                        )
                    parts = state.target.split("/")
                    if len(parts) < 2 or parts[0] != "package":
                        raise TransactionalPackageError(
                            "succeeded package operation target is invalid"
                        )
                    package_id = parts[1]
                    record = records.get(package_id)
                    audit.append(
                        actor_id=request_event.actor_id,
                        action=state.action,
                        target_type="platform.package",
                        target_id=package_id,
                        outcome=AuditOutcome.SUCCESS,
                        metadata={
                            "operation_id": identifier,
                            "version": (
                                record.manifest.version if record is not None else None
                            ),
                            "status": (
                                record.status.value if record is not None else None
                            ),
                            "reconciled": True,
                        },
                    )
                    appended = True
                if appended:
                    core.state.anchor_journals()

        read_platform = auth.require_permission("core.platform.read")
        mutate_theme = auth.require_mutation("core.theme.manage")
        mutate_packages = auth.require_mutation("core.package.manage")
        mutate_operations = auth.require_mutation("core.operations.manage")
        operational_safety = core.state.maintenance_safety_service()

        def require_operational_write() -> None:
            try:
                operational_safety.require_writable()
            except MaintenanceActive:
                raise HTTPException(
                    status_code=503,
                    detail="privileged writes are frozen by maintenance",
                    headers={"Cache-Control": "no-store"},
                ) from None

        @application.get("/api/admin/maintenance")
        def maintenance_status(principal=Depends(read_platform)) -> dict:
            del principal
            return asdict(operational_safety.state())

        @application.post("/api/admin/maintenance/enter")
        def enter_maintenance(
            payload: MaintenanceEnterRequest,
            principal=Depends(mutate_operations),
        ) -> dict:
            try:
                state = operational_safety.enter(
                    payload.operation_id, actor_id=principal.user_id,
                    reason=payload.reason,
                    expected_generation=payload.expected_generation,
                )
            except OperationalSafetyError as error:
                raise HTTPException(status_code=409, detail=str(error)) from None
            return asdict(state)

        @application.post("/api/admin/maintenance/exit")
        def exit_maintenance(
            payload: MaintenanceExitRequest,
            principal=Depends(mutate_operations),
        ) -> dict:
            try:
                state = operational_safety.exit(
                    payload.operation_id, actor_id=principal.user_id,
                    expected_generation=payload.expected_generation,
                    validate_invariants=lambda: core.state.health_check(),
                )
            except OperationalSafetyError as error:
                raise HTTPException(status_code=409, detail=str(error)) from None
            return asdict(state)

        @application.post("/api/admin/emergency/packages/quarantine")
        def emergency_quarantine_package(
            payload: EmergencyPackageRequest,
            principal=Depends(mutate_operations),
        ) -> dict:
            state = operational_safety.state()
            if not state.active or state.generation != payload.expected_generation:
                raise HTTPException(
                    status_code=409,
                    detail="matching active maintenance generation is required",
                )
            try:
                with exclusive_file_lock(runtime.extension_operation_lock_path):
                    record = application.state.package_registry.quarantine(
                        payload.package_id
                    )
                    for registry in (
                        core.state.service_registry,
                        core.state.event_bus,
                        core.state.render_slots,
                    ):
                        registry.deactivate_owner(payload.package_id)
                    core.state.permission_catalog.set_package_active(
                        payload.package_id, active=False
                    )
                    core.state.cache.invalidate_namespace(payload.package_id)
                    event = audit.append(
                        actor_id=principal.user_id,
                        action="emergency.package.quarantine",
                        target_type="platform.package",
                        target_id=payload.package_id,
                        outcome=AuditOutcome.SUCCESS,
                        metadata={
                            "incident_id": payload.incident_id,
                            "maintenance_generation": state.generation,
                            "status": record.status.value,
                        },
                    )
                    core.state.anchor_audit_event(event)
            except Exception as error:
                if isinstance(error, HTTPException):
                    raise
                raise HTTPException(
                    status_code=409, detail="emergency quarantine failed"
                ) from None
            return {
                "incident_id": payload.incident_id,
                "package_id": payload.package_id,
                "status": "disabled",
                "maintenance_generation": state.generation,
            }

        @application.get("/api/admin/diagnostics")
        def run_diagnostics(principal=Depends(read_platform)) -> dict:
            results = diagnostics.run()
            audit.append(
                actor_id=principal.user_id,
                action="core.diagnostics.read",
                target_type="core.diagnostics",
                outcome=AuditOutcome.SUCCESS,
                metadata={"checks": len(results)},
            )
            core.state.anchor_journals()
            return {
                "passed": all(item.passed for item in results),
                "checks": [item.model_dump(mode="json") for item in results],
            }

        @application.get("/api/admin/jobs")
        def job_summary(principal=Depends(read_platform)) -> dict:
            records = jobs.records()
            counts = Counter(record.status.value for record in records.values())
            audit.append(
                actor_id=principal.user_id,
                action="core.jobs.read",
                target_type="core.job-queue",
                outcome=AuditOutcome.SUCCESS,
                metadata={"count": len(records)},
            )
            core.state.anchor_journals()
            return {"count": len(records), "status": dict(sorted(counts.items()))}

        @application.get("/api/admin/themes/active")
        def admin_active_theme(principal=Depends(read_platform)) -> dict:
            configuration = application.state.configuration_store.require()
            selected = application.state.theme_manager.state.selection(
                configuration.store_id
            )
            audit.append(
                actor_id=principal.user_id,
                action="theme.selection.read",
                target_type="store.theme",
                target_id=configuration.store_id,
                outcome=AuditOutcome.SUCCESS,
            )
            core.state.anchor_journals()
            return selected.model_dump(mode="json")

        @application.post("/api/admin/themes/active")
        def activate_theme(
            payload: ThemeActivationRequest,
            principal=Depends(mutate_theme),
        ) -> dict:
            require_operational_write()
            configuration = application.state.configuration_store.require()
            records = application.state.package_registry.records()
            record = records.get(payload.theme_id)
            if (
                record is None
                or record.manifest.type != "theme"
                or record.status != "enabled"
            ):
                raise HTTPException(
                    status_code=409,
                    detail="theme package must be installed and enabled",
                )
            try:
                selected = theme_operations.activate(
                    payload.theme_id,
                    store_id=configuration.store_id,
                    actor_id=principal.user_id,
                )
            except ThemeOperationError:
                raise HTTPException(
                    status_code=409,
                    detail="theme activation failed",
                ) from None
            core.state.anchor_journals()
            return selected.model_dump(mode="json")

        @application.post("/api/admin/themes/rollback")
        def rollback_theme(principal=Depends(mutate_theme)) -> dict:
            require_operational_write()
            configuration = application.state.configuration_store.require()
            try:
                selected = theme_operations.rollback(
                    store_id=configuration.store_id,
                    actor_id=principal.user_id,
                )
            except ThemeOperationError:
                raise HTTPException(
                    status_code=409,
                    detail="theme rollback failed",
                ) from None
            core.state.anchor_journals()
            return selected.model_dump(mode="json")

        def package_result(result: PackageLifecycleResult) -> dict:
            return {
                "operation_id": result.operation_id,
                "action": result.action,
                "package_id": result.package_id,
                "version": result.version,
                "status": result.status,
                "idempotent_replay": result.idempotent_replay,
            }

        def audit_package_result(
            result: PackageLifecycleResult,
            *,
            actor_id: str,
        ) -> dict:
            runtime_registries = (
                core.state.service_registry,
                core.state.event_bus,
                core.state.render_slots,
            )
            catalog = core.state.permission_catalog
            records = core.state.package_registry.records()
            record = records.get(result.package_id)
            if result.action in {"install", "update"} and record is not None:
                catalog.sync_manifest(
                    record.manifest,
                    active=record.status == PackageStatus.ENABLED,
                )
            if result.action == "enable":
                for registry in runtime_registries:
                    registry.activate_owner(result.package_id)
                if record is not None:
                    catalog.sync_manifest(record.manifest, active=True)
                else:
                    catalog.set_package_active(result.package_id, active=True)
            elif result.action == "disable":
                for registry in runtime_registries:
                    registry.deactivate_owner(result.package_id)
                catalog.set_package_active(result.package_id, active=False)
            elif result.action == "uninstall":
                for registry in runtime_registries:
                    registry.deactivate_owner(result.package_id)
                catalog.retain_package(result.package_id)
            if result.action in {"update", "disable", "uninstall"}:
                core.state.cache.invalidate_namespace(result.package_id)
            try:
                action = f"package.{result.action}"
                if not any(
                    event.action == action
                    and event.outcome == AuditOutcome.SUCCESS
                    and event.metadata.get("operation_id") == result.operation_id
                    for event in audit.events()
                ):
                    audit.append(
                        actor_id=actor_id,
                        action=action,
                        target_type="platform.package",
                        target_id=result.package_id,
                        outcome=AuditOutcome.SUCCESS,
                        metadata={
                            "operation_id": result.operation_id,
                            "version": result.version,
                            "status": (
                                result.status.value if result.status else None
                            ),
                            "idempotent_replay": result.idempotent_replay,
                        },
                    )
                core.state.anchor_journals()
            except Exception:
                raise PackageCommitEvidencePending(
                    "package commit evidence is pending"
                ) from None
            return package_result(result)

        def package_failure(
            *,
            action: str,
            target_id: str,
            operation_id: str,
            actor_id: str,
            error: Exception,
        ) -> None:
            audit.append(
                actor_id=actor_id,
                action=f"package.{action}",
                target_type="platform.package",
                target_id=target_id,
                outcome=AuditOutcome.FAILURE,
                metadata={
                    "operation_id": operation_id,
                    "error_code": f"package.{type(error).__name__.casefold()}"[:128],
                },
            )
            core.state.anchor_journals()

        def package_operation_pending(operation_id: str) -> bool:
            """Fail closed when a package attempt has no terminal journal decision."""

            try:
                state = operations.state(operation_id)
            except Exception:
                return True
            return state is not None and state.status == OperationStatus.STARTED

        def raise_package_recovery_required(operation_id: str) -> None:
            if package_operation_pending(operation_id):
                raise HTTPException(
                    status_code=503,
                    detail="package recovery is required",
                    headers={"Cache-Control": "no-store"},
                ) from None

        def audit_package_request(
            *,
            action: str,
            target_id: str,
            operation_id: str,
            actor_id: str,
        ) -> None:
            requested_action = f"package.{action}.requested"
            if not any(
                event.action == requested_action
                and event.metadata.get("operation_id") == operation_id
                for event in audit.events()
            ):
                audit.append(
                    actor_id=actor_id,
                    action=requested_action,
                    target_type="platform.package",
                    target_id=target_id,
                    outcome=AuditOutcome.SUCCESS,
                    metadata={"operation_id": operation_id},
                )
                core.state.anchor_journals()

        @application.get("/api/admin/packages")
        def list_packages(principal=Depends(read_platform)) -> dict:
            try:
                records = package_manager().records()
            except SigningKeyStoreError as error:
                audit.append(
                    actor_id=principal.user_id,
                    action="package.registry.read",
                    target_type="platform.package-registry",
                    outcome=AuditOutcome.FAILURE,
                    metadata={"error_code": "package.trust_unavailable"},
                )
                core.state.anchor_journals()
                raise HTTPException(
                    status_code=503,
                    detail="package trust or recovery service is unavailable",
                ) from error
            audit.append(
                actor_id=principal.user_id,
                action="package.registry.read",
                target_type="platform.package-registry",
                outcome=AuditOutcome.SUCCESS,
                metadata={"count": len(records)},
            )
            core.state.anchor_journals()
            return {
                "packages": {
                    package_id: record.model_dump(mode="json")
                    for package_id, record in sorted(records.items())
                }
            }

        def artifact_operation(
            action: str,
            payload: PackageArtifactRequest,
            actor_id: str,
        ) -> dict:
            artifact = runtime.package_inbox_dir / payload.artifact
            signature = runtime.package_inbox_dir / f"{payload.artifact}.sig.json"
            audit_package_request(
                action=action,
                target_id=payload.artifact,
                operation_id=payload.operation_id,
                actor_id=actor_id,
            )
            try:
                manager = package_manager()
                method = manager.install if action == "install" else manager.update
                result = method(payload.operation_id, artifact, signature)
                return audit_package_result(result, actor_id=actor_id)
            except PackageCommitEvidencePending:
                raise HTTPException(
                    status_code=503,
                    detail="package committed; audit checkpoint retry required",
                ) from None
            except SigningKeyStoreError as error:
                raise_package_recovery_required(payload.operation_id)
                package_failure(
                    action=action,
                    target_id="artifact",
                    operation_id=payload.operation_id,
                    actor_id=actor_id,
                    error=error,
                )
                raise HTTPException(
                    status_code=503,
                    detail="package trust or recovery service is unavailable",
                ) from None
            except TransactionalPackageError as error:
                raise_package_recovery_required(payload.operation_id)
                package_failure(
                    action=action,
                    target_id="artifact",
                    operation_id=payload.operation_id,
                    actor_id=actor_id,
                    error=error,
                )
                raise HTTPException(
                    status_code=409,
                    detail=f"package {action} failed",
                ) from None
            except PackageArtifactError as error:
                package_failure(
                    action=action,
                    target_id="artifact",
                    operation_id=payload.operation_id,
                    actor_id=actor_id,
                    error=error,
                )
                raise HTTPException(
                    status_code=409,
                    detail=f"package {action} failed",
                ) from None

        @application.post("/api/admin/packages/install")
        def install_package(
            payload: PackageArtifactRequest,
            principal=Depends(mutate_packages),
        ) -> dict:
            require_operational_write()
            return artifact_operation("install", payload, principal.user_id)

        @application.post("/api/admin/packages/update")
        def update_package(
            payload: PackageArtifactRequest,
            principal=Depends(mutate_packages),
        ) -> dict:
            require_operational_write()
            return artifact_operation("update", payload, principal.user_id)

        def state_operation(
            action: str,
            payload: PackageStateRequest,
            actor_id: str,
        ) -> dict:
            audit_package_request(
                action=action,
                target_id=payload.package_id,
                operation_id=payload.operation_id,
                actor_id=actor_id,
            )
            try:
                manager = package_manager()
                method = getattr(manager, action)
                result = method(payload.operation_id, payload.package_id)
                return audit_package_result(result, actor_id=actor_id)
            except PackageCommitEvidencePending:
                raise HTTPException(
                    status_code=503,
                    detail="package committed; audit checkpoint retry required",
                ) from None
            except SigningKeyStoreError as error:
                raise_package_recovery_required(payload.operation_id)
                package_failure(
                    action=action,
                    target_id=payload.package_id,
                    operation_id=payload.operation_id,
                    actor_id=actor_id,
                    error=error,
                )
                raise HTTPException(
                    status_code=503,
                    detail="package trust or recovery service is unavailable",
                ) from None
            except TransactionalPackageError as error:
                raise_package_recovery_required(payload.operation_id)
                package_failure(
                    action=action,
                    target_id=payload.package_id,
                    operation_id=payload.operation_id,
                    actor_id=actor_id,
                    error=error,
                )
                raise HTTPException(
                    status_code=409,
                    detail=f"package {action} failed",
                ) from None

        @application.post("/api/admin/packages/enable")
        def enable_package(
            payload: PackageStateRequest,
            principal=Depends(mutate_packages),
        ) -> dict:
            require_operational_write()
            return state_operation("enable", payload, principal.user_id)

        @application.post("/api/admin/packages/disable")
        def disable_package(
            payload: PackageStateRequest,
            principal=Depends(mutate_packages),
        ) -> dict:
            require_operational_write()
            return state_operation("disable", payload, principal.user_id)

        @application.post("/api/admin/packages/uninstall")
        def uninstall_package(
            payload: PackageStateRequest,
            principal=Depends(mutate_packages),
        ) -> dict:
            require_operational_write()
            return state_operation("uninstall", payload, principal.user_id)

    else:
        initialization_lock = threading.Lock()
        initialized = False

        def initialize_after_installation() -> None:
            nonlocal initialized
            if initialized or application.state.install_store.read() != InstallState.COMPLETED:
                return
            with initialization_lock:
                if initialized:
                    return
                installed = create_admin_app(runtime)
                _copy_routes(installed, application, ("/api/auth", "/api/admin"))
                _copy_state(installed, application)
                initialized = True

        application.add_middleware(
            _InitializeBeforeRouting,
            initializer=initialize_after_installation,
        )

    _instrument(application)
    return application


def create_web_app(settings: CoreSettings | None = None) -> FastAPI:
    """Create the public SSR application without Installer or Admin routes."""

    runtime = settings or CoreSettings()
    core = create_core_app(runtime)
    registry = core.state.theme_registry
    manager = core.state.theme_manager
    default_theme = registry.require_default()
    allowed_hooks = set(default_theme.hooks)
    for theme in registry.discover().values():
        allowed_hooks.update(theme.hooks)
    renderer = WebRenderer(
        theme_manager=manager,
        theme_registry=registry,
        hook_registry=HookRegistry(allowed_hooks),
        template_resolver=TemplateResolver(
            registry,
            runtime.modules_dir,
            (runtime.installed_packages_dir,),
        ),
    )
    application = FastAPI(
        title="PLAIK Web",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    _safe_validation(application)
    application.state.public_projection_version = 1

    def require_web_ready() -> dict:
        if core.state.install_store.read() != InstallState.COMPLETED:
            raise HTTPException(
                status_code=503,
                detail="web is unavailable until installation completes",
            )
        try:
            return core.state.public_health_check()
        except Exception:
            raise HTTPException(
                status_code=503,
                detail="web readiness check failed",
            ) from None

    @application.get("/health")
    def web_health() -> dict:
        return require_web_ready()

    @application.get("/", response_class=HTMLResponse)
    def web_home() -> HTMLResponse:
        require_web_ready()
        configuration = core.state.configuration_store.require()
        store_id = configuration.store_id
        locale = configuration.locale
        brand = " ".join(
            part.capitalize()
            for part in store_id.removesuffix("-test").split("-")
            if part
        ) or "PLAIK"
        public_url = str(configuration.public_url).rstrip("/")
        try:
            rendered = renderer.render(
                store_id=store_id,
                locale=locale,
                page_title=f"{brand} — PLAIK",
                context={"brand": brand, "public_url": public_url},
            )
        except WebRenderError:
            raise HTTPException(
                status_code=503,
                detail="web rendering is unavailable",
            ) from None
        return HTMLResponse(
            rendered.html,
            headers={
                "Content-Language": locale,
                "X-Web-Theme": rendered.theme_id,
            },
        )

    @application.get("/robots.txt", response_class=Response)
    def web_robots() -> Response:
        require_web_ready()
        public_url = str(core.state.configuration_store.require().public_url).rstrip("/")
        return Response(
            f"User-agent: *\nAllow: /\nSitemap: {public_url}/sitemap.xml\n",
            media_type="text/plain",
        )

    @application.get("/sitemap.xml", response_class=Response)
    def web_sitemap() -> Response:
        require_web_ready()
        public_url = str(core.state.configuration_store.require().public_url).rstrip("/")
        return Response(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"<url><loc>{public_url}/</loc></url>"
            "</urlset>\n",
            media_type="application/xml",
        )

    @application.get("/favicon.ico", response_class=Response)
    def web_favicon() -> Response:
        require_web_ready()
        return Response(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            '<rect width="64" height="64" rx="14" fill="#1457d9"/>'
            '<path d="M17 43V21h8l7 11 7-11h8v22h-8V33l-7 10-7-10v10z" fill="white"/>'
            "</svg>",
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @application.get("/themes/{theme_id}/{asset_path:path}")
    def theme_asset(theme_id: str, asset_path: str) -> FileResponse:
        require_web_ready()
        try:
            path = renderer.asset_path(theme_id, asset_path)
        except WebRenderError:
            raise HTTPException(status_code=404, detail="asset not found") from None
        return FileResponse(path, headers={"X-Content-Type-Options": "nosniff"})

    _instrument(application)
    return application


_INSTALLER_HTML = """<!doctype html>
<html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PLAIK Installer</title><style>
:root{color-scheme:light;font-family:system-ui,sans-serif;background:#f5f6f8;color:#171719}
main{max-width:44rem;margin:8vh auto;padding:2rem;background:white;border:1px solid #dfe2e8;border-radius:1rem}
code{background:#eef1f6;padding:.15rem .35rem;border-radius:.25rem}
</style></head><body><main><h1>PLAIK Installer</h1>
<p>Bootstrap API is available under <code>/api/install</code>.</p></main></body></html>"""


_ADMIN_HTML = """<!doctype html>
<html lang="uk" data-plaik-admin><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PLAIK Admin</title><style>
[data-plaik-admin]{color-scheme:dark;font-family:system-ui,sans-serif;background:#111318;color:#f4f6fb}
[data-plaik-admin] body{margin:0}[data-plaik-admin] main{max-width:64rem;margin:8vh auto;padding:2rem}
[data-plaik-admin] .card{background:#1a1e26;border:1px solid #303745;border-radius:1rem;padding:1.5rem}
</style></head><body><main><section class="card"><h1>PLAIK Admin</h1>
<p>Увійдіть через захищений сеансовий API.</p></section></main></body></html>"""
