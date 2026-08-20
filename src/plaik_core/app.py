"""Runnable Platform v2 bootstrap API."""

import hashlib
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from plaik_contracts import PackageManifest, SecretReference

from . import __version__
from .audit import AuditEvent, AuditLog, AuditOutcome
from .cache import NamespacedTTLCache
from .config import CoreSettings
from .core_schema import (
    CORE_MIGRATIONS,
    initialize_reference_context,
    verify_reference_context,
)
from .database import ConnectionFactory, DatabasePreflightError, preflight_connection
from .identity import IdentityError, IdentityStore, SessionStore
from .http_auth import LoginRateLimiter, RateLimitExceeded
from .integrity import (
    FileCheckpointStore,
    IntegrityCheckpointError,
    JournalKind,
)
from .postgresql_integrity import PostgreSQLCheckpointStore
from .remote_control import RemoteControlStore
from .installer import (
    INSTALL_SEQUENCE,
    InstallState,
    InstallStateStore,
    InvalidInstallTransition,
)
from .installer_recovery import InstallerRecoveryCoordinator
from .installer_config import (
    InstallerConfiguration,
    InstallerConfigurationError,
    InstallerConfigurationStore,
    PostgreSQLDatabase,
    SQLiteDatabase,
)
from .migrations import MigrationError, MigrationRunner
from .jobs import DelegatingJobQueue, DurableJobQueue, JobDrainPump, JobRunner
from .extension_runtime import EventBus, RenderSlotRegistry, ServiceRegistry
from .event_outbox import DelegatingDurableEvents, SqliteDurableEvents
from .operation_journal import OperationJournal, OperationStatus
from .operational_safety import MaintenanceController
from .package_declarations import PackagePermissionCatalog
from .packages import PackageRegistry, PackageStatus
from .package_sql_session import PackageSqlUnavailable
from .postgresql import PostgreSQLAdapter, PostgreSQLAdapterError
from .postgresql_outbox_runtime import PostgreSQLDurableEvents
from .postgresql_job_queue import PostgreSQLJobQueue
from .postgresql_security import (
    DelegatingStore,
    PostgreSQLAuditLog,
    PostgreSQLIdentityStore,
    PostgreSQLOperationJournal,
    PostgreSQLSessionStore,
)
from .requirements import RequirementsNotMet, SystemRequirements
from .secret_store import (
    EnvironmentSecretProvider,
    LocalFileSecretProvider,
    SecretProviderRegistry,
    SecretStoreError,
)
from .service_control import (
    ServiceControlError,
    handoff_is_ready,
    handoff_snapshot,
    request_database_provision,
    request_service_finalization,
)
from .connection_store import ConnectionStore
from .extension_host import ExtensionHost
from .health_issues import HealthIssueRegistry
from .settings_store import SettingsStore, settings_events_to_audit_sink
from .postgresql_settings_store import PostgreSQLSettingsStore
from .storage import exclusive_file_lock, read_json
from .theme_revisions import ThemeRevisionStore
from .themes import ActiveThemeStore, ThemeManager, ThemeRegistry


class TransitionRequest(BaseModel):
    target: InstallState


class AdminBootstrapRequest(BaseModel):
    email: str
    password: SecretStr


class InstallerProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(pattern=r"^(127\.0\.0\.1|localhost|::1)$")
    port: int = Field(ge=1, le=65535)
    database: str = Field(pattern=r"^[a-z][a-z0-9_]{2,62}$")
    username: str = Field(pattern=r"^[a-z][a-z0-9_]{2,62}$")
    runtime_username: str = Field(pattern=r"^[a-z][a-z0-9_]{2,62}$")
    checkpoint_username: str = Field(pattern=r"^[a-z][a-z0-9_]{2,62}$")


class InstallerCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    migrator_password: SecretStr
    runtime_password: SecretStr
    checkpoint_password: SecretStr

    @field_validator(
        "migrator_password", "runtime_password", "checkpoint_password"
    )
    @classmethod
    def validate_secret_length(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 12 or len(raw.encode("utf-8")) > 256:
            raise ValueError("password length is invalid")
        return value


def create_app(settings: CoreSettings | None = None) -> FastAPI:
    runtime = settings or CoreSettings()
    install_store = InstallStateStore(runtime.install_state_path)
    package_registry = PackageRegistry(
        runtime.package_registry_path,
        core_version=__version__,
        protected_ids={"default"},
    )
    if runtime.package_registry_path.is_file():
        with exclusive_file_lock(runtime.install_operation_lock_path):
            with exclusive_file_lock(runtime.extension_operation_lock_path):
                package_registry.persist_legacy_cleanup()

    def enabled_theme_package_ids() -> set[str]:
        return {
            package_id
            for package_id, record in package_registry.records().items()
            if record.manifest.type == "theme"
            and record.status == PackageStatus.ENABLED
        }

    theme_registry = ThemeRegistry(
        runtime.themes_dir,
        (runtime.installed_packages_dir,),
        enabled_package_ids=enabled_theme_package_ids,
    )
    theme_manager = ThemeManager(theme_registry, ActiveThemeStore(runtime.active_themes_path))
    theme_revision_store = ThemeRevisionStore(
        runtime.theme_revisions_path,
        theme_registry=theme_registry,
    )
    system_requirements = SystemRequirements(runtime)
    configuration_store = InstallerConfigurationStore(runtime.installer_config_path)
    identity_store_json = IdentityStore(runtime.identity_registry_path)

    def postgresql_security_backend_ready() -> bool:
        state = install_store.read()
        if (
            INSTALL_SEQUENCE.index(state)
            < INSTALL_SEQUENCE.index(InstallState.DATABASE_READY)
        ):
            return False
        try:
            configured = configuration_store.require()
        except Exception:
            return False
        return isinstance(configured.database, PostgreSQLDatabase)

    def resolve_identity_store() -> IdentityStore | PostgreSQLIdentityStore:
        if not postgresql_security_backend_ready():
            return identity_store_json
        configured = configuration_store.require()
        return PostgreSQLIdentityStore(postgresql_adapter(configured).runtime_connect)

    identity_store = DelegatingStore(resolve_identity_store)
    runtime_cache = NamespacedTTLCache()
    json_jobs = DurableJobQueue(runtime.jobs_registry_path)
    pg_jobs_holder: dict[str, PostgreSQLJobQueue | None] = {"queue": None}

    def resolve_job_queue() -> DurableJobQueue | PostgreSQLJobQueue:
        if postgresql_security_backend_ready():
            queue = pg_jobs_holder["queue"]
            if queue is not None:
                return queue
        return json_jobs

    job_queue = DelegatingJobQueue(resolve_job_queue, fallback=json_jobs)
    service_registry = ServiceRegistry()
    event_bus = EventBus()
    sqlite_events = SqliteDurableEvents(
        runtime.event_outbox_path,
        event_bus,
        dispatch_after_enqueue=False,
    )
    pg_events_holder: dict[str, PostgreSQLDurableEvents | None] = {"events": None}

    def resolve_durable_events() -> SqliteDurableEvents | PostgreSQLDurableEvents:
        if postgresql_security_backend_ready():
            events = pg_events_holder["events"]
            if events is not None:
                return events
        return sqlite_events

    durable_events = DelegatingDurableEvents(
        resolve_durable_events,
        fallback=sqlite_events,
    )
    render_slots = RenderSlotRegistry()
    permission_catalog = PackagePermissionCatalog(
        runtime.package_permission_catalog_path
    )
    connection_store = ConnectionStore(runtime.connections_path)
    health_issues = HealthIssueRegistry()
    json_settings_store = SettingsStore(runtime.settings_registry_path, {})
    pg_settings_holder: dict[str, PostgreSQLSettingsStore | None] = {"store": None}
    package_sql_connect_holder: dict[str, Any] = {"connect": None}

    def resolve_settings_store() -> SettingsStore:
        if not postgresql_security_backend_ready():
            return json_settings_store
        store = pg_settings_holder["store"]
        if store is None:
            raise RuntimeError("PostgreSQL settings store is unavailable")
        return store

    def _resolve_package_sql_connect(package_id: str):
        configured = configuration_store.read()
        if configured is None or not isinstance(configured.database, PostgreSQLDatabase):
            raise PackageSqlUnavailable("package SQL is unavailable")
        connect = package_sql_connect_holder["connect"]
        if connect is None:
            raise PackageSqlUnavailable("package SQL is unavailable")
        return connect(package_id)

    settings_store = DelegatingStore(resolve_settings_store)
    extension_host = ExtensionHost(
        packages_root=runtime.installed_packages_dir,
        service_registry=service_registry,
        event_bus=event_bus,
        event_publication=durable_events,
        render_slots=render_slots,
        job_queue=job_queue,
        connection_store=connection_store,
        health_issues=health_issues,
        settings_store=settings_store,
        package_sql_connect=_resolve_package_sql_connect,
    )
    job_runner = JobRunner(job_queue, extension_host.job_handlers)
    job_pump = JobDrainPump(job_runner)
    extension_host.set_job_drain(job_pump.drain)
    session_pepper_reference = SecretReference(
        provider="local",
        key="platform/session-pepper",
        version="v1",
    )
    audit_key_reference = SecretReference(
        provider="local",
        key="platform/audit-integrity",
        version="v1",
    )
    operation_key_reference = SecretReference(
        provider="local",
        key="platform/operation-journal-integrity",
        version="v1",
    )
    csrf_key_reference = SecretReference(
        provider="local",
        key="platform/http-csrf-integrity",
        version="v1",
    )
    checkpoint_key_reference = SecretReference(
        provider="local",
        key="platform/integrity-checkpoint",
        version="v1",
    )
    backup_key_reference = SecretReference(
        provider="local",
        key="platform/backup-integrity",
        version="v1",
    )
    maintenance_key_reference = SecretReference(
        provider="local",
        key="platform/maintenance-integrity",
        version="v1",
    )

    application = FastAPI(title="PLAIK Core", version=__version__)

    @application.exception_handler(RequestValidationError)
    async def safe_validation_error(
        _request: Request, error: RequestValidationError
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

    application.state.settings = runtime
    application.state.install_store = install_store
    application.state.theme_registry = theme_registry
    application.state.theme_manager = theme_manager
    application.state.theme_revision_store = theme_revision_store
    application.state.package_registry = package_registry
    application.state.system_requirements = system_requirements
    application.state.configuration_store = configuration_store
    application.state.identity_store = identity_store
    application.state.identity_store_json = identity_store_json
    application.state.cache = runtime_cache
    application.state.job_queue = job_queue
    application.state.job_runner = job_runner
    application.state.service_registry = service_registry
    application.state.event_bus = event_bus
    application.state.event_outbox = durable_events
    application.state.render_slots = render_slots
    application.state.permission_catalog = permission_catalog
    application.state.connection_store = connection_store
    application.state.health_issues = health_issues
    application.state.settings_store = settings_store
    application.state.extension_host = extension_host
    application.state.secret_providers = None
    application.state.session_store = None
    application.state.audit_log = None
    application.state.operation_journal = None
    application.state.http_auth = None
    application.state.maintenance_safety = None
    installer_rate_limiter = LoginRateLimiter(
        maximum_failures=5,
        window_seconds=60,
        block_seconds=300,
        maximum_clients=4096,
    )
    application.state.installer_rate_limiter = installer_rate_limiter

    def sync_extension_host() -> None:
        host: ExtensionHost = application.state.extension_host
        host.set_secret_providers(application.state.secret_providers)
        records = package_registry.records()
        durable_events.defer_dispatch()
        job_pump.deferred = True
        try:
            try:
                configuration = configuration_store.require()
            except Exception:
                host.drop_unenabled(records)
                durable_events.enable_live_dispatch()
                return
            host.sync_enabled(records, configuration)
            durable_events.recover_subscribers()
        finally:
            job_pump.deferred = False
            job_pump.drain()

    application.state.sync_extension_host = sync_extension_host

    def security_services(
        *, create_missing: bool,
    ) -> tuple[
        SessionStore | PostgreSQLSessionStore,
        AuditLog,
        OperationJournal,
    ]:
        cached_session = application.state.session_store
        cached_audit = application.state.audit_log
        cached_operations = application.state.operation_journal
        if (
            cached_session is not None
            and cached_audit is not None
            and cached_operations is not None
        ):
            if json_settings_store.audit_sink is None:
                json_settings_store.audit_sink = (
                    settings_events_to_audit_sink(cached_audit.append)
                )
            return cached_session, cached_audit, cached_operations

        local_secrets = LocalFileSecretProvider(runtime.secrets_dir)
        if os.environ.get("PLAIK_PUBLIC_SECRETS") == "1":
            from .public_secrets import PublishedRuntimeSecretProvider

            local_secrets = PublishedRuntimeSecretProvider(runtime.secrets_dir)
        providers = SecretProviderRegistry(
            (EnvironmentSecretProvider(), local_secrets)
        )
        may_generate = create_missing and install_store.read() != InstallState.COMPLETED
        if may_generate:
            session_pepper = providers.generate_if_missing(
                session_pepper_reference,
                entropy_bytes=48,
            )
            audit_integrity_key = providers.generate_if_missing(
                audit_key_reference,
                entropy_bytes=48,
            )
            operation_integrity_key = providers.generate_if_missing(
                operation_key_reference,
                entropy_bytes=48,
            )
            providers.generate_if_missing(
                csrf_key_reference,
                entropy_bytes=48,
            )
            providers.generate_if_missing(
                checkpoint_key_reference,
                entropy_bytes=48,
            )
            providers.generate_if_missing(
                backup_key_reference,
                entropy_bytes=48,
            )
            providers.generate_if_missing(
                maintenance_key_reference,
                entropy_bytes=48,
            )
        else:
            session_pepper = providers.resolve(session_pepper_reference)
            audit_integrity_key = providers.resolve(audit_key_reference)
            operation_integrity_key = providers.resolve(operation_key_reference)

        configured = None
        use_postgresql_security = postgresql_security_backend_ready()
        if use_postgresql_security:
            configured = configuration_store.require()

        audit_key = audit_integrity_key.get_secret_value().encode("utf-8")
        operation_key = operation_integrity_key.get_secret_value().encode("utf-8")
        if use_postgresql_security and configured is not None:
            adapter = postgresql_adapter(configured)
            connect = adapter.runtime_connect
            sessions = PostgreSQLSessionStore(
                connect,
                token_pepper=session_pepper.get_secret_value().encode("utf-8"),
                identity_store=identity_store,
            )
            audit = PostgreSQLAuditLog(connect, integrity_key=audit_key)
            operations = PostgreSQLOperationJournal(
                connect,
                integrity_key=operation_key,
            )
            audit.adopt_legacy_file_if_empty(runtime.audit_log_path)
            operations.adopt_legacy_file_if_empty(runtime.operation_journal_path)
        else:
            sessions = SessionStore(
                runtime.sessions_registry_path,
                token_pepper=session_pepper.get_secret_value().encode("utf-8"),
                identity_store=identity_store,
            )
            audit = AuditLog(
                runtime.audit_log_path,
                integrity_key=audit_key,
            )
            operations = OperationJournal(
                runtime.operation_journal_path,
                integrity_key=operation_key,
            )
        application.state.secret_providers = providers
        application.state.session_store = sessions
        application.state.audit_log = audit
        application.state.operation_journal = operations
        json_settings_store.audit_sink = settings_events_to_audit_sink(
            audit.append
        )
        sync_extension_host()
        return sessions, audit, operations

    def maintenance_safety() -> MaintenanceController:
        cached = application.state.maintenance_safety
        if cached is not None:
            return cached
        _sessions, audit, _operations = security_services(create_missing=False)
        providers = application.state.secret_providers
        if providers is None:
            raise RuntimeError("secret providers are unavailable")
        key = providers.resolve(maintenance_key_reference)

        def record(event: str, metadata: dict[str, object]) -> None:
            appended = audit.append(
                actor_id=str(metadata.get("actor_id") or metadata.get("resume_actor_id") or "system"),
                action=event,
                target_type="platform.maintenance",
                target_id=str(metadata.get("operation_id") or metadata.get("resume_operation_id") or "maintenance"),
                outcome=AuditOutcome.SUCCESS,
                metadata=metadata,
            )
            anchor_audit_event(appended)

        controller = MaintenanceController(
            runtime.maintenance_state_path,
            integrity_key=key.get_secret_value().encode("utf-8"),
            key_id="maintenance-integrity-v1",
            event_sink=record,
        )
        application.state.maintenance_safety = controller
        return controller

    def http_auth_service():
        """Build the installed Admin HTTP security adapter on first use."""

        cached = application.state.http_auth
        if cached is not None:
            return cached
        if install_store.read() != InstallState.COMPLETED:
            raise RuntimeError("HTTP authentication is available only after installation")
        sessions, audit, _operations = security_services(create_missing=False)
        providers = application.state.secret_providers
        if providers is None:
            raise RuntimeError("secret providers are unavailable")
        csrf_key = providers.resolve(csrf_key_reference)
        from .http_auth import HttpAuth

        def wan_control_hostname() -> str | None:
            record = RemoteControlStore(runtime.remote_control_path).read()
            if record.intent is None:
                return None
            return record.intent.control_hostname

        adapter = HttpAuth(
            identity_store,
            sessions,
            audit,
            csrf_key=csrf_key.get_secret_value().encode("utf-8"),
            audit_checkpoint=anchor_audit_event,
            wan_control_hostname=wan_control_hostname,
        )
        application.state.http_auth = adapter
        return adapter

    def integrity_checkpoint_store() -> FileCheckpointStore | PostgreSQLCheckpointStore:
        providers = application.state.secret_providers
        if providers is None:
            raise RuntimeError("secret providers are unavailable")
        checkpoint_key = providers.resolve(checkpoint_key_reference)
        integrity_key = checkpoint_key.get_secret_value().encode("utf-8")
        if postgresql_security_backend_ready():
            configured = configuration_store.require()
            connect = postgresql_adapter(configured).checkpoint_connect
            return PostgreSQLCheckpointStore(connect, integrity_key=integrity_key)
        return FileCheckpointStore(
            runtime.integrity_checkpoint_path,
            integrity_key=integrity_key,
        )

    def selected_installation_id(installation_id: str | None = None) -> str:
        configured = configuration_store.read()
        return installation_id or (
            configured.installation_id if configured is not None else "bootstrap"
        )

    def anchor_audit_event(event: AuditEvent) -> None:
        """Anchor an event whose complete audit prefix was verified before append."""

        checkpoints = integrity_checkpoint_store()
        installation_id = selected_installation_id()
        try:
            checkpoints.checkpoint(
                installation_id,
                JournalKind.AUDIT,
                event_count=event.sequence,
                head_hash=event.event_hash,
            )
        except IntegrityCheckpointError:
            # Concurrent callbacks may arrive out of order. A later trusted head
            # already commits this fully verified prefix; equal-count mismatch or
            # a missing/older head remains an integrity failure.
            latest = checkpoints.latest(installation_id, JournalKind.AUDIT)
            if latest is None or latest.event_count <= event.sequence:
                raise
        application.state.integrity_checkpoints = checkpoints

    def anchor_journals(
        *,
        installation_id: str | None = None,
    ) -> None:
        """Advance the independently stored trusted journal heads."""

        _sessions, audit, operations = security_services(create_missing=False)
        checkpoints = integrity_checkpoint_store()
        selected_installation = selected_installation_id(installation_id)
        audit_head = audit.verify()
        operation_head = operations.verify()
        checkpoints.checkpoint(
            selected_installation,
            JournalKind.AUDIT,
            event_count=audit_head.event_count,
            head_hash=audit_head.head_hash,
        )
        checkpoints.checkpoint(
            selected_installation,
            JournalKind.OPERATIONS,
            event_count=operation_head.event_count,
            head_hash=operation_head.head_hash,
        )
        application.state.integrity_checkpoints = checkpoints

    def anchor_committed_installer_mutation(
        *,
        installation_id: str | None = None,
    ) -> None:
        """Anchor committed state or expose that only the checkpoint is pending."""

        try:
            anchor_journals(installation_id=installation_id)
        except Exception:
            raise HTTPException(
                status_code=503,
                detail="operation committed; integrity checkpoint pending",
                headers={"Cache-Control": "no-store"},
            ) from None

    def reference_database(
        configuration: InstallerConfiguration | None = None,
        *,
        create_parent: bool = True,
    ) -> tuple[Path, ConnectionFactory]:
        configured = configuration or configuration_store.require()
        if not isinstance(configured.database, SQLiteDatabase):
            raise TypeError("reference database requires SQLite configuration")
        database_path = (runtime.data_dir / configured.database.path).resolve()
        data_root = runtime.data_dir.resolve()
        if database_path == data_root or data_root not in database_path.parents:
            raise HTTPException(
                status_code=422,
                detail="SQLite database path escapes the Platform data directory",
            )
        if create_parent:
            database_path.parent.mkdir(parents=True, exist_ok=True)
        return database_path, lambda: sqlite3.connect(database_path)

    def postgresql_adapter(
        configuration: InstallerConfiguration | None = None,
    ) -> PostgreSQLAdapter:
        configured = configuration or configuration_store.require()
        if not isinstance(configured.database, PostgreSQLDatabase):
            raise TypeError("PostgreSQL adapter requires PostgreSQL configuration")
        providers = application.state.secret_providers
        if providers is None:
            if os.environ.get("PLAIK_PUBLIC_SECRETS") == "1":
                from .public_secrets import PublishedRuntimeSecretProvider

                local_secrets = PublishedRuntimeSecretProvider(runtime.secrets_dir)
            else:
                local_secrets = LocalFileSecretProvider(runtime.secrets_dir)
            providers = SecretProviderRegistry(
                (EnvironmentSecretProvider(), local_secrets)
            )
            application.state.secret_providers = providers
        if providers is None:
            raise RuntimeError("secret providers are unavailable")
        return PostgreSQLAdapter(configured, providers)

    pg_settings_holder["store"] = PostgreSQLSettingsStore(
        lambda: postgresql_adapter().runtime_connect(),
        json_settings_store,
    )
    pg_events_holder["events"] = PostgreSQLDurableEvents(
        lambda: postgresql_adapter().runtime_connect(),
        event_bus,
        dispatch_after_enqueue=False,
    )
    pg_jobs_holder["queue"] = PostgreSQLJobQueue(
        lambda: postgresql_adapter().runtime_connect(),
    )
    application.state.postgresql_adapter = postgresql_adapter

    def package_owner_connect(package_id: str):
        return postgresql_adapter().package_owner_connect(package_id)

    application.state.package_owner_connect = package_owner_connect
    package_sql_connect_holder["connect"] = package_owner_connect

    def require_installer_access(request: Request) -> None:
        client_key = installer_rate_limiter.key_for(request)
        try:
            installer_rate_limiter.check(client_key)
        except RateLimitExceeded as error:
            raise HTTPException(
                status_code=429,
                detail="installer access temporarily unavailable",
                headers={"Retry-After": str(error.retry_after_seconds)},
            ) from None
        supplied = request.headers.get("X-Installer-Token", "")
        if runtime.installer_token and secrets.compare_digest(
            supplied, runtime.installer_token
        ):
            installer_rate_limiter.record_success(client_key)
            return
        client_host = request.client.host if request.client else ""
        if (
            runtime.allow_unsafe_local_installer
            and client_host in {"127.0.0.1", "::1", "testclient"}
        ):
            installer_rate_limiter.record_success(client_key)
            return
        installer_rate_limiter.record_failure(client_key)
        raise HTTPException(status_code=403, detail="installer access denied")

    def install_payload(state: InstallState | None = None) -> dict:
        current = state if state is not None else install_store.read()
        return {"state": current, "handoff": handoff_snapshot(runtime)}

    def require_installer_open(request: Request) -> None:
        require_installer_access(request)
        if (
            install_store.read() == InstallState.COMPLETED
            and handoff_is_ready(runtime)
        ):
            raise HTTPException(status_code=410, detail="installer is closed")

    def operation_id(action: str, target: str, payload: str = "") -> str:
        digest = hashlib.sha256(
            f"{action}\0{target}\0{payload}".encode("utf-8")
        ).hexdigest()[:24]
        return f"installer-{digest}"

    def begin_or_retry(
        operations: OperationJournal,
        identifier: str,
        *,
        action: str,
        target: str,
    ):
        state = operations.begin(identifier, action=action, target=target)
        if state.status == OperationStatus.FAILED:
            state = operations.retry(identifier)
        return state

    def operation_error_code(prefix: str, error: Exception) -> str:
        return f"{prefix}.{type(error).__name__.lower()}"[:127]

    def append_audit_once(
        audit: AuditLog,
        *,
        operation_identifier: str,
        action: str,
        target_type: str,
        actor_id: str | None = None,
        target_id: str | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        metadata: dict | None = None,
    ) -> None:
        if audit_has_operation(audit, operation_identifier, action):
            return
        safe_metadata = {"operation_id": operation_identifier, **(metadata or {})}
        audit.append(
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            metadata=safe_metadata,
        )

    def audit_has_operation(
        audit: AuditLog,
        operation_identifier: str,
        action: str,
    ) -> bool:
        return any(
            event.action == action
            and event.metadata.get("operation_id") == operation_identifier
            for event in audit.events()
        )

    def installer_recovery_coordinator(
        audit: AuditLog,
        operations: OperationJournal,
    ) -> InstallerRecoveryCoordinator:
        def database_ready_verifier() -> bool:
            configuration = configuration_store.read()
            if configuration is None:
                return False
            if isinstance(configuration.database, SQLiteDatabase):
                try:
                    database_path, connect = reference_database(
                        configuration,
                        create_parent=False,
                    )
                except HTTPException:
                    return False
                if not database_path.is_file():
                    return False
                try:
                    preflight_connection(connect)
                    verify_reference_context(connect, configuration)
                except Exception:
                    return False
                return True
            try:
                adapter = postgresql_adapter(configuration)
                adapter.preflight()
                adapter.verify_context()
            except Exception:
                return False
            return True

        def theme_ready_verifier() -> bool:
            configuration = configuration_store.read()
            if configuration is None:
                return False
            records = package_registry.records()
            default = records.get("default")
            if default is None or default.status != PackageStatus.ENABLED:
                return False
            try:
                theme_manager.state.selection(configuration.store_id)
            except Exception:
                return False
            return True

        return InstallerRecoveryCoordinator(
            install_store=install_store,
            configuration_store=configuration_store,
            identity_store=identity_store,
            operations=operations,
            audit=audit,
            append_audit_once=append_audit_once,
            database_ready_verifier=database_ready_verifier,
            theme_ready_verifier=theme_ready_verifier,
        )

    def recover_pending_installer_operations(
        audit: AuditLog,
        operations: OperationJournal,
    ) -> None:
        installer_recovery_coordinator(audit, operations).recover_pending()

    def require_bootstrap_transition_evidence(
        state: InstallState,
        configuration: InstallerConfiguration,
        audit: AuditLog,
        operations: OperationJournal,
    ) -> None:
        current_index = INSTALL_SEQUENCE.index(state)
        database_index = INSTALL_SEQUENCE.index(InstallState.DATABASE_READY)
        operation_states = operations.states()
        audit_events = audit.events()
        for expected_state in INSTALL_SEQUENCE[database_index : current_index + 1]:
            target = f"state/{expected_state.value}"
            identifier = operation_id(
                "installer.transition",
                target,
                configuration.installation_id,
            )
            operation = operation_states.get(identifier)
            if (
                operation is None
                or operation.action != "installer.transition"
                or operation.target != target
                or operation.status != OperationStatus.SUCCEEDED
            ):
                raise RuntimeError(
                    "installer operation evidence does not match persisted state"
                )
            if not any(
                event.action == "installer.transition"
                and event.target_type == "installer.state"
                and event.target_id == expected_state.value
                and event.outcome == AuditOutcome.SUCCESS
                and event.metadata.get("operation_id") == identifier
                for event in audit_events
            ):
                raise RuntimeError(
                    "installer audit evidence does not match persisted state"
                )

    @application.get("/health")
    def health() -> dict:
        default_theme = theme_registry.require_default()
        state = install_store.read()
        configuration = configuration_store.read()
        if configuration is not None:
            if configuration.sealed and state != InstallState.COMPLETED:
                raise RuntimeError("installer configuration was sealed prematurely")
            if state == InstallState.COMPLETED and not configuration.sealed:
                raise RuntimeError("completed installer configuration is not sealed")
        if state != InstallState.NOT_STARTED:
            _sessions, audit, operations = security_services(create_missing=False)
            audit.verify()
            recover_pending_installer_operations(audit, operations)
            operation_verification = operations.verify()
            if (
                INSTALL_SEQUENCE.index(state)
                >= INSTALL_SEQUENCE.index(InstallState.DATABASE_READY)
                and operation_verification.pending_count
            ):
                raise RuntimeError("installer operation recovery is pending")
        if INSTALL_SEQUENCE.index(state) >= INSTALL_SEQUENCE.index(
            InstallState.DATABASE_READY
        ):
            if configuration is None:
                raise RuntimeError("installed database has no configuration")
            require_bootstrap_transition_evidence(
                state,
                configuration,
                audit,
                operations,
            )
            anchor_journals(installation_id=configuration.installation_id)
            if isinstance(configuration.database, SQLiteDatabase):
                database_path, connect = reference_database(
                    configuration,
                    create_parent=False,
                )
                if not database_path.is_file():
                    raise RuntimeError("configured Platform database is missing")
                preflight_connection(connect)
                verify_reference_context(connect, configuration)
            else:
                adapter = postgresql_adapter(configuration)
                adapter.preflight()
                adapter.verify_context()
        return {
            "status": "ok",
            "core_version": __version__,
            "install_state": state,
            "default_theme": default_theme.id,
        }

    def public_health() -> dict:
        """Verify only state deliberately projected to the public process.

        This path must not construct secret providers, sessions, audit journals,
        operation journals, database-owner adapters or recovery authorities.
        Privileged deployment health remains responsible for those invariants
        before a release is activated.
        """

        default_theme = theme_registry.require_default()
        state = install_store.read()
        if state != InstallState.COMPLETED:
            raise RuntimeError("public installation state is incomplete")
        configuration = configuration_store.require()
        if not configuration.sealed:
            raise RuntimeError("public configuration is not sealed")
        maintenance = read_json(runtime.maintenance_state_path, None)
        if maintenance is not None:
            if (not isinstance(maintenance, dict)
                    or set(maintenance) != {"state", "hmac_sha256"}
                    or not isinstance(maintenance["state"], dict)
                    or not isinstance(maintenance["state"].get("active"), bool)):
                raise RuntimeError("public maintenance projection is invalid")
            if maintenance["state"]["active"]:
                raise RuntimeError("public writes are frozen by maintenance")
        return {
            "status": "ok",
            "core_version": __version__,
            "install_state": state,
            "default_theme": default_theme.id,
            "store_id": configuration.store_id,
        }

    @application.get("/api/core/status")
    def core_status() -> dict:
        theme_registry.require_default()
        return {
            "version": __version__,
            "installed": install_store.read() == InstallState.COMPLETED,
        }

    @application.get(
        "/api/install/status", dependencies=[Depends(require_installer_open)]
    )
    def detailed_install_status() -> dict:
        return {
            "install_state": install_store.read(),
            "configuration": configuration_store.redacted(),
            "themes": theme_registry.list(),
            "packages": {
                package_id: record.model_dump(mode="json")
                for package_id, record in package_registry.records().items()
            },
        }

    @application.get("/api/install/state", dependencies=[Depends(require_installer_access)])
    def install_state() -> dict:
        return install_payload()

    @application.get(
        "/api/install/requirements", dependencies=[Depends(require_installer_open)]
    )
    def install_requirements() -> dict:
        report = system_requirements.inspect()
        return {
            "passed": report.passed,
            "checks": [
                {"id": check.id, "passed": check.passed, "detail": check.detail}
                for check in report.checks
            ],
            "observations": [
                {"id": item.id, "passed": item.passed, "detail": item.detail}
                for item in report.observations
            ],
            "inventory": report.inventory,
        }

    @application.get(
        "/api/install/configuration", dependencies=[Depends(require_installer_open)]
    )
    def install_configuration() -> dict:
        return {"configuration": configuration_store.redacted()}

    @application.put(
        "/api/install/configuration", dependencies=[Depends(require_installer_access)]
    )
    def write_install_configuration(
        configuration: InstallerConfiguration,
    ) -> dict:
        with exclusive_file_lock(runtime.install_operation_lock_path):
            state = install_store.read()
            if state == InstallState.COMPLETED:
                raise HTTPException(status_code=423, detail="installer is locked")
            if state not in {
                InstallState.REQUIREMENTS_CHECKED,
                InstallState.CONFIGURED,
            }:
                raise HTTPException(
                    status_code=409,
                    detail="configuration can be written only after requirements checks and before database setup",
                )
            _sessions, audit, operations = security_services(create_missing=False)
            target = f"installation/{configuration.installation_id}"
            identifier = operation_id(
                "installer.configure",
                target,
                configuration.model_dump_json(),
            )
            operation = begin_or_retry(
                operations,
                identifier,
                action="installer.configure",
                target=target,
            )
            if operation.status == OperationStatus.SUCCEEDED:
                anchor_committed_installer_mutation(
                    installation_id=configuration.installation_id
                )
                return {"configuration": configuration_store.require().redacted()}
            try:
                if isinstance(configuration.database, PostgreSQLDatabase):
                    providers = application.state.secret_providers
                    if providers is None:
                        raise SecretStoreError("secret providers are unavailable")
                    providers.resolve(configuration.database.credential)
                stored = configuration_store.write(configuration)
                append_audit_once(
                    audit,
                    operation_identifier=identifier,
                    action="installer.configuration.write",
                    target_type="installer.configuration",
                    metadata={
                        "profile": stored.profile.value,
                        "mode": stored.mode.value,
                    },
                )
                operations.succeed(identifier)
            except InstallerConfigurationError as error:
                operations.fail(
                    identifier,
                    error_code=operation_error_code("configuration", error),
                )
                raise HTTPException(status_code=409, detail=str(error)) from error
            except SecretStoreError as error:
                operations.fail(
                    identifier,
                    error_code=operation_error_code("configuration", error),
                )
                raise HTTPException(
                    status_code=422,
                    detail="database credential reference cannot be resolved",
                ) from None
            except Exception as error:
                operations.fail(
                    identifier,
                    error_code=operation_error_code("configuration", error),
                )
                raise HTTPException(
                    status_code=500,
                    detail="installer configuration operation failed",
                ) from None
            anchor_committed_installer_mutation(
                installation_id=configuration.installation_id
            )
            return {"configuration": stored.redacted()}

    @application.post(
        "/api/install/credentials", dependencies=[Depends(require_installer_open)]
    )
    def write_install_credentials(request: InstallerCredentialRequest) -> dict:
        secrets_dir = LocalFileSecretProvider(runtime.secrets_dir)
        try:
            secrets_dir.write_group(
                [
                    ("database/migrator", request.migrator_password, "v1"),
                    ("database/runtime", request.runtime_password, "v1"),
                    ("database/checkpoint", request.checkpoint_password, "v1"),
                ]
            )
        except SecretStoreError:
            raise HTTPException(
                status_code=422, detail="credentials could not be stored"
            ) from None
        return {"stored": True}

    @application.post(
        "/api/install/credentials/generate",
        dependencies=[Depends(require_installer_open)],
    )
    def generate_install_credentials() -> dict:
        from .postgresql_provision import generate_role_secret

        secrets_dir = LocalFileSecretProvider(runtime.secrets_dir)
        try:
            secrets_dir.write_group(
                [
                    ("database/migrator", generate_role_secret(), "v1"),
                    ("database/runtime", generate_role_secret(), "v1"),
                    ("database/checkpoint", generate_role_secret(), "v1"),
                ]
            )
        except SecretStoreError:
            raise HTTPException(
                status_code=422, detail="credentials could not be stored"
            ) from None
        return {"stored": True, "generated": True}

    @application.post(
        "/api/install/provision", dependencies=[Depends(require_installer_open)]
    )
    def provision_install_database(request: InstallerProvisionRequest) -> dict:
        if install_store.read() not in {
            InstallState.REQUIREMENTS_CHECKED,
            InstallState.CONFIGURED,
        }:
            raise HTTPException(
                status_code=409,
                detail="database creation is available only after requirements checks and before database setup",
            )
        try:
            request_database_provision(
                runtime,
                {
                    "host": request.host,
                    "port": request.port,
                    "database": request.database,
                    "username": request.username,
                    "runtime_username": request.runtime_username,
                    "checkpoint_username": request.checkpoint_username,
                },
            )
        except ServiceControlError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return {"provisioned": True}

    @application.post(
        "/api/install/finalize", dependencies=[Depends(require_installer_access)]
    )
    def finalize_install_services() -> dict:
        if install_store.read() != InstallState.COMPLETED:
            raise HTTPException(
                status_code=409,
                detail="service finalization requires a completed installation",
            )
        try:
            request_service_finalization(runtime)
        except ServiceControlError as error:
            raise HTTPException(status_code=503, detail=str(error)) from None
        snapshot = handoff_snapshot(runtime)
        if snapshot["status"] != "ready":
            raise HTTPException(
                status_code=503,
                detail=snapshot["detail"] or "service finalization did not complete",
            )
        return {"finalized": True, "handoff": snapshot}

    @application.post(
        "/api/install/admin", dependencies=[Depends(require_installer_access)]
    )
    def create_first_admin(request: AdminBootstrapRequest) -> dict:
        with exclusive_file_lock(runtime.install_operation_lock_path):
            if install_store.read() != InstallState.DATABASE_READY:
                raise HTTPException(
                    status_code=409,
                    detail="the first administrator is created only after database setup",
                )
            configuration = configuration_store.require()
            _sessions, audit, operations = security_services(create_missing=False)
            target = "identity/super-admin"
            identifier = operation_id(
                "installer.admin.bootstrap",
                target,
                f"{configuration.installation_id}\0{request.email.strip().casefold()}",
            )
            operation = begin_or_retry(
                operations,
                identifier,
                action="installer.admin.bootstrap",
                target=target,
            )
            existing = next(
                (
                    user
                    for user in identity_store.users().values()
                    if user.active
                    and "super_admin" in user.roles
                    and user.email == request.email.strip().casefold()
                ),
                None,
            )
            if operation.status == OperationStatus.SUCCEEDED and existing is None:
                raise HTTPException(
                    status_code=500,
                    detail="administrator operation journal is inconsistent",
                )
            try:
                user = existing or identity_store.create_first_super_admin(
                    request.email,
                    request.password.get_secret_value(),
                )
                append_audit_once(
                    audit,
                    operation_identifier=identifier,
                    action="identity.super-admin.bootstrap",
                    target_type="identity.user",
                    target_id=user.id,
                    metadata={"roles": sorted(user.roles)},
                )
                operations.succeed(identifier)
            except (IdentityError, TypeError, ValueError) as error:
                append_audit_once(
                    audit,
                    operation_identifier=identifier,
                    action="identity.super-admin.bootstrap.failure",
                    target_type="identity.user",
                    outcome=AuditOutcome.FAILURE,
                    metadata={"error_code": operation_error_code("identity", error)},
                )
                operations.fail(
                    identifier,
                    error_code=operation_error_code("identity", error),
                )
                raise HTTPException(status_code=422, detail=str(error)) from error
            except Exception as error:
                operations.fail(
                    identifier,
                    error_code=operation_error_code("identity", error),
                )
                raise HTTPException(
                    status_code=500,
                    detail="administrator bootstrap operation failed",
                ) from None
            anchor_committed_installer_mutation(
                installation_id=configuration.installation_id
            )
            return {
                "id": user.id,
                "email": user.email,
                "roles": sorted(user.roles),
            }

    @application.post(
        "/api/install/transition", dependencies=[Depends(require_installer_access)]
    )
    def install_transition(request: TransitionRequest) -> dict:
        with exclusive_file_lock(runtime.install_operation_lock_path):
            current = install_store.read()
            configuration = configuration_store.read()
            installation_id = (
                configuration.installation_id
                if configuration is not None
                else "bootstrap"
            )
            target = f"state/{request.target.value}"
            identifier = operation_id(
                "installer.transition",
                target,
                installation_id,
            )

            if current == InstallState.COMPLETED:
                if request.target != InstallState.COMPLETED or configuration is None:
                    raise HTTPException(status_code=423, detail="installer is locked")
                _sessions, audit, operations = security_services(create_missing=False)
                existing_operation = operations.state(identifier)
                audit_present = audit_has_operation(
                    audit,
                    identifier,
                    "installer.transition",
                )
                if (
                    configuration.sealed
                    and existing_operation is not None
                    and existing_operation.status == OperationStatus.SUCCEEDED
                    and audit_present
                ):
                    anchor_committed_installer_mutation(
                        installation_id=configuration.installation_id
                    )
                    raise HTTPException(status_code=423, detail="installer is locked")
                operation = begin_or_retry(
                    operations,
                    identifier,
                    action="installer.transition",
                    target=target,
                )
                if not configuration.sealed:
                    configuration_store.seal(install_store)
                append_audit_once(
                    audit,
                    operation_identifier=identifier,
                    action="installer.transition",
                    target_type="installer.state",
                    target_id=InstallState.COMPLETED.value,
                )
                if operation.status != OperationStatus.SUCCEEDED:
                    operations.succeed(identifier)
                anchor_committed_installer_mutation(
                    installation_id=configuration.installation_id
                )
                try:
                    request_service_finalization(runtime)
                except ServiceControlError:
                    pass
                return install_payload(InstallState.COMPLETED)

            try:
                install_store.validate_transition(request.target)
            except InvalidInstallTransition as error:
                raise HTTPException(status_code=409, detail=str(error)) from error

            if (
                current == InstallState.NOT_STARTED
                and request.target == InstallState.NOT_STARTED
            ):
                return install_payload(current)

            if request.target == InstallState.REQUIREMENTS_CHECKED:
                try:
                    system_requirements.inspect().require()
                except RequirementsNotMet as error:
                    raise HTTPException(status_code=422, detail=str(error)) from error

            _sessions, audit, operations = security_services(create_missing=True)
            operation = begin_or_retry(
                operations,
                identifier,
                action="installer.transition",
                target=target,
            )
            if request.target == current:
                append_audit_once(
                    audit,
                    operation_identifier=identifier,
                    action="installer.transition",
                    target_type="installer.state",
                    target_id=current.value,
                )
                if operation.status != OperationStatus.SUCCEEDED:
                    operations.succeed(identifier)
                anchor_committed_installer_mutation(
                    installation_id=installation_id
                )
                return install_payload(current)
            if operation.status == OperationStatus.SUCCEEDED:
                raise HTTPException(
                    status_code=500,
                    detail="installer operation journal is inconsistent",
                )

            try:
                if request.target == InstallState.CONFIGURED:
                    configuration_store.require()
                if request.target == InstallState.DATABASE_READY:
                    configuration = configuration_store.require()
                    if isinstance(configuration.database, SQLiteDatabase):
                        _database_path, connect = reference_database(configuration)
                        preflight_connection(connect)
                        runner = MigrationRunner(connect)
                        runner.apply(CORE_MIGRATIONS)
                        initialize_reference_context(connect, configuration)
                        if not all(
                            entry.status == "applied" for entry in runner.ledger()
                        ):
                            raise MigrationError(
                                "database migration ledger is not fully applied"
                            )
                    else:
                        adapter = postgresql_adapter(configuration)
                        from .host_inventory import discover_host_inventory
                        from .postgresql_provision import (
                            try_apply_package_owner_control,
                        )

                        try_apply_package_owner_control(
                            port=configuration.database.port,
                            database=configuration.database.database,
                            migrator_role=configuration.database.username,
                            inventory=discover_host_inventory(runtime),
                        )
                        adapter.bootstrap_core()
                        if not all(
                            entry.status == "applied"
                            for entry in adapter.migrations.ledger()
                        ):
                            raise MigrationError(
                                "database migration ledger is not fully applied"
                            )
                if (
                    request.target == InstallState.ADMIN_READY
                    and not identity_store.has_active_super_admin()
                ):
                    raise HTTPException(
                        status_code=422,
                        detail="an active super administrator is required",
                    )
                if request.target == InstallState.THEME_READY:
                    default_theme = theme_registry.require_default()
                    with exclusive_file_lock(runtime.extension_operation_lock_path):
                        records = package_registry.records()
                        if "default" not in records:
                            package_registry.install_many(
                                [
                                    PackageManifest.model_validate(
                                        {
                                            "id": default_theme.id,
                                            "type": "theme",
                                            "version": default_theme.version,
                                            "name": default_theme.name,
                                            "core": default_theme.core,
                                        }
                                    )
                                ]
                            )
                            records = package_registry.records()
                        if records["default"].status != PackageStatus.ENABLED:
                            package_registry.enable("default")
                    configuration = configuration_store.require()
                    theme_manager.activate(
                        "default",
                        store_id=configuration.store_id,
                    )

                state = install_store.advance(request.target)
                if state == InstallState.COMPLETED:
                    configuration_store.seal(install_store)
                append_audit_once(
                    audit,
                    operation_identifier=identifier,
                    action="installer.transition",
                    target_type="installer.state",
                    target_id=state.value,
                )
                operations.succeed(identifier)
                if state == InstallState.DATABASE_READY:
                    ready_configuration = configuration_store.read()
                    if ready_configuration is not None and isinstance(
                        ready_configuration.database, PostgreSQLDatabase
                    ):
                        application.state.session_store = None
                        application.state.audit_log = None
                        application.state.operation_journal = None
                        application.state.http_auth = None
            except HTTPException as error:
                append_audit_once(
                    audit,
                    operation_identifier=identifier,
                    action="installer.transition.failure",
                    target_type="installer.state",
                    target_id=request.target.value,
                    outcome=AuditOutcome.FAILURE,
                    metadata={
                        "error_code": operation_error_code("transition", error)
                    },
                )
                operations.fail(
                    identifier,
                    error_code=operation_error_code("transition", error),
                )
                raise
            except InstallerConfigurationError as error:
                append_audit_once(
                    audit,
                    operation_identifier=identifier,
                    action="installer.transition.failure",
                    target_type="installer.state",
                    target_id=request.target.value,
                    outcome=AuditOutcome.FAILURE,
                    metadata={
                        "error_code": operation_error_code("transition", error)
                    },
                )
                operations.fail(
                    identifier,
                    error_code=operation_error_code("transition", error),
                )
                raise HTTPException(status_code=422, detail=str(error)) from error
            except (
                DatabasePreflightError,
                MigrationError,
                PostgreSQLAdapterError,
                sqlite3.Error,
            ) as error:
                append_audit_once(
                    audit,
                    operation_identifier=identifier,
                    action="installer.transition.failure",
                    target_type="installer.state",
                    target_id=request.target.value,
                    outcome=AuditOutcome.FAILURE,
                    metadata={
                        "error_code": operation_error_code("transition", error)
                    },
                )
                operations.fail(
                    identifier,
                    error_code=operation_error_code("transition", error),
                )
                raise HTTPException(
                    status_code=500,
                    detail=f"installer transition failed ({type(error).__name__})",
                ) from None
            except Exception as error:
                operations.fail(
                    identifier,
                    error_code=operation_error_code("transition", error),
                )
                raise HTTPException(
                    status_code=500,
                    detail="installer transition failed",
                ) from None
            anchor_committed_installer_mutation(
                installation_id=(
                    configuration.installation_id
                    if configuration is not None
                    else installation_id
                )
            )
            return install_payload(state)

    @application.get("/api/core/themes/active")
    def active_theme(store_id: str | None = None) -> dict:
        configuration = configuration_store.read()
        selected_store = store_id or (
            configuration.store_id if configuration is not None else "default"
        )
        return theme_manager.active(selected_store).model_dump(mode="json")

    application.state.security_services = security_services
    application.state.maintenance_safety_service = maintenance_safety
    application.state.http_auth_service = http_auth_service
    application.state.postgresql_adapter = postgresql_adapter
    application.state.anchor_journals = anchor_journals
    application.state.anchor_audit_event = anchor_audit_event
    application.state.health_check = health
    application.state.public_health_check = public_health
    application.state.require_installer_access = require_installer_access

    return application


app = create_app()
