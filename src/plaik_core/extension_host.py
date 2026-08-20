"""Construct public ExtensionRuntime for enabled packages."""

from __future__ import annotations

import importlib.util
import threading
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, create_model

from plaik_contracts import HealthIssue, HealthSeverity, ResourceRef, ScopeRef, SecretReference
from plaik_sdk import (
    EventPublisher,
    ExtensionRuntime,
    HealthReporter,
    JobHandler,
    JobScheduler,
    SecretReader,
    SecretValue,
    ServiceResolver,
    SettingsReader,
    SlotContributor,
)

from .connection_store import ConnectionStore, ConnectionStoreError
from .extension_runtime import (
    EventBus,
    ExtensionContractError,
    RenderSlotRegistry,
    ServiceRegistry,
)
from .health_issues import HealthIssueRegistry
from .installer_config import InstallerConfiguration
from .jobs import JobQueue, _owner_job_prefix, _validate_job_type
from .packages import PackageRecord, PackageStatus
from .secret_store import SecretNotFoundError, SecretProviderRegistry
from .settings_store import SettingsStore, SettingsStoreError


class ExtensionHostError(RuntimeError):
    """An enabled package could not be given an ExtensionRuntime."""


def _require_exact_str(value: object, error: str) -> str:
    if type(value) is not str:
        raise ExtensionHostError(error)
    return value


def _optional_exact_str(value: object, error: str) -> str | None:
    if value is None:
        return None
    return _require_exact_str(value, error)


def _canonical_scope(provided: object) -> ScopeRef:
    """Rebuild ScopeRef from primitive fields; reject subclasses and constructed junk."""

    error = "scope is outside the bound runtime identity"
    if type(provided) is not ScopeRef:
        raise ExtensionHostError(error)
    try:
        installation_id = provided.installation_id
        group_id = provided.group_id
        store_id = provided.store_id
    except AttributeError:
        raise ExtensionHostError(error) from None
    try:
        return ScopeRef.model_validate(
            {
                "installation_id": _require_exact_str(installation_id, error),
                "group_id": _optional_exact_str(group_id, error),
                "store_id": _optional_exact_str(store_id, error),
            }
        )
    except (ValidationError, TypeError, ValueError):
        raise ExtensionHostError(error) from None


def _require_bound_scope(bound: ScopeRef, provided: object) -> ScopeRef:
    """Reject a scope outside the bound installation → group → store identity."""

    canonical = _canonical_scope(provided)
    if canonical not in bound.inheritance_chain():
        raise ExtensionHostError("scope is outside the bound runtime identity")
    return canonical


def _canonical_resource(provided: object, owner: str, bound: ScopeRef) -> ResourceRef:
    error = "resource owner must match the publishing package"
    if type(provided) is not ResourceRef:
        raise ExtensionHostError(error)
    try:
        owner_value = provided.owner
        kind_value = provided.kind
        id_value = provided.id
        scope_value = provided.scope
    except AttributeError:
        raise ExtensionHostError(error) from None
    scope = _require_bound_scope(bound, scope_value)
    try:
        canonical = ResourceRef.model_validate(
            {
                "owner": _require_exact_str(owner_value, error),
                "kind": _require_exact_str(kind_value, error),
                "id": _require_exact_str(id_value, error),
                "scope": scope,
            }
        )
    except (ValidationError, TypeError, ValueError):
        raise ExtensionHostError(error) from None
    if canonical.owner != owner:
        raise ExtensionHostError(error)
    return canonical


def _canonical_health_issue(provided: object, owner: str, bound: ScopeRef) -> HealthIssue:
    if type(provided) is not HealthIssue:
        raise TypeError("health issue must be a HealthIssue")
    error = "health issue owner must match the reporting package"
    try:
        owner_value = provided.owner
        code_value = provided.code
        severity_value = provided.severity
        scope_value = provided.scope
        message_value = provided.message
    except AttributeError:
        raise TypeError("health issue must be a HealthIssue") from None
    if type(severity_value) is not HealthSeverity:
        raise TypeError("health issue must be a HealthIssue")
    scope = _require_bound_scope(bound, scope_value)
    try:
        canonical = HealthIssue.model_validate(
            {
                "owner": _require_exact_str(owner_value, error),
                "code": _require_exact_str(code_value, error),
                "severity": severity_value,
                "scope": scope,
                "message": _require_exact_str(message_value, error),
            }
        )
    except (ValidationError, TypeError, ValueError):
        raise ExtensionHostError(error) from None
    if canonical.owner != owner:
        raise ExtensionHostError(error)
    return canonical


class _PackageSettingsBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _settings_field_name(key: str, used: set[str]) -> str:
    name = key.replace("-", "_").replace(".", "_")
    if not name.isidentifier():
        name = "setting_" + "".join(
            character if character.isalnum() else "_" for character in key
        )
    candidate = name
    suffix = 1
    while candidate in used:
        candidate = f"{name}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _package_settings_schema(
    package_id: str, declarations: tuple[Any, ...] | list[Any]
) -> type[BaseModel]:
    used: set[str] = set()
    fields: dict[str, Any] = {}
    for item in declarations:
        name = _settings_field_name(item.key, used)
        if item.secret:
            fields[name] = (SecretReference | None, Field(default=None, alias=item.key))
        else:
            fields[name] = (
                str | int | bool | None,
                Field(default=None, alias=item.key),
            )
    return create_model(
        f"PackageSettings_{package_id.replace('-', '_')}",
        __base__=_PackageSettingsBase,
        **fields,
    )


class _OwnerSettings(SettingsReader):
    def __init__(
        self,
        host: ExtensionHost,
        owner: str,
        scope: ScopeRef,
        generation: int,
    ) -> None:
        self._host = host
        self._owner = owner
        self._scope = scope
        self._generation = generation

    def get(self, key: str, default: Any = None) -> Any:
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("settings reader is no longer bound")
            store = self._host._settings
            if store is None or self._owner not in store.schemas:
                return default
            try:
                resolved = store.resolve(self._scope, self._owner)
            except SettingsStoreError as error:
                raise ExtensionHostError("settings could not be resolved") from error
            for field_name, field in resolved.values.__class__.model_fields.items():
                public_key = field.alias if field.alias else field_name
                if public_key == key:
                    return getattr(resolved.values, field_name)
            return default


class _OwnerSecrets(SecretReader):
    def __init__(self, host: ExtensionHost, owner: str, generation: int) -> None:
        self._host = host
        self._owner = owner
        self._generation = generation

    def get(self, key: str) -> SecretValue:
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("secret reader is no longer bound")
            try:
                connection = self._host._connections.get(self._owner, key)
            except ConnectionStoreError as error:
                raise SecretNotFoundError(
                    f"secret is not granted to this package: {key}"
                ) from error
            if self._host._secrets is None:
                raise SecretNotFoundError("secret providers are unavailable")
            return self._host._secrets.resolve(connection.secret)


class _OwnerServices(ServiceResolver):
    def __init__(self, host: ExtensionHost, owner: str, generation: int) -> None:
        self._host = host
        self._owner = owner
        self._generation = generation

    def resolve(self, contract: str, version: str = "*") -> Any:
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("service resolver is no longer bound")
            return self._host._services.resolve(contract, version)

    def register(self, contract: str, version: str, provider: Any) -> None:
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("service resolver is no longer bound")
            if not contract.startswith(f"{self._owner}."):
                raise ExtensionHostError(
                    "service contract must use its package-owned namespace"
                )
            self._host._services.register(
                owner=self._owner,
                contract=contract,
                version=version,
                provider=provider,
            )


class _OwnerEvents(EventPublisher):
    def __init__(
        self,
        host: ExtensionHost,
        owner: str,
        scope: ScopeRef,
        generation: int,
    ) -> None:
        self._host = host
        self._owner = owner
        self._scope = scope
        self._generation = generation

    def publish(
        self,
        contract: str,
        version: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
        scope: ScopeRef | None = None,
        resource: ResourceRef | None = None,
        correlation_id: str | None = None,
    ) -> None:
        persist = getattr(self._host._publication, "persist", None)
        drain = getattr(self._host._publication, "drain", None)
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("event publisher is no longer bound")
            if scope is None:
                resolved_scope = self._scope
            else:
                resolved_scope = _require_bound_scope(self._scope, scope)
            canonical_resource = None
            if resource is not None:
                canonical_resource = _canonical_resource(
                    resource, self._owner, self._scope
                )
            if persist is None or drain is None:
                self._host._publication.publish(
                    owner=self._owner,
                    contract=contract,
                    version=version,
                    payload=payload,
                    idempotency_key=idempotency_key,
                    scope=resolved_scope,
                    resource=canonical_resource,
                    correlation_id=correlation_id,
                )
                return
            persist(
                owner=self._owner,
                contract=contract,
                version=version,
                payload=payload,
                idempotency_key=idempotency_key,
                scope=resolved_scope,
                resource=canonical_resource,
                correlation_id=correlation_id,
            )
        drain()

    def subscribe(
        self,
        contract: str,
        version: str,
        handler,
        *,
        priority: int = 100,
    ) -> None:
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("event publisher is no longer bound")
            if not callable(handler):
                raise TypeError("event handler must be callable")
            self._host._events.subscribe(
                subscriber=self._owner,
                contract=contract,
                version=version,
                handler=handler,
                priority=priority,
            )


class _OwnerJobs(JobScheduler):
    def __init__(self, host: ExtensionHost, owner: str, generation: int) -> None:
        self._host = host
        self._owner = owner
        self._generation = generation

    def enqueue(
        self,
        job_type: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
        maximum_attempts: int = 5,
        scheduled_at: datetime | None = None,
    ) -> str:
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("job scheduler is no longer bound")
            if not job_type.startswith(f"{self._owner}."):
                raise ExtensionHostError(
                    "job type must use its package-owned namespace"
                )
            record = self._host._jobs.enqueue(
                job_type,
                payload,
                idempotency_key=idempotency_key,
                maximum_attempts=maximum_attempts,
                scheduled_at=scheduled_at,
            )
            drain = self._host._job_drain
        if drain is not None:
            drain()
        return record.id

    def register(self, job_type: str, handler: JobHandler) -> None:
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("job scheduler is no longer bound")
            job_type = _validate_job_type(job_type)
            if not job_type.startswith(f"{self._owner}."):
                raise ExtensionHostError(
                    "job type must use its package-owned namespace"
                )
            if not callable(handler):
                raise TypeError("job handler must be callable")
            self._host._job_handlers[job_type] = handler


class _OwnerSlots(SlotContributor):
    def __init__(self, host: ExtensionHost, owner: str, generation: int) -> None:
        self._host = host
        self._owner = owner
        self._generation = generation

    def bind(
        self,
        slot: str,
        version: str,
        template: str,
        *,
        position: int = 100,
    ) -> None:
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("slot contributor is no longer bound")
            self._host._slots.bind(
                contributor=self._owner,
                slot=slot,
                version=version,
                template=template,
                position=position,
            )


class _OwnerHealth(HealthReporter):
    def __init__(
        self,
        host: ExtensionHost,
        owner: str,
        scope: ScopeRef,
        generation: int,
    ) -> None:
        self._host = host
        self._owner = owner
        self._scope = scope
        self._generation = generation

    def report(self, issue: HealthIssue) -> None:
        with self._host._lock:
            if self._host._runtime_generations.get(self._owner) != self._generation:
                raise ExtensionHostError("health reporter is no longer bound")
            self._host._health.report(
                _canonical_health_issue(issue, self._owner, self._scope)
            )


class ExtensionHost:
    """Build and retain one ExtensionRuntime per enabled module or integration."""

    def __init__(
        self,
        *,
        packages_root: Path,
        service_registry: ServiceRegistry,
        event_bus: EventBus,
        event_publication: Any | None = None,
        render_slots: RenderSlotRegistry,
        job_queue: JobQueue,
        connection_store: ConnectionStore,
        health_issues: HealthIssueRegistry,
        secret_providers: SecretProviderRegistry | None = None,
        settings_store: SettingsStore | None = None,
    ) -> None:
        self._packages_root = Path(packages_root)
        self._services = service_registry
        self._events = event_bus
        self._publication = event_publication or event_bus
        self._slots = render_slots
        self._jobs = job_queue
        self._job_handlers: dict[str, JobHandler] = {}
        self._job_drain = None
        self._connections = connection_store
        self._health = health_issues
        self._secrets = secret_providers
        self._settings = settings_store
        self._runtimes: dict[str, ExtensionRuntime] = {}
        self._registered: set[str] = set()
        self._runtime_generations: dict[str, int] = {}
        self._runtime_epoch = 0
        self._lock = threading.RLock()

    def set_secret_providers(self, providers: SecretProviderRegistry | None) -> None:
        self._secrets = providers

    def set_job_drain(self, drain: Any | None) -> None:
        self._job_drain = drain

    @property
    def job_handlers(self) -> dict[str, JobHandler]:
        return self._job_handlers

    def bind_configuration(self, configuration: InstallerConfiguration) -> ScopeRef:
        return ScopeRef.store(
            configuration.group_id,
            configuration.store_id,
            configuration.installation_id,
        )

    def drop_unenabled(self, records: Mapping[str, PackageRecord]) -> None:
        """Revoke dropped runtimes without rebuilding; safe when configuration is missing."""

        with self._lock:
            self._drop_unenabled_locked(records)

    def sync_enabled(
        self,
        records: Mapping[str, PackageRecord],
        configuration: InstallerConfiguration,
    ) -> tuple[ExtensionRuntime, ...]:
        scope = self.bind_configuration(configuration)
        bound: list[ExtensionRuntime] = []
        with self._lock:
            enabled_ids = self._drop_unenabled_locked(records)
            for package_id in sorted(enabled_ids):
                runtime = self._runtimes.get(package_id)
                if runtime is None:
                    try:
                        runtime = self._build_runtime(
                            records[package_id], scope, configuration.locale
                        )
                        if package_id not in self._registered:
                            self._try_register(package_id, runtime)
                        self._runtimes[package_id] = runtime
                        self._registered.add(package_id)
                    finally:
                        if (
                            runtime is not None
                            and self._runtimes.get(package_id) is not runtime
                        ):
                            self._unbind_generation(package_id)
                            self._set_owner_registries_active(package_id, False)
                if runtime is not None and self._runtimes.get(package_id) is runtime:
                    self._set_owner_registries_active(package_id, True)
                bound.append(runtime)
        return tuple(bound)

    def _drop_unenabled_locked(
        self, records: Mapping[str, PackageRecord]
    ) -> set[str]:
        enabled_ids = {
            package_id
            for package_id, record in records.items()
            if record.status == PackageStatus.ENABLED
            and record.manifest.type.value in {"module", "integration"}
        }
        dropping = [
            package_id
            for package_id in tuple(self._runtimes)
            if package_id not in enabled_ids
        ]
        for package_id in dropping:
            self._unbind_generation(package_id)
            self._set_owner_registries_active(package_id, False)
            del self._runtimes[package_id]
        for package_id in tuple(self._runtime_generations):
            if package_id not in enabled_ids or package_id not in self._runtimes:
                self._unbind_generation(package_id)
                if package_id not in enabled_ids:
                    self._set_owner_registries_active(package_id, False)
        for package_id in tuple(self._registered):
            if package_id not in records:
                self._drop_job_handlers(package_id)
                self._registered.discard(package_id)
        return enabled_ids

    def _drop_job_handlers(self, package_id: str) -> None:
        prefix = _owner_job_prefix(package_id)
        for job_type in [
            job_type
            for job_type in self._job_handlers
            if job_type.startswith(prefix)
        ]:
            del self._job_handlers[job_type]

    def _set_owner_registries_active(self, package_id: str, active: bool) -> None:
        for registry in (self._services, self._events, self._slots):
            if active:
                registry.activate_owner(package_id)
            else:
                registry.deactivate_owner(package_id)
        if not active:
            self._jobs.cancel_owner(package_id)

    def _unbind_generation(self, package_id: str) -> None:
        """Drop the runtime generation so stale handles fail closed, and forget issues."""

        self._runtime_generations.pop(package_id, None)
        self._health.clear(owner=package_id)

    def runtime_for(self, package_id: str) -> ExtensionRuntime | None:
        with self._lock:
            return self._runtimes.get(package_id)

    def _build_runtime(
        self,
        record: PackageRecord,
        scope: ScopeRef,
        locale: str,
    ) -> ExtensionRuntime:
        package_id = record.manifest.id
        self._ensure_settings_schema(record)
        store_id = scope.store_id or scope.group_id or scope.installation_id
        self._runtime_epoch += 1
        generation = self._runtime_epoch
        runtime = ExtensionRuntime(
            package_id=package_id,
            store_id=store_id,
            locale=locale,
            settings=_OwnerSettings(self, package_id, scope, generation),
            secrets=_OwnerSecrets(self, package_id, generation),
            services=_OwnerServices(self, package_id, generation),
            events=_OwnerEvents(self, package_id, scope, generation),
            jobs=_OwnerJobs(self, package_id, generation),
            slots=_OwnerSlots(self, package_id, generation),
            health=_OwnerHealth(self, package_id, scope, generation),
        )
        self._runtime_generations[package_id] = generation
        self._declare_manifest_events(record)
        return runtime

    def _declare_manifest_events(self, record: PackageRecord) -> None:
        for event in record.manifest.events:
            try:
                self._events.declare(
                    owner=record.manifest.id,
                    contract=event.contract,
                    version=event.version,
                )
            except ExtensionContractError:
                continue

    def _ensure_settings_schema(self, record: PackageRecord) -> None:
        if self._settings is None:
            return
        declarations = record.manifest.settings
        if not declarations:
            return
        self._settings.register_schema(
            record.manifest.id,
            _package_settings_schema(record.manifest.id, declarations),
        )

    def _try_register(self, package_id: str, runtime: ExtensionRuntime) -> None:
        module_path = self._packages_root / package_id / "extension.py"
        if not module_path.is_file():
            return
        spec = importlib.util.spec_from_file_location(
            f"plaik_extension_{package_id.replace('-', '_')}",
            module_path,
        )
        if spec is None or spec.loader is None:
            raise ExtensionHostError(f"cannot load extension module for {package_id}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        register = getattr(module, "register", None)
        if not callable(register):
            return
        register(runtime)
