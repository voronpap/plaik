"""Construct public ExtensionRuntime for enabled packages."""

from __future__ import annotations

import importlib.util
import threading
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from plaik_contracts import HealthIssue, HealthSeverity, ResourceRef, ScopeRef
from plaik_sdk import (
    EventPublisher,
    ExtensionRuntime,
    HealthReporter,
    JobScheduler,
    SecretReader,
    SecretValue,
    ServiceResolver,
    SettingsReader,
    SlotContributor,
)

from .connection_store import ConnectionStore, ConnectionStoreError
from .extension_runtime import EventBus, RenderSlotRegistry, ServiceRegistry
from .health_issues import HealthIssueRegistry
from .installer_config import InstallerConfiguration
from .jobs import DurableJobQueue
from .packages import PackageRecord, PackageStatus
from .secret_store import SecretNotFoundError, SecretProviderRegistry


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


class _NullSettings(SettingsReader):
    def get(self, key: str, default: Any = None) -> Any:
        del key
        return default


class _OwnerSecrets(SecretReader):
    def __init__(self, host: ExtensionHost, owner: str) -> None:
        self._host = host
        self._owner = owner

    def get(self, key: str) -> SecretValue:
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
    def __init__(self, registry: ServiceRegistry) -> None:
        self._registry = registry

    def resolve(self, contract: str, version: str = "*") -> Any:
        return self._registry.resolve(contract, version)


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
            self._host._events.publish(
                owner=self._owner,
                contract=contract,
                version=version,
                payload=payload,
                idempotency_key=idempotency_key,
                scope=resolved_scope,
                resource=canonical_resource,
                correlation_id=correlation_id,
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
            record = self._host._jobs.enqueue(
                job_type,
                payload,
                idempotency_key=idempotency_key,
                maximum_attempts=maximum_attempts,
                scheduled_at=scheduled_at,
            )
            return record.id


class _OwnerSlots(SlotContributor):
    def __init__(self, registry: RenderSlotRegistry, owner: str) -> None:
        self._registry = registry
        self._owner = owner

    def bind(
        self,
        slot: str,
        version: str,
        template: str,
        *,
        position: int = 100,
    ) -> None:
        self._registry.bind(
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
        render_slots: RenderSlotRegistry,
        job_queue: DurableJobQueue,
        connection_store: ConnectionStore,
        health_issues: HealthIssueRegistry,
        secret_providers: SecretProviderRegistry | None = None,
    ) -> None:
        self._packages_root = Path(packages_root)
        self._services = service_registry
        self._events = event_bus
        self._slots = render_slots
        self._jobs = job_queue
        self._connections = connection_store
        self._health = health_issues
        self._secrets = secret_providers
        self._runtimes: dict[str, ExtensionRuntime] = {}
        self._registered: set[str] = set()
        self._runtime_generations: dict[str, int] = {}
        self._runtime_epoch = 0
        self._lock = threading.RLock()

    def set_secret_providers(self, providers: SecretProviderRegistry | None) -> None:
        self._secrets = providers

    def bind_configuration(self, configuration: InstallerConfiguration) -> ScopeRef:
        return ScopeRef.store(
            configuration.group_id,
            configuration.store_id,
            configuration.installation_id,
        )

    def sync_enabled(
        self,
        records: Mapping[str, PackageRecord],
        configuration: InstallerConfiguration,
    ) -> tuple[ExtensionRuntime, ...]:
        scope = self.bind_configuration(configuration)
        bound: list[ExtensionRuntime] = []
        with self._lock:
            enabled_ids = {
                package_id
                for package_id, record in records.items()
                if record.status == PackageStatus.ENABLED
                and record.manifest.type.value in {"module", "integration"}
            }
            for package_id in tuple(self._runtimes):
                if package_id not in enabled_ids:
                    del self._runtimes[package_id]
            for package_id in tuple(self._runtime_generations):
                if package_id not in enabled_ids or package_id not in self._runtimes:
                    self._unbind_health(package_id)
            for package_id in tuple(self._registered):
                if package_id not in records:
                    self._registered.discard(package_id)
            for package_id in sorted(enabled_ids):
                runtime = self._runtimes.get(package_id)
                if runtime is None:
                    committed = False
                    try:
                        runtime = self._build_runtime(
                            package_id, scope, configuration.locale
                        )
                        if package_id not in self._registered:
                            self._try_register(package_id, runtime)
                            self._registered.add(package_id)
                        self._runtimes[package_id] = runtime
                        committed = True
                    finally:
                        if not committed:
                            self._unbind_health(package_id)
                bound.append(runtime)
        return tuple(bound)

    def _unbind_health(self, package_id: str) -> None:
        self._runtime_generations.pop(package_id, None)
        self._health.clear(owner=package_id)

    def runtime_for(self, package_id: str) -> ExtensionRuntime | None:
        with self._lock:
            return self._runtimes.get(package_id)

    def _build_runtime(
        self,
        package_id: str,
        scope: ScopeRef,
        locale: str,
    ) -> ExtensionRuntime:
        store_id = scope.store_id or scope.group_id or scope.installation_id
        self._runtime_epoch += 1
        generation = self._runtime_epoch
        runtime = ExtensionRuntime(
            package_id=package_id,
            store_id=store_id,
            locale=locale,
            settings=_NullSettings(),
            secrets=_OwnerSecrets(self, package_id),
            services=_OwnerServices(self._services),
            events=_OwnerEvents(self, package_id, scope, generation),
            jobs=_OwnerJobs(self, package_id, generation),
            slots=_OwnerSlots(self._slots, package_id),
            health=_OwnerHealth(self, package_id, scope, generation),
        )
        self._runtime_generations[package_id] = generation
        return runtime

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
