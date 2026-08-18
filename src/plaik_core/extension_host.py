"""Construct public ExtensionRuntime for enabled packages."""

from __future__ import annotations

import importlib.util
import threading
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from plaik_contracts import HealthIssue, ScopeRef, ResourceRef
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
    def __init__(self, bus: EventBus, owner: str, scope: ScopeRef) -> None:
        self._bus = bus
        self._owner = owner
        self._scope = scope

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
        self._bus.publish(
            owner=self._owner,
            contract=contract,
            version=version,
            payload=payload,
            idempotency_key=idempotency_key,
            scope=scope or self._scope,
            resource=resource,
            correlation_id=correlation_id,
        )


class _OwnerJobs(JobScheduler):
    def __init__(self, queue: DurableJobQueue) -> None:
        self._queue = queue

    def enqueue(
        self,
        job_type: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
        maximum_attempts: int = 5,
        scheduled_at: datetime | None = None,
    ) -> str:
        record = self._queue.enqueue(
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
    def __init__(self, registry: HealthIssueRegistry, owner: str) -> None:
        self._registry = registry
        self._owner = owner

    def report(self, issue: HealthIssue) -> None:
        if not isinstance(issue, HealthIssue):
            raise TypeError("health issue must be a HealthIssue")
        if issue.owner != self._owner:
            raise ExtensionHostError(
                "health issue owner must match the reporting package"
            )
        self._registry.report(issue)


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
                    self._health.clear(owner=package_id)
            for package_id in tuple(self._registered):
                if package_id not in records:
                    self._registered.discard(package_id)
            for package_id in sorted(enabled_ids):
                runtime = self._runtimes.get(package_id)
                if runtime is None:
                    runtime = self._build_runtime(package_id, scope, configuration.locale)
                    if package_id not in self._registered:
                        self._try_register(package_id, runtime)
                        self._registered.add(package_id)
                    self._runtimes[package_id] = runtime
                bound.append(runtime)
        return tuple(bound)

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
        return ExtensionRuntime(
            package_id=package_id,
            store_id=store_id,
            locale=locale,
            settings=_NullSettings(),
            secrets=_OwnerSecrets(self, package_id),
            services=_OwnerServices(self._services),
            events=_OwnerEvents(self._events, package_id, scope),
            jobs=_OwnerJobs(self._jobs),
            slots=_OwnerSlots(self._slots, package_id),
            health=_OwnerHealth(self._health, package_id),
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
