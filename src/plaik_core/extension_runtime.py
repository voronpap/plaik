"""Versioned, owner-scoped runtime contracts for extension collaboration."""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


_OWNER = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_CONTRACT = re.compile(r"^[a-z][a-z0-9-]*(?:\.[a-z][A-Za-z0-9_-]*)+$")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
MAX_VERSION_RANGE_BYTES = 512
MAX_EVENT_PAYLOAD_BYTES = 1024 * 1024
MAX_EVENT_PAYLOAD_DEPTH = 16
MAX_EVENT_PAYLOAD_KEYS = 512
MAX_EVENT_PAYLOAD_ITEMS = 4096
MAX_EVENT_PAYLOAD_KEY_BYTES = 128


class ExtensionContractError(RuntimeError):
    """A versioned extension contract is invalid or unavailable."""


class ContractOwnershipError(ExtensionContractError):
    """A package attempted to mutate a contract owned by another package."""


class ContractCompatibilityError(ExtensionContractError):
    """No active provider/declaration satisfies the requested version."""


class EventDeliveryError(ExtensionContractError):
    """A synchronous reference event handler failed."""


@dataclass(frozen=True, slots=True)
class ServiceRegistration:
    owner: str
    contract: str
    version: str
    provider: Any
    active: bool = True


class ServiceRegistry:
    """Resolve the highest active service version satisfying a consumer range."""

    def __init__(self) -> None:
        self._registrations: dict[tuple[str, Version], ServiceRegistration] = {}
        self._lock = threading.RLock()

    def register(
        self,
        *,
        owner: str,
        contract: str,
        version: str,
        provider: Any,
    ) -> ServiceRegistration:
        owner, contract = _validate_owned_contract(owner, contract)
        parsed_version = _version(version)
        if provider is None:
            raise ValueError("service provider cannot be None")
        key = (contract, parsed_version)
        with self._lock:
            if key in self._registrations:
                raise ExtensionContractError("service contract version is already registered")
            registration = ServiceRegistration(owner, contract, str(parsed_version), provider)
            self._registrations[key] = registration
            return registration

    def resolve(self, contract: str, version: str = "*") -> Any:
        _validate_contract_name(contract)
        specifier = _specifier(version)
        with self._lock:
            candidates = [
                (parsed, registration)
                for (name, parsed), registration in self._registrations.items()
                if name == contract and registration.active and parsed in specifier
            ]
            if not candidates:
                raise ContractCompatibilityError("no compatible active service provider")
            return max(candidates, key=lambda item: item[0])[1].provider

    def unregister(self, *, owner: str, contract: str, version: str) -> None:
        _validate_owner(owner)
        key = (_validate_contract_name(contract), _version(version))
        with self._lock:
            registration = self._registrations.get(key)
            if registration is None:
                raise ExtensionContractError("service contract version is not registered")
            if registration.owner != owner:
                raise ContractOwnershipError("only the service owner may unregister it")
            del self._registrations[key]

    def deactivate_owner(self, owner: str) -> int:
        return self._set_owner_active(owner, False)

    def activate_owner(self, owner: str) -> int:
        return self._set_owner_active(owner, True)

    def _set_owner_active(self, owner: str, active: bool) -> int:
        _validate_owner(owner)
        changed = 0
        with self._lock:
            for key, registration in tuple(self._registrations.items()):
                if registration.owner == owner and registration.active != active:
                    self._registrations[key] = replace(registration, active=active)
                    changed += 1
        return changed


EventValidator = Callable[[Mapping[str, Any]], Mapping[str, Any]]
EventHandler = Callable[[Mapping[str, Any]], None]


@dataclass(frozen=True, slots=True)
class EventDeclaration:
    owner: str
    contract: str
    version: str
    validator: EventValidator | None = None
    active: bool = True


@dataclass(frozen=True, slots=True)
class EventSubscription:
    subscriber: str
    contract: str
    version: str
    handler: EventHandler
    priority: int = 100
    active: bool = True


class EventBus:
    """Synchronous, at-most-once reference bus for declared versioned events."""

    def __init__(self) -> None:
        self._declarations: dict[tuple[str, Version], EventDeclaration] = {}
        self._subscriptions: list[EventSubscription] = []
        self._lock = threading.RLock()

    def declare(
        self,
        *,
        owner: str,
        contract: str,
        version: str,
        validator: EventValidator | None = None,
    ) -> EventDeclaration:
        owner, contract = _validate_owned_contract(owner, contract)
        parsed = _version(version)
        key = (contract, parsed)
        with self._lock:
            if key in self._declarations:
                raise ExtensionContractError("event contract version is already declared")
            declaration = EventDeclaration(owner, contract, str(parsed), validator)
            self._declarations[key] = declaration
            return declaration

    def subscribe(
        self,
        *,
        subscriber: str,
        contract: str,
        version: str,
        handler: EventHandler,
        priority: int = 100,
    ) -> EventSubscription:
        subscriber = _validate_owner(subscriber)
        contract = _validate_contract_name(contract)
        specifier = _specifier(version)
        if not callable(handler):
            raise TypeError("event handler must be callable")
        if not -10_000 <= priority <= 10_000:
            raise ValueError("event priority is outside the supported range")
        with self._lock:
            if not any(
                name == contract and parsed in specifier and declaration.active
                for (name, parsed), declaration in self._declarations.items()
            ):
                raise ContractCompatibilityError("event subscription has no compatible contract")
            if any(
                item.subscriber == subscriber
                and item.contract == contract
                and item.version == version
                for item in self._subscriptions
            ):
                raise ExtensionContractError("event subscription is already registered")
            subscription = EventSubscription(
                subscriber, contract, version, handler, priority
            )
            self._subscriptions.append(subscription)
            return subscription

    def publish(
        self,
        *,
        owner: str,
        contract: str,
        version: str,
        payload: Mapping[str, Any],
    ) -> int:
        owner = _validate_owner(owner)
        contract = _validate_contract_name(contract)
        parsed = _version(version)
        with self._lock:
            declaration = self._declarations.get((contract, parsed))
            if declaration is None or not declaration.active:
                raise ContractCompatibilityError("event contract version is not active")
            if declaration.owner != owner:
                raise ContractOwnershipError("only the event owner may publish it")
            snapshot = _json_snapshot(payload)
            if declaration.validator is not None:
                try:
                    snapshot = _json_snapshot(declaration.validator(snapshot))
                except Exception:
                    raise ExtensionContractError("event payload validation failed") from None
            subscriptions = sorted(
                (
                    item
                    for item in self._subscriptions
                    if item.active
                    and item.contract == contract
                    and parsed in _specifier(item.version)
                ),
                key=lambda item: (item.priority, item.subscriber),
            )
        delivered = 0
        for subscription in subscriptions:
            try:
                subscription.handler(_json_snapshot(snapshot))
            except Exception:
                raise EventDeliveryError(
                    f"event delivery failed for subscriber {subscription.subscriber}"
                ) from None
            delivered += 1
        return delivered

    def deactivate_owner(self, owner: str) -> int:
        return self._set_owner_active(owner, False)

    def activate_owner(self, owner: str) -> int:
        return self._set_owner_active(owner, True)

    def _set_owner_active(self, owner: str, active: bool) -> int:
        owner = _validate_owner(owner)
        changed = 0
        with self._lock:
            for key, declaration in tuple(self._declarations.items()):
                if declaration.owner == owner and declaration.active != active:
                    self._declarations[key] = replace(declaration, active=active)
                    changed += 1
            for index, subscription in enumerate(self._subscriptions):
                if subscription.subscriber == owner and subscription.active != active:
                    self._subscriptions[index] = replace(subscription, active=active)
                    changed += 1
        return changed


@dataclass(frozen=True, slots=True)
class RenderSlotDeclaration:
    owner: str
    contract: str
    version: str
    active: bool = True


@dataclass(frozen=True, slots=True)
class RenderBinding:
    contributor: str
    slot: str
    version: str
    template: str
    position: int = 100
    active: bool = True


class RenderSlotRegistry:
    """Own versioned render hooks and order package-owned template bindings."""

    def __init__(self) -> None:
        self._slots: dict[tuple[str, Version], RenderSlotDeclaration] = {}
        self._bindings: list[RenderBinding] = []
        self._lock = threading.RLock()

    def declare(self, *, owner: str, slot: str, version: str) -> RenderSlotDeclaration:
        owner, slot = _validate_owned_contract(owner, slot)
        parsed = _version(version)
        key = (slot, parsed)
        with self._lock:
            if key in self._slots:
                raise ExtensionContractError("render slot version is already declared")
            declaration = RenderSlotDeclaration(owner, slot, str(parsed))
            self._slots[key] = declaration
            return declaration

    def bind(
        self,
        *,
        contributor: str,
        slot: str,
        version: str,
        template: str,
        position: int = 100,
    ) -> RenderBinding:
        contributor = _validate_owner(contributor)
        slot = _validate_contract_name(slot)
        specifier = _specifier(version)
        template = _safe_template(template)
        if not -10_000 <= position <= 10_000:
            raise ValueError("render position is outside the supported range")
        with self._lock:
            if not any(
                name == slot and parsed in specifier and declaration.active
                for (name, parsed), declaration in self._slots.items()
            ):
                raise ContractCompatibilityError("render binding has no compatible slot")
            if any(
                item.contributor == contributor
                and item.slot == slot
                and item.version == version
                and item.template == template
                for item in self._bindings
            ):
                raise ExtensionContractError("render binding is already registered")
            binding = RenderBinding(contributor, slot, version, template, position)
            self._bindings.append(binding)
            return binding

    def bindings(self, *, slot: str, version: str) -> tuple[RenderBinding, ...]:
        slot = _validate_contract_name(slot)
        parsed = _version(version)
        with self._lock:
            declaration = self._slots.get((slot, parsed))
            if declaration is None or not declaration.active:
                raise ContractCompatibilityError("render slot version is not active")
            return tuple(
                sorted(
                    (
                        item
                        for item in self._bindings
                        if item.active
                        and item.slot == slot
                        and parsed in _specifier(item.version)
                    ),
                    key=lambda item: (item.position, item.contributor, item.template),
                )
            )

    def remove_slot(self, *, owner: str, slot: str, version: str) -> None:
        owner = _validate_owner(owner)
        key = (_validate_contract_name(slot), _version(version))
        with self._lock:
            declaration = self._slots.get(key)
            if declaration is None:
                raise ExtensionContractError("render slot version is not declared")
            if declaration.owner != owner:
                raise ContractOwnershipError("only the render slot owner may remove it")
            if any(
                item.slot == slot and key[1] in _specifier(item.version)
                for item in self._bindings
            ):
                raise ExtensionContractError("render slot still has registered bindings")
            del self._slots[key]

    def unbind(
        self,
        *,
        contributor: str,
        slot: str,
        version: str,
        template: str,
    ) -> None:
        contributor = _validate_owner(contributor)
        slot = _validate_contract_name(slot)
        _specifier(version)
        template = _safe_template(template)
        with self._lock:
            for index, binding in enumerate(self._bindings):
                if (
                    binding.contributor == contributor
                    and binding.slot == slot
                    and binding.version == version
                    and binding.template == template
                ):
                    del self._bindings[index]
                    return
        raise ContractOwnershipError("render binding is not owned by the contributor")

    def deactivate_owner(self, owner: str) -> int:
        return self._set_owner_active(owner, False)

    def activate_owner(self, owner: str) -> int:
        return self._set_owner_active(owner, True)

    def _set_owner_active(self, owner: str, active: bool) -> int:
        owner = _validate_owner(owner)
        changed = 0
        with self._lock:
            for key, declaration in tuple(self._slots.items()):
                if declaration.owner == owner and declaration.active != active:
                    self._slots[key] = replace(declaration, active=active)
                    changed += 1
            for index, binding in enumerate(self._bindings):
                if binding.contributor == owner and binding.active != active:
                    self._bindings[index] = replace(binding, active=active)
                    changed += 1
        return changed


def _validate_owned_contract(owner: str, contract: str) -> tuple[str, str]:
    owner = _validate_owner(owner)
    contract = _validate_contract_name(contract)
    if owner == "core" or contract.startswith("core."):
        raise ContractOwnershipError("core.* contracts are reserved for Platform Core")
    if not contract.startswith(f"{owner}."):
        raise ContractOwnershipError("contract name must use its package-owned namespace")
    return owner, contract


def _validate_owner(value: str) -> str:
    if not isinstance(value, str) or not _OWNER.fullmatch(value):
        raise ValueError("invalid extension owner id")
    return value


def _validate_contract_name(value: str) -> str:
    if not isinstance(value, str) or len(value) > 192 or not _CONTRACT.fullmatch(value):
        raise ValueError("invalid versioned contract name")
    return value


def _version(value: str) -> Version:
    if not isinstance(value, str) or not _SEMVER.fullmatch(value):
        raise ValueError("contract version must be semantic major.minor.patch")
    try:
        parsed = Version(value)
    except (InvalidVersion, TypeError) as error:
        raise ValueError("invalid contract version") from error
    if parsed.is_prerelease or parsed.is_devrelease or parsed.local is not None:
        raise ValueError("contract versions must be stable public releases")
    return parsed


def _specifier(value: str) -> SpecifierSet:
    if not isinstance(value, str):
        raise ValueError("invalid contract version range")
    try:
        if len(value.encode("utf-8")) > MAX_VERSION_RANGE_BYTES:
            raise ValueError("contract version range exceeds the size limit")
    except UnicodeError:
        raise ValueError("invalid contract version range") from None
    try:
        return SpecifierSet("" if value == "*" else value)
    except (InvalidSpecifier, TypeError) as error:
        raise ValueError("invalid contract version range") from error


def _safe_template(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("invalid render template path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("invalid render template path")
    return path.as_posix()


def _json_snapshot(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise TypeError("event payload must be a mapping")
    _validate_event_payload_structure(payload)
    try:
        encoded = json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(encoded.encode("utf-8")) > MAX_EVENT_PAYLOAD_BYTES:
            raise ExtensionContractError("event payload exceeds the reference size limit")
        decoded = json.loads(encoded)
    except ExtensionContractError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as error:
        raise ExtensionContractError("event payload must be JSON-safe") from error
    if not isinstance(decoded, dict):
        raise ExtensionContractError("event payload must be an object")
    return decoded


def _validate_event_payload_structure(payload: Mapping[str, Any]) -> None:
    stack: list[tuple[Any, int]] = [(payload, 1)]
    seen: set[int] = set()
    key_count = 0
    item_count = 0
    while stack:
        current, depth = stack.pop()
        item_count += 1
        if item_count > MAX_EVENT_PAYLOAD_ITEMS:
            raise ExtensionContractError("event payload exceeds the item limit")
        if depth > MAX_EVENT_PAYLOAD_DEPTH:
            raise ExtensionContractError("event payload exceeds the depth limit")
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                raise ExtensionContractError("event payload must be acyclic")
            seen.add(identity)
            for key, nested in current.items():
                if not isinstance(key, str):
                    raise ExtensionContractError("event payload field names must be strings")
                try:
                    key_bytes = len(key.encode("utf-8"))
                except UnicodeError:
                    raise ExtensionContractError("event payload field name is invalid") from None
                if not 1 <= key_bytes <= MAX_EVENT_PAYLOAD_KEY_BYTES:
                    raise ExtensionContractError("event payload field name is invalid")
                key_count += 1
                if key_count > MAX_EVENT_PAYLOAD_KEYS:
                    raise ExtensionContractError("event payload exceeds the key limit")
                stack.append((nested, depth + 1))
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in seen:
                raise ExtensionContractError("event payload must be acyclic")
            seen.add(identity)
            stack.extend((nested, depth + 1) for nested in current)
