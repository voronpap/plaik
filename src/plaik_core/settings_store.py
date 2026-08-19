"""Typed, explicitly scoped settings with reference-only secret handling."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError
from plaik_contracts import SecretReference

from .context import StoreContext
from .storage import exclusive_file_lock, read_json, write_json_atomic


class SettingsStoreError(RuntimeError):
    """Settings data or an operation violates the scoped settings contract."""


class SettingsAuditEvent(BaseModel):
    """Value-free metadata safe to pass to the platform audit subsystem."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str
    namespace: str
    scope: str
    changed_fields: tuple[str, ...]
    secret_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SettingsResolution:
    """Validated settings plus the exact source scope for each explicit field."""

    values: BaseModel
    sources: Mapping[str, str]
    chain: tuple[str, ...]


AuditSink = Callable[[SettingsAuditEvent], None]


def settings_events_to_audit_sink(append: Callable[..., object]) -> AuditSink:
    """Adapt value-free settings events onto the platform audit journal."""

    def sink(event: SettingsAuditEvent) -> None:
        metadata: dict[str, Any] = {
            "scope": event.scope,
            "changed_fields": list(event.changed_fields),
        }
        if event.secret_fields:
            metadata["reference_fields"] = list(event.secret_fields)
        append(
            actor_id=None,
            action=f"settings.{event.action}",
            target_type="platform.settings",
            target_id=event.namespace,
            metadata=metadata,
        )

    return sink


class SettingsStore:
    """Persist and resolve typed overrides over the installation hierarchy.

    Schemas are registered by a stable namespace.  Stored records contain only
    the fields overridden at a scope.  Resolution walks installation, group and
    store scopes in that order and validates the final value with Pydantic.
    Mutations serialize the complete registry read-modify-write. External audit
    sinks run after commit and outside that lock; sink failures do not roll back
    the persisted mutation.
    """

    REGISTRY_VERSION = 1

    def __init__(
        self,
        path: Path,
        schemas: Mapping[str, type[BaseModel]],
        *,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self.path = path
        self.schemas = dict(schemas)
        self.audit_sink = audit_sink
        for namespace, schema in self.schemas.items():
            self._validate_namespace(namespace)
            if not isinstance(schema, type) or not issubclass(schema, BaseModel):
                raise TypeError(f"settings schema must be a BaseModel: {namespace}")

    def set(
        self,
        context: StoreContext,
        namespace: str,
        values: Mapping[str, Any] | BaseModel,
    ) -> SettingsResolution:
        """Set only the supplied fields as overrides at the exact context."""

        schema = self._schema(namespace)
        supplied = self._supplied_values(values)
        if not supplied:
            raise SettingsStoreError("at least one setting must be supplied")

        unknown = sorted(set(supplied) - self._public_field_names(schema))
        if unknown:
            raise SettingsStoreError(f"unknown settings for {namespace}: {unknown}")

        with exclusive_file_lock(self.path):
            registry = self._read_registry()
            scopes = registry["scopes"]
            scope_namespaces = scopes.setdefault(context.key, {})
            previous_override = scope_namespaces.get(namespace, {})
            if not isinstance(previous_override, dict):
                raise SettingsStoreError(
                    f"invalid settings record for {context.key}/{namespace}"
                )

            candidate_override = {**previous_override, **supplied}
            merged, _ = self._merge(
                context,
                namespace,
                registry,
                exact_override=candidate_override,
            )
            validated = self._validate(schema, namespace, merged)
            canonical = {
                key: value
                for key, value in validated.model_dump(mode="json", by_alias=True).items()
                if key in candidate_override
            }
            self._assert_secret_references(validated, supplied)

            scope_namespaces[namespace] = canonical
            write_json_atomic(self.path, registry)

        self._audit(
            action="set",
            namespace=namespace,
            context=context,
            changed_fields=tuple(sorted(supplied)),
            validated=validated,
        )
        return self.resolve(context, namespace)

    def clear(
        self,
        context: StoreContext,
        namespace: str,
        fields: set[str] | None = None,
    ) -> SettingsResolution:
        """Remove exact-scope overrides so values inherit from the parent/default."""

        schema = self._schema(namespace)
        with exclusive_file_lock(self.path):
            registry = self._read_registry()
            scopes = registry["scopes"]
            scope_namespaces = scopes.get(context.key, {})
            override = scope_namespaces.get(namespace, {})
            if not isinstance(override, dict):
                raise SettingsStoreError(
                    f"invalid settings record for {context.key}/{namespace}"
                )

            changed = set(override) if fields is None else set(fields)
            unknown = sorted(changed - self._public_field_names(schema))
            if unknown:
                raise SettingsStoreError(f"unknown settings for {namespace}: {unknown}")

            candidate = {
                key: value for key, value in override.items() if key not in changed
            }
            merged, _ = self._merge(
                context,
                namespace,
                registry,
                exact_override=candidate,
            )
            validated = self._validate(schema, namespace, merged)

            if candidate:
                scope_namespaces[namespace] = candidate
            else:
                scope_namespaces.pop(namespace, None)
            if not scope_namespaces:
                scopes.pop(context.key, None)

            write_json_atomic(self.path, registry)

        self._audit(
            action="clear",
            namespace=namespace,
            context=context,
            changed_fields=tuple(sorted(changed)),
            validated=validated,
        )
        return self.resolve(context, namespace)

    def resolve(self, context: StoreContext, namespace: str) -> SettingsResolution:
        schema = self._schema(namespace)
        registry = self._read_registry()
        merged, sources = self._merge(context, namespace, registry)
        validated = self._validate(schema, namespace, merged)
        for field_name, field in schema.model_fields.items():
            public_key = self._public_field_name(field_name, field)
            if public_key not in sources:
                sources[public_key] = "schema-default"
        return SettingsResolution(
            values=validated,
            sources=dict(sorted(sources.items())),
            chain=tuple(scope.key for scope in context.inheritance_chain()),
        )

    @staticmethod
    def _supplied_values(values: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
        if isinstance(values, BaseModel):
            return values.model_dump(mode="python", exclude_unset=True, by_alias=True)
        if not isinstance(values, Mapping):
            raise TypeError("settings values must be a mapping or BaseModel")
        return dict(values)

    def _schema(self, namespace: str) -> type[BaseModel]:
        self._validate_namespace(namespace)
        try:
            return self.schemas[namespace]
        except KeyError as error:
            raise SettingsStoreError(f"unknown settings namespace: {namespace}") from error

    @staticmethod
    def _validate_namespace(namespace: str) -> None:
        if not namespace or len(namespace) > 128:
            raise ValueError("settings namespace must contain 1..128 characters")
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
        if namespace[0] not in set("abcdefghijklmnopqrstuvwxyz0123456789") or any(
            character not in allowed for character in namespace
        ):
            raise ValueError(f"invalid settings namespace: {namespace}")

    @staticmethod
    def _public_field_name(field_name: str, field: Any) -> str:
        alias = getattr(field, "alias", None)
        if isinstance(alias, str) and alias:
            return alias
        return field_name

    @staticmethod
    def _public_field_names(schema: type[BaseModel]) -> set[str]:
        return {
            SettingsStore._public_field_name(name, field)
            for name, field in schema.model_fields.items()
        }

    @staticmethod
    def _python_field_name(schema: type[BaseModel], public_key: str) -> str | None:
        for name, field in schema.model_fields.items():
            if SettingsStore._public_field_name(name, field) == public_key:
                return name
        return None

    def register_schema(self, namespace: str, schema: type[BaseModel]) -> None:
        self._validate_namespace(namespace)
        if not isinstance(schema, type) or not issubclass(schema, BaseModel):
            raise TypeError(f"settings schema must be a BaseModel: {namespace}")
        self.schemas[namespace] = schema

    def _read_registry(self) -> dict[str, Any]:
        registry = read_json(
            self.path,
            {"version": self.REGISTRY_VERSION, "scopes": {}},
        )
        if not isinstance(registry, dict):
            raise SettingsStoreError("settings registry must be an object")
        if registry.get("version") != self.REGISTRY_VERSION:
            raise SettingsStoreError("unsupported settings registry version")
        scopes = registry.get("scopes")
        if not isinstance(scopes, dict):
            raise SettingsStoreError("settings registry scopes must be an object")
        return registry

    @staticmethod
    def _validate(
        schema: type[BaseModel], namespace: str, values: Mapping[str, Any]
    ) -> BaseModel:
        unknown = sorted(set(values) - SettingsStore._public_field_names(schema))
        if unknown:
            raise SettingsStoreError(f"unknown settings for {namespace}: {unknown}")
        try:
            return schema.model_validate(values)
        except ValidationError as error:
            raise SettingsStoreError(
                f"invalid resolved settings for {namespace}; "
                f"validation failed with {error.error_count()} issue(s)"
            ) from None

    @staticmethod
    def _merge(
        context: StoreContext,
        namespace: str,
        registry: Mapping[str, Any],
        *,
        exact_override: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        merged: dict[str, Any] = {}
        sources: dict[str, str] = {}
        scopes = registry["scopes"]
        chain = context.inheritance_chain()
        for scope in chain:
            scope_record = scopes.get(scope.key, {})
            if not isinstance(scope_record, dict):
                raise SettingsStoreError(f"invalid settings scope: {scope.key}")
            override = scope_record.get(namespace, {})
            if scope == context and exact_override is not None:
                override = exact_override
            if not isinstance(override, Mapping):
                raise SettingsStoreError(
                    f"invalid settings record for {scope.key}/{namespace}"
                )
            for field_name, value in override.items():
                merged[field_name] = value
                sources[field_name] = scope.key
        return merged, sources

    @staticmethod
    def _assert_secret_references(
        validated: BaseModel, supplied: Mapping[str, Any]
    ) -> None:
        """Reject plaintext supplied for fields typed as SecretReference."""

        for public_key in supplied:
            python_name = SettingsStore._python_field_name(type(validated), public_key)
            if python_name is None:
                continue
            value = getattr(validated, python_name)
            if isinstance(value, SecretReference):
                raw = supplied[public_key]
                if not isinstance(raw, (SecretReference, Mapping)):
                    raise SettingsStoreError(
                        f"secret setting {public_key} must be a SecretReference"
                    )

    @staticmethod
    def _contains_secret_reference(value: Any) -> bool:
        if isinstance(value, SecretReference):
            return True
        if isinstance(value, BaseModel):
            return any(
                SettingsStore._contains_secret_reference(item)
                for item in value.__dict__.values()
            )
        if isinstance(value, Mapping):
            return any(
                SettingsStore._contains_secret_reference(item)
                for item in value.values()
            )
        if isinstance(value, (list, tuple, set, frozenset)):
            return any(SettingsStore._contains_secret_reference(item) for item in value)
        return False

    def _audit(
        self,
        *,
        action: str,
        namespace: str,
        context: StoreContext,
        changed_fields: tuple[str, ...],
        validated: BaseModel,
    ) -> None:
        if self.audit_sink is None:
            return
        secret_fields = tuple(
            sorted(
                public_key
                for public_key in changed_fields
                if self._contains_secret_reference(
                    getattr(
                        validated,
                        self._python_field_name(type(validated), public_key)
                        or public_key,
                    )
                )
            )
        )
        self.audit_sink(
            SettingsAuditEvent(
                action=action,
                namespace=namespace,
                scope=context.key,
                changed_fields=changed_fields,
                secret_fields=secret_fields,
            )
        )
