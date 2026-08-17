"""Serialize public EventEnvelope fields onto durable outbox rows."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from plaik_contracts import EventEnvelope, ResourceRef, ScopeRef


def dump_scope(scope: ScopeRef | None) -> str | None:
    if scope is None:
        return None
    return json.dumps(scope.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def dump_resource(resource: ResourceRef | None) -> str | None:
    if resource is None:
        return None
    return json.dumps(resource.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def load_scope(raw: Any) -> ScopeRef:
    payload = _as_mapping(raw)
    if payload is None:
        return ScopeRef.installation()
    return ScopeRef.model_validate(payload)


def load_resource(raw: Any) -> ResourceRef | None:
    payload = _as_mapping(raw)
    if payload is None:
        return None
    return ResourceRef.model_validate(payload)


def parse_created_at(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        created = value
    else:
        created = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if created.tzinfo is None:
        return created.replace(tzinfo=UTC)
    return created


def envelope_from_row(
    *,
    event_id: str,
    owner: str,
    contract: str,
    version: str,
    payload: dict[str, Any],
    scope_raw: Any,
    resource_raw: Any,
    idempotency_key: str | None,
    correlation_id: str | None,
    created_at: datetime | str,
) -> EventEnvelope:
    return EventEnvelope(
        id=event_id,
        owner=owner,
        contract=contract,
        version=version,
        payload=payload,
        scope=load_scope(scope_raw),
        resource=load_resource(resource_raw),
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        created_at=parse_created_at(created_at),
    )


def _as_mapping(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        if not raw:
            return None
        decoded = json.loads(raw)
        if decoded is None:
            return None
        if not isinstance(decoded, dict):
            raise ValueError("envelope field must be a JSON object")
        return decoded
    raise ValueError("envelope field must be JSON")
