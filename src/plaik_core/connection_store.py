"""Persist ConnectionRef identities; credentials stay SecretReference pointers."""

from __future__ import annotations

import re
from pathlib import Path

from plaik_contracts import ConnectionRef, SecretReference
from plaik_contracts.packages import PACKAGE_ID_PATTERN

from .storage import exclusive_file_lock, read_json, write_json_atomic

_OWNER = re.compile(PACKAGE_ID_PATTERN)


class ConnectionStoreError(RuntimeError):
    """A connection identity could not be stored or loaded."""


class ConnectionStore:
    """Package-owned named connections backed by existing secret providers.

    Occupancy generation is the linearization token for grants. ``revoke_owner``
    always advances the owner's generation under the same file lock that
    serializes ``upsert``. A writer that sampled a generation before revoke
    cannot recreate the grant (including after a later install — ABA).
    Omitting ``occupancy_generation`` takes the live generation inside the
    lock and is a fresh grant, not a stale retry.
    """

    REGISTRY_VERSION = 2
    LEGACY_REGISTRY_VERSION = 1

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def occupancy_generation(self, owner: str) -> int:
        """Return the live occupancy epoch used to fence grants for ``owner``."""

        _owner_connection_prefix(owner)
        registry = self._read()
        return registry["owner_generations"].get(owner, 0)

    def upsert(
        self,
        connection: ConnectionRef,
        *,
        occupancy_generation: int | None = None,
    ) -> ConnectionRef:
        if not isinstance(connection, ConnectionRef):
            raise TypeError("connection must be a ConnectionRef")
        if not isinstance(connection.secret, SecretReference):
            raise TypeError("connection secret must be a SecretReference")
        if occupancy_generation is not None:
            occupancy_generation = _require_generation(occupancy_generation)
        key = _connection_key(connection.owner, connection.id)
        with exclusive_file_lock(self.path):
            registry = self._read()
            current = registry["owner_generations"].get(connection.owner, 0)
            expected = current if occupancy_generation is None else occupancy_generation
            if expected != current:
                raise ConnectionStoreError(
                    f"connection occupancy generation is stale: {connection.owner}"
                )
            registry["connections"][key] = connection.model_dump(mode="json")
            write_json_atomic(self.path, registry)
        return connection

    def get(self, owner: str, connection_id: str) -> ConnectionRef:
        key = _connection_key(owner, connection_id)
        registry = self._read()
        payload = registry["connections"].get(key)
        if not isinstance(payload, dict):
            raise ConnectionStoreError(f"connection is not registered: {owner}/{connection_id}")
        return ConnectionRef.model_validate(payload)

    def list_for_owner(self, owner: str) -> tuple[ConnectionRef, ...]:
        prefix = _owner_connection_prefix(owner)
        registry = self._read()
        items = []
        for key, payload in registry["connections"].items():
            if not isinstance(key, str) or not key.startswith(prefix):
                continue
            if not isinstance(payload, dict):
                raise ConnectionStoreError(f"invalid connection record: {key}")
            items.append(ConnectionRef.model_validate(payload))
        return tuple(sorted(items, key=lambda item: item.id))

    def revoke_owner(self, owner: str) -> int:
        """Forget grants for a package and advance its occupancy generation."""

        prefix = _owner_connection_prefix(owner)
        with exclusive_file_lock(self.path):
            registry = self._read()
            generations = registry["owner_generations"]
            generations[owner] = generations.get(owner, 0) + 1
            connections = registry["connections"]
            removing = [
                key
                for key in tuple(connections)
                if isinstance(key, str) and key.startswith(prefix)
            ]
            for key in removing:
                del connections[key]
            write_json_atomic(self.path, registry)
            return len(removing)

    def _read(self) -> dict:
        data = read_json(
            self.path,
            {
                "version": self.REGISTRY_VERSION,
                "connections": {},
                "owner_generations": {},
            },
        )
        if not isinstance(data, dict):
            raise ConnectionStoreError("invalid connection registry")
        version = data.get("version")
        if version not in {self.LEGACY_REGISTRY_VERSION, self.REGISTRY_VERSION}:
            raise ConnectionStoreError("unsupported connection registry version")
        connections = data.get("connections")
        if not isinstance(connections, dict):
            raise ConnectionStoreError("invalid connection registry")
        if version == self.LEGACY_REGISTRY_VERSION:
            generations = data.get("owner_generations", {})
        else:
            generations = data.get("owner_generations")
        if not isinstance(generations, dict):
            raise ConnectionStoreError("invalid connection registry")
        canonical_generations: dict[str, int] = {}
        for owner, value in generations.items():
            if not isinstance(owner, str) or not _OWNER.fullmatch(owner):
                raise ConnectionStoreError("invalid connection occupancy generation")
            canonical_generations[owner] = _require_generation(value)
        return {
            "version": self.REGISTRY_VERSION,
            "connections": connections,
            "owner_generations": canonical_generations,
        }


def _connection_key(owner: str, connection_id: str) -> str:
    return f"{owner}:{connection_id}"


def _owner_connection_prefix(owner: str) -> str:
    if not isinstance(owner, str) or not _OWNER.fullmatch(owner):
        raise ValueError("invalid extension owner id")
    return f"{owner}:"


def _require_generation(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConnectionStoreError("invalid connection occupancy generation")
    return value
