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
    """Package-owned named connections backed by existing secret providers."""

    REGISTRY_VERSION = 1

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def upsert(self, connection: ConnectionRef) -> ConnectionRef:
        if not isinstance(connection, ConnectionRef):
            raise TypeError("connection must be a ConnectionRef")
        if not isinstance(connection.secret, SecretReference):
            raise TypeError("connection secret must be a SecretReference")
        key = _connection_key(connection.owner, connection.id)
        with exclusive_file_lock(self.path):
            registry = self._read()
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
        """Forget every named connection granted to a package."""

        prefix = _owner_connection_prefix(owner)
        with exclusive_file_lock(self.path):
            registry = self._read()
            connections = registry["connections"]
            removing = [
                key
                for key in tuple(connections)
                if isinstance(key, str) and key.startswith(prefix)
            ]
            if not removing:
                return 0
            for key in removing:
                del connections[key]
            write_json_atomic(self.path, registry)
            return len(removing)

    def _read(self) -> dict:
        data = read_json(
            self.path,
            {"version": self.REGISTRY_VERSION, "connections": {}},
        )
        if not isinstance(data, dict):
            raise ConnectionStoreError("invalid connection registry")
        connections = data.get("connections")
        if not isinstance(connections, dict):
            raise ConnectionStoreError("invalid connection registry")
        return {
            "version": self.REGISTRY_VERSION,
            "connections": connections,
        }


def _connection_key(owner: str, connection_id: str) -> str:
    return f"{owner}:{connection_id}"


def _owner_connection_prefix(owner: str) -> str:
    if not isinstance(owner, str) or not _OWNER.fullmatch(owner):
        raise ValueError("invalid extension owner id")
    return f"{owner}:"
