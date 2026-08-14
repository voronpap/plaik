"""Authenticated metadata lifecycle for long-lived cryptographic keys."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .storage import exclusive_file_lock, read_json, write_json_atomic


_ID = re.compile(r"^[a-z0-9][a-z0-9._:@-]{2,127}$")


class KeyLifecycleError(RuntimeError):
    """A key lifecycle transition or authenticated registry is invalid."""


class KeyState(StrEnum):
    ACTIVE = "active"
    VERIFY_ONLY = "verify_only"
    REVOKED = "revoked"
    RETIRED = "retired"


@dataclass(frozen=True, slots=True)
class KeyGeneration:
    purpose: str
    key_id: str
    algorithm: str
    state: KeyState
    predecessor: str | None
    created_at: str
    changed_at: str


class KeyLifecycleRegistry:
    """Track rotation/revocation metadata separately from secret material."""

    def __init__(self, path: Path, *, integrity_key: bytes, integrity_key_id: str) -> None:
        if len(integrity_key) < 32:
            raise ValueError("key lifecycle integrity key is too short")
        if _ID.fullmatch(integrity_key_id) is None:
            raise ValueError("invalid lifecycle integrity key identity")
        self._path = Path(path)
        self._key = bytes(integrity_key)
        self._key_id = integrity_key_id

    def records(self) -> dict[str, KeyGeneration]:
        envelope = read_json(self._path, None)
        if envelope is None:
            return {}
        if not isinstance(envelope, dict) or set(envelope) != {
            "format", "integrity_key_id", "records", "hmac_sha256"
        }:
            raise KeyLifecycleError("key lifecycle registry is invalid")
        signed = {key: envelope[key] for key in ("format", "integrity_key_id", "records")}
        expected = hmac.new(self._key, self._canonical(signed), hashlib.sha256).hexdigest()
        if (envelope["format"] != "plaik-key-lifecycle/v1"
                or envelope["integrity_key_id"] != self._key_id
                or not hmac.compare_digest(str(envelope["hmac_sha256"]), expected)
                or not isinstance(envelope["records"], dict)
                or len(envelope["records"]) > 256):
            raise KeyLifecycleError("key lifecycle authentication failed")
        try:
            return {
                key_id: KeyGeneration(**{**value, "state": KeyState(value["state"])})
                for key_id, value in envelope["records"].items()
            }
        except (KeyError, TypeError, ValueError):
            raise KeyLifecycleError("key lifecycle schema is invalid") from None

    def provision(self, purpose: str, key_id: str, algorithm: str) -> KeyGeneration:
        purpose, key_id, algorithm = self._validate(purpose, key_id, algorithm)
        with exclusive_file_lock(self._path):
            records = self.records()
            existing = records.get(key_id)
            if existing is not None:
                if (existing.purpose, existing.algorithm) == (purpose, algorithm):
                    return existing
                raise KeyLifecycleError("key identity cannot be rebound")
            if any(item.purpose == purpose and item.state == KeyState.ACTIVE
                   for item in records.values()):
                raise KeyLifecycleError("purpose already has an active key generation")
            now = datetime.now(UTC).isoformat()
            created = KeyGeneration(purpose, key_id, algorithm, KeyState.ACTIVE,
                                    None, now, now)
            records[key_id] = created
            self._write(records)
            return created

    def rotate(self, purpose: str, next_key_id: str, algorithm: str) -> KeyGeneration:
        purpose, next_key_id, algorithm = self._validate(purpose, next_key_id, algorithm)
        with exclusive_file_lock(self._path):
            records = self.records()
            current = [item for item in records.values()
                       if item.purpose == purpose and item.state == KeyState.ACTIVE]
            if len(current) != 1 or next_key_id in records:
                raise KeyLifecycleError("key rotation precondition failed")
            now = datetime.now(UTC).isoformat()
            previous = current[0]
            records[previous.key_id] = KeyGeneration(
                previous.purpose, previous.key_id, previous.algorithm,
                KeyState.VERIFY_ONLY, previous.predecessor, previous.created_at, now,
            )
            created = KeyGeneration(purpose, next_key_id, algorithm, KeyState.ACTIVE,
                                    previous.key_id, now, now)
            records[next_key_id] = created
            self._write(records)
            return created

    def revoke(self, key_id: str) -> KeyGeneration:
        return self._transition(key_id, KeyState.REVOKED)

    def retire(self, key_id: str) -> KeyGeneration:
        with exclusive_file_lock(self._path):
            records = self.records()
            current = self._require(records, key_id)
            if current.state not in {KeyState.VERIFY_ONLY, KeyState.REVOKED}:
                raise KeyLifecycleError("active key cannot be retired")
            return self._replace(records, current, KeyState.RETIRED)

    def signing_key(self, purpose: str) -> KeyGeneration:
        matches = [item for item in self.records().values()
                   if item.purpose == purpose and item.state == KeyState.ACTIVE]
        if len(matches) != 1:
            raise KeyLifecycleError("purpose has no unique active signing key")
        return matches[0]

    def require_verifiable(self, key_id: str) -> KeyGeneration:
        current = self._require(self.records(), key_id)
        if current.state not in {KeyState.ACTIVE, KeyState.VERIFY_ONLY}:
            raise KeyLifecycleError("key generation is not trusted for verification")
        return current

    def _transition(self, key_id: str, state: KeyState) -> KeyGeneration:
        with exclusive_file_lock(self._path):
            records = self.records()
            return self._replace(records, self._require(records, key_id), state)

    def _replace(self, records: dict[str, KeyGeneration], current: KeyGeneration,
                 state: KeyState) -> KeyGeneration:
        changed = KeyGeneration(
            current.purpose, current.key_id, current.algorithm, state,
            current.predecessor, current.created_at, datetime.now(UTC).isoformat(),
        )
        records[current.key_id] = changed
        self._write(records)
        return changed

    def _write(self, records: dict[str, KeyGeneration]) -> None:
        signed = {
            "format": "plaik-key-lifecycle/v1",
            "integrity_key_id": self._key_id,
            "records": {key_id: {**asdict(item), "state": item.state.value}
                        for key_id, item in sorted(records.items())},
        }
        write_json_atomic(self._path, {
            **signed,
            "hmac_sha256": hmac.new(self._key, self._canonical(signed), hashlib.sha256).hexdigest(),
        })

    @staticmethod
    def _canonical(value: dict[str, object]) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def _validate(purpose: str, key_id: str, algorithm: str) -> tuple[str, str, str]:
        if any(_ID.fullmatch(value) is None for value in (purpose, key_id, algorithm)):
            raise ValueError("invalid key lifecycle identity")
        return purpose, key_id, algorithm

    @staticmethod
    def _require(records: dict[str, KeyGeneration], key_id: str) -> KeyGeneration:
        try:
            return records[key_id]
        except KeyError:
            raise KeyLifecycleError("unknown key generation") from None
