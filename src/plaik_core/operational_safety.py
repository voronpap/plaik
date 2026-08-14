"""Durable maintenance fencing and bounded process shutdown barriers."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .storage import exclusive_file_lock, read_json, write_json_atomic


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_REASON = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")


class OperationalSafetyError(RuntimeError):
    """Operational safety state is unsafe or a requested transition conflicts."""


class MaintenanceActive(OperationalSafetyError):
    """A privileged or durable mutation was attempted while writes are frozen."""


class StaleMaintenanceGeneration(OperationalSafetyError):
    """A process observed an older durable maintenance generation."""


@dataclass(frozen=True, slots=True)
class MaintenanceState:
    generation: int
    active: bool
    operation_id: str | None
    actor_id: str | None
    reason: str | None
    changed_at: str
    key_id: str


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class MaintenanceController:
    """Serialize and authenticate one shared maintenance generation."""

    def __init__(
        self,
        path: Path,
        *,
        integrity_key: bytes,
        key_id: str,
        event_sink: Callable[[str, dict[str, object]], None],
    ) -> None:
        if len(integrity_key) < 32:
            raise ValueError("maintenance integrity key is too short")
        if _REASON.fullmatch(key_id) is None:
            raise ValueError("invalid maintenance integrity key identity")
        self._path = Path(path)
        self._key = bytes(integrity_key)
        self._key_id = key_id
        self._event_sink = event_sink

    def state(self) -> MaintenanceState:
        envelope = read_json(self._path, None)
        if envelope is None:
            return MaintenanceState(0, False, None, None, None, "", self._key_id)
        if not isinstance(envelope, dict) or set(envelope) != {"state", "hmac_sha256"}:
            raise OperationalSafetyError("maintenance state envelope is invalid")
        payload = envelope["state"]
        if not isinstance(payload, dict):
            raise OperationalSafetyError("maintenance state is invalid")
        expected = hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(envelope["hmac_sha256"]), expected):
            raise OperationalSafetyError("maintenance state authentication failed")
        try:
            state = MaintenanceState(**payload)
        except (TypeError, ValueError):
            raise OperationalSafetyError("maintenance state schema is invalid") from None
        if state.generation < 1 or state.key_id != self._key_id:
            raise OperationalSafetyError("maintenance state key generation is invalid")
        if state.active != bool(state.operation_id):
            raise OperationalSafetyError("maintenance state activity binding is invalid")
        return state

    def enter(
        self,
        operation_id: str,
        *,
        actor_id: str,
        reason: str,
        expected_generation: int,
    ) -> MaintenanceState:
        operation_id, actor_id, reason = self._validate(operation_id, actor_id, reason)
        with exclusive_file_lock(self._path):
            current = self.state()
            if current.active:
                if (current.operation_id, current.actor_id, current.reason) == (
                    operation_id,
                    actor_id,
                    reason,
                ):
                    return current
                raise MaintenanceActive("another maintenance operation is active")
            if current.generation != expected_generation:
                raise StaleMaintenanceGeneration("maintenance generation changed")
            changed = self._publish(
                generation=current.generation + 1,
                active=True,
                operation_id=operation_id,
                actor_id=actor_id,
                reason=reason,
            )
            self._event_sink("maintenance.entered", self._metadata(changed))
            return changed

    def exit(
        self,
        operation_id: str,
        *,
        actor_id: str,
        expected_generation: int,
        validate_invariants: Callable[[], None],
    ) -> MaintenanceState:
        operation_id, actor_id, _ = self._validate(operation_id, actor_id, "resume")
        with exclusive_file_lock(self._path):
            current = self.state()
            if not current.active:
                if current.operation_id is None and current.generation == expected_generation:
                    return current
                raise StaleMaintenanceGeneration("maintenance generation changed")
            if current.generation != expected_generation:
                raise StaleMaintenanceGeneration("maintenance generation changed")
            validate_invariants()
            changed = self._publish(
                generation=current.generation + 1,
                active=False,
                operation_id=None,
                actor_id=None,
                reason=None,
            )
            self._event_sink(
                "maintenance.exited",
                {
                    **self._metadata(changed),
                    "resume_operation_id": operation_id,
                    "resume_actor_id": actor_id,
                },
            )
            return changed

    def require_writable(self, observed_generation: int | None = None) -> int:
        current = self.state()
        if current.active:
            raise MaintenanceActive("privileged writes are frozen")
        if observed_generation is not None and observed_generation != current.generation:
            raise StaleMaintenanceGeneration("writer maintenance fence is stale")
        return current.generation

    def _publish(self, **values: object) -> MaintenanceState:
        state = MaintenanceState(
            **values,
            changed_at=datetime.now(UTC).isoformat(),
            key_id=self._key_id,
        )
        payload = {
            "generation": state.generation,
            "active": state.active,
            "operation_id": state.operation_id,
            "actor_id": state.actor_id,
            "reason": state.reason,
            "changed_at": state.changed_at,
            "key_id": state.key_id,
        }
        write_json_atomic(
            self._path,
            {
                "state": payload,
                "hmac_sha256": hmac.new(
                    self._key,
                    _canonical(payload),
                    hashlib.sha256,
                ).hexdigest(),
            },
        )
        return state

    @staticmethod
    def _validate(operation_id: str, actor_id: str, reason: str) -> tuple[str, str, str]:
        if _IDENTIFIER.fullmatch(operation_id) is None:
            raise ValueError("invalid maintenance operation identity")
        if _ACTOR.fullmatch(actor_id) is None:
            raise ValueError("invalid maintenance actor identity")
        if _REASON.fullmatch(reason) is None:
            raise ValueError("invalid maintenance reason")
        return operation_id, actor_id, reason

    @staticmethod
    def _metadata(state: MaintenanceState) -> dict[str, object]:
        return {
            "generation": state.generation,
            "operation_id": state.operation_id,
            "actor_id": state.actor_id,
            "reason": state.reason,
            "key_id": state.key_id,
        }


class ShutdownBarrier:
    """Reject new durable work after shutdown begins and drain boundedly."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._closing = False
        self._active = 0

    @contextmanager
    def durable_work(self) -> Iterator[None]:
        with self._condition:
            if self._closing:
                raise OperationalSafetyError("shutdown barrier is closed")
            self._active += 1
        try:
            yield
        finally:
            with self._condition:
                self._active -= 1
                self._condition.notify_all()

    def begin_shutdown(self, timeout_seconds: float) -> bool:
        if not 0 <= timeout_seconds <= 60:
            raise ValueError("shutdown timeout is outside the supported bound")
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            self._closing = True
            while self._active:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True
