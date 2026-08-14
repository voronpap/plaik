"""Audited, rollback-capable theme activation coordinator."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .audit import AuditLog, AuditOutcome
from .operation_journal import OperationJournal, OperationStatus
from .storage import exclusive_file_lock, read_json, write_json_atomic
from .themes import ActiveThemeSelection, ThemeManager


class ThemeOperationError(RuntimeError):
    """A theme activation or rollback failed or requires recovery."""


class _ThemeIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    operation_id: str
    action: Literal["theme.activate", "theme.rollback"]
    store_id: str
    actor_id: str
    target_theme: str
    before: ActiveThemeSelection


class ThemeActivationCoordinator:
    def __init__(
        self,
        *,
        manager: ThemeManager,
        audit: AuditLog,
        operations: OperationJournal,
        lock_path,
        target_validator: Callable[[str], None] | None = None,
        failure_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.manager = manager
        self.audit = audit
        self.operations = operations
        self.lock_path = Path(lock_path)
        self.intent_path = self.lock_path.with_name(
            f".{self.lock_path.name}.theme-intent.json"
        )
        self.target_validator = target_validator
        self.failure_injector = failure_injector

    def activate(
        self,
        theme_id: str,
        *,
        store_id: str,
        actor_id: str,
    ) -> ActiveThemeSelection:
        return self._change(
            action="theme.activate",
            store_id=store_id,
            actor_id=actor_id,
            target_theme=theme_id,
        )

    def rollback(self, *, store_id: str, actor_id: str) -> ActiveThemeSelection:
        selection = self.manager.state.selection(store_id)
        if selection.previous is None:
            raise ThemeOperationError("no previous theme is available")
        return self._change(
            action="theme.rollback",
            store_id=store_id,
            actor_id=actor_id,
            target_theme=selection.previous,
        )

    def _change(
        self,
        *,
        action: str,
        store_id: str,
        actor_id: str,
        target_theme: str,
    ) -> ActiveThemeSelection:
        with exclusive_file_lock(self.lock_path):
            self._recover_locked()
            before = self.manager.state.selection(store_id)
            target = f"store/{store_id}/theme/{target_theme}"
            identifier = _operation_id(action, target, before)
            operation = self.operations.begin(
                identifier,
                action=action,
                target=target,
            )
            if operation.status == OperationStatus.FAILED:
                operation = self.operations.retry(identifier)
            if operation.status == OperationStatus.SUCCEEDED:
                return self.manager.state.selection(store_id)
            if self.target_validator is not None:
                try:
                    self.target_validator(target_theme)
                except Exception:
                    self.operations.fail(
                        identifier,
                        error_code="theme.target_unavailable",
                    )
                    raise ThemeOperationError("theme target is unavailable") from None
            intent = _ThemeIntent(
                operation_id=identifier,
                action=action,
                store_id=store_id,
                actor_id=actor_id,
                target_theme=target_theme,
                before=before,
            )
            write_json_atomic(self.intent_path, intent.model_dump(mode="json"))
            audit_succeeded = False
            try:
                if action == "theme.activate":
                    self.manager.activate(target_theme, store_id)
                else:
                    rolled_back = self.manager.rollback(store_id)
                    if rolled_back.id != target_theme:
                        raise ThemeOperationError("theme rollback target changed")
                after = self.manager.state.selection(store_id)
                self._inject("after_state")
                self._append_success_audit(intent, after)
                audit_succeeded = True
                self._inject("after_audit")
                self.operations.succeed(identifier)
                self._inject("after_succeed")
                self.intent_path.unlink(missing_ok=True)
                return after
            except Exception as error:
                decision = self._operation_decision(identifier)
                if decision == OperationStatus.SUCCEEDED:
                    # SUCCEEDED is the durable commit boundary. The existing
                    # recovery path verifies the target and removes the intent,
                    # so never restore the old theme after this point.
                    raise ThemeOperationError(
                        "theme operation committed; recovery cleanup is required"
                    ) from None
                if decision is None:
                    # If the journal outcome itself cannot be established, a
                    # rollback could contradict a success that became durable.
                    raise ThemeOperationError(
                        "theme operation outcome is uncertain; recovery is required"
                    ) from None

                self.manager.state.restore(store_id, before)
                if audit_succeeded:
                    try:
                        self.audit.append(
                            actor_id=actor_id,
                            action=f"{action}.compensated",
                            target_type="store.theme",
                            target_id=store_id,
                            outcome=AuditOutcome.FAILURE,
                            metadata={
                                "operation_id": identifier,
                                "restored_theme": before.active,
                            },
                        )
                    except Exception:
                        raise ThemeOperationError(
                            "theme state was restored but compensation audit failed"
                        ) from None
                try:
                    if decision == OperationStatus.STARTED:
                        self.operations.fail(
                            identifier,
                            error_code=f"theme.{type(error).__name__.casefold()}"[:128],
                        )
                except Exception:
                    raise ThemeOperationError(
                        "theme state was restored but operation recovery failed"
                    ) from None
                self.intent_path.unlink(missing_ok=True)
                raise ThemeOperationError("theme operation failed and was rolled back") from None

    def _operation_decision(self, operation_id: str) -> OperationStatus | None:
        """Return a verified journal status, or ``None`` when outcome is uncertain."""

        try:
            state = self.operations.state(operation_id)
        except Exception:
            return None
        return state.status if state is not None else None

    def recover(self) -> str | None:
        """Finish or compensate one durable theme intent after process loss."""

        with exclusive_file_lock(self.lock_path):
            return self._recover_locked()

    def _recover_locked(self) -> str | None:
        if not self.intent_path.is_file():
            return None
        try:
            intent = _ThemeIntent.model_validate(read_json(self.intent_path, {}))
        except Exception:
            raise ThemeOperationError("theme operation intent is invalid") from None
        state = self.operations.state(intent.operation_id)
        if state is None:
            raise ThemeOperationError("theme operation intent has no journal evidence")
        current = self.manager.state.selection(intent.store_id)
        if state.status == OperationStatus.SUCCEEDED:
            if current.active != intent.target_theme:
                raise ThemeOperationError(
                    "completed theme operation conflicts with active state"
                )
            self.intent_path.unlink(missing_ok=True)
            return intent.operation_id
        if state.status == OperationStatus.FAILED:
            self.manager.state.restore(intent.store_id, intent.before)
            self.intent_path.unlink(missing_ok=True)
            return intent.operation_id
        if current.active == intent.target_theme:
            self._append_success_audit(intent, current)
            self.operations.succeed(intent.operation_id)
        else:
            self.manager.state.restore(intent.store_id, intent.before)
            self.operations.fail(
                intent.operation_id,
                error_code="theme.recovered_before_commit",
            )
        self.intent_path.unlink(missing_ok=True)
        return intent.operation_id

    def _append_success_audit(
        self,
        intent: _ThemeIntent,
        after: ActiveThemeSelection,
    ) -> None:
        if any(
            event.action == intent.action
            and event.metadata.get("operation_id") == intent.operation_id
            for event in self.audit.events()
        ):
            return
        self.audit.append(
            actor_id=intent.actor_id,
            action=intent.action,
            target_type="store.theme",
            target_id=intent.store_id,
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "operation_id": intent.operation_id,
                "from_theme": intent.before.active,
                "to_theme": after.active,
            },
        )

    def _inject(self, point: str) -> None:
        if self.failure_injector is not None:
            self.failure_injector(point)


def _operation_id(
    action: str,
    target: str,
    previous: ActiveThemeSelection,
) -> str:
    generation = previous.model_dump_json()
    digest = hashlib.sha256(
        f"{action}\0{target}\0{generation}".encode("utf-8")
    ).hexdigest()[:32]
    return f"theme-{digest}"