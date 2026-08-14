"""Cross-resource recovery for reference installer operation journal attempts."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .audit import AuditLog, AuditOutcome
from .identity import SUPER_ADMIN_ROLE, IdentityStore
from .installer import INSTALL_SEQUENCE, InstallState, InstallStateStore
from .installer_config import InstallerConfigurationStore
from .operation_journal import OperationJournal, OperationState, OperationStatus


class IdentityReader(Protocol):
    def users(self) -> dict[str, Any]: ...

    def has_active_super_admin(self) -> bool: ...


@dataclass(frozen=True)
class InstallerRecoveryReport:
    recovered: tuple[str, ...]
    still_pending: tuple[str, ...]
    failed: tuple[str, ...] = ()


class InstallerRecoveryCoordinator:
    """Complete installer journal attempts when durable side effects already committed."""

    def __init__(
        self,
        *,
        install_store: InstallStateStore,
        configuration_store: InstallerConfigurationStore,
        identity_store: IdentityStore | IdentityReader,
        operations: OperationJournal,
        audit: AuditLog,
        append_audit_once: Callable[..., None],
        database_ready_verifier: Callable[[], bool],
        theme_ready_verifier: Callable[[], bool],
    ) -> None:
        self._install_store = install_store
        self._configuration_store = configuration_store
        self._identity_store = identity_store
        self._operations = operations
        self._audit = audit
        self._append_audit_once = append_audit_once
        self._database_ready_verifier = database_ready_verifier
        self._theme_ready_verifier = theme_ready_verifier

    def recover_pending(self) -> InstallerRecoveryReport:
        recovered: list[str] = []
        still_pending: list[str] = []
        failed: list[str] = []
        for operation in self._operations.pending():
            if self._try_recover(operation):
                self._operations.succeed(operation.operation_id)
                recovered.append(operation.operation_id)
            elif self._fail_if_superseded(operation):
                failed.append(operation.operation_id)
            else:
                still_pending.append(operation.operation_id)
        return InstallerRecoveryReport(
            recovered=tuple(recovered),
            still_pending=tuple(still_pending),
            failed=tuple(failed),
        )

    def _try_recover(self, operation: OperationState) -> bool:
        if operation.status != OperationStatus.STARTED:
            return False
        if operation.action == "installer.configure":
            return self._recover_configure(operation)
        if operation.action == "installer.admin.bootstrap":
            return self._recover_admin_bootstrap(operation)
        if operation.action == "installer.transition":
            return self._recover_transition(operation)
        return False

    def _recover_configure(self, operation: OperationState) -> bool:
        configuration = self._configuration_store.read()
        if configuration is None:
            return False
        target = f"installation/{configuration.installation_id}"
        if operation.target != target:
            return False
        expected_identifier = _installer_operation_id(
            "installer.configure",
            target,
            configuration.model_dump_json(),
        )
        if operation.operation_id != expected_identifier:
            return False
        current = self._install_store.read()
        if INSTALL_SEQUENCE.index(current) < INSTALL_SEQUENCE.index(
            InstallState.REQUIREMENTS_CHECKED
        ):
            return False
        self._append_audit_once(
            self._audit,
            operation_identifier=operation.operation_id,
            action="installer.configuration.write",
            target_type="installer.configuration",
            metadata={
                "profile": configuration.profile.value,
                "mode": configuration.mode.value,
            },
        )
        return True

    def _recover_admin_bootstrap(self, operation: OperationState) -> bool:
        target = "identity/super-admin"
        if operation.target != target:
            return False
        current = self._install_store.read()
        if INSTALL_SEQUENCE.index(current) < INSTALL_SEQUENCE.index(
            InstallState.DATABASE_READY
        ):
            return False
        configuration = self._configuration_store.read()
        if configuration is None:
            return False
        user = next(
            (
                item
                for item in self._identity_store.users().values()
                if item.active
                and SUPER_ADMIN_ROLE in item.roles
                and operation.operation_id
                == _installer_operation_id(
                    "installer.admin.bootstrap",
                    target,
                    f"{configuration.installation_id}\0{item.email.strip().casefold()}",
                )
            ),
            None,
        )
        if user is None:
            return False
        self._append_audit_once(
            self._audit,
            operation_identifier=operation.operation_id,
            action="identity.super-admin.bootstrap",
            target_type="identity.user",
            target_id=user.id,
            metadata={"roles": sorted(user.roles)},
        )
        return True

    def _fail_if_superseded(self, operation: OperationState) -> bool:
        if operation.action == "installer.configure":
            current = self._install_store.read()
            if INSTALL_SEQUENCE.index(current) < INSTALL_SEQUENCE.index(
                InstallState.DATABASE_READY
            ):
                return False
            configuration = self._configuration_store.read()
            if configuration is None:
                return False
            target = f"installation/{configuration.installation_id}"
            current_identifier = _installer_operation_id(
                "installer.configure",
                target,
                configuration.model_dump_json(),
            )
            if operation.operation_id == current_identifier:
                return False
            self._operations.fail(
                operation.operation_id,
                error_code="installer.superseded",
            )
            return True

        if operation.action == "installer.admin.bootstrap":
            current = self._install_store.read()
            if INSTALL_SEQUENCE.index(current) < INSTALL_SEQUENCE.index(
                InstallState.DATABASE_READY
            ):
                return False
            configuration = self._configuration_store.read()
            if configuration is None:
                return False
            active_super_admins = [
                item
                for item in self._identity_store.users().values()
                if item.active and SUPER_ADMIN_ROLE in item.roles
            ]
            if not active_super_admins:
                return False
            target = "identity/super-admin"
            if any(
                operation.operation_id
                == _installer_operation_id(
                    "installer.admin.bootstrap",
                    target,
                    f"{configuration.installation_id}\0{item.email.strip().casefold()}",
                )
                for item in active_super_admins
            ):
                return False
            self._operations.fail(
                operation.operation_id,
                error_code="installer.superseded",
            )
            return True

        return False

    def _recover_transition(self, operation: OperationState) -> bool:
        prefix = "state/"
        if not operation.target.startswith(prefix):
            return False
        target_state = InstallState(operation.target.removeprefix(prefix))
        current = self._install_store.read()
        if INSTALL_SEQUENCE.index(current) < INSTALL_SEQUENCE.index(target_state):
            return False
        if target_state == InstallState.DATABASE_READY and not self._database_ready_verifier():
            return False
        if target_state == InstallState.ADMIN_READY and not self._identity_store.has_active_super_admin():
            return False
        if target_state == InstallState.THEME_READY and not self._theme_ready_verifier():
            return False
        if target_state == InstallState.COMPLETED:
            configuration = self._configuration_store.read()
            if configuration is None or not configuration.sealed:
                return False
        self._append_audit_once(
            self._audit,
            operation_identifier=operation.operation_id,
            action="installer.transition",
            target_type="installer.state",
            target_id=target_state.value,
        )
        return True


def _installer_operation_id(action: str, target: str, payload: str = "") -> str:
    digest = hashlib.sha256(
        f"{action}\0{target}\0{payload}".encode("utf-8")
    ).hexdigest()[:24]
    return f"installer-{digest}"
