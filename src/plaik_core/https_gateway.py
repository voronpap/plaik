"""Atomic HTTPS gateway publication. Providers stay outside Core domain logic.

This layer runs ``plan → validate → apply → verify → inspect`` against the
current ``RemoteControlRecord``. It never binds WAN listeners itself, never
writes nginx configuration, never reopens the installer, and never moves
installation off ``COMPLETED``. After a CONTROL_CENTER inspection of
``PUBLICATION_PENDING``, it persists observed ``ENABLED``.

Provider side effects are serialized by a dedicated cross-process lock, separate
from the RemoteControlStore lock. Core persists ``ERROR`` (derived CLOSED) only
after inspection proves the gateway is actually CLOSED.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .installer import InstallState
from .remote_control import (
    CONTROL_LOOPBACK,
    WEB_LOOPBACK,
    GatewayInspection,
    GatewayPlan,
    GatewayProviderName,
    HttpsGatewayProvider,
    InvalidRemoteControlTransition,
    RemoteControlError,
    RemoteControlRecord,
    RemoteControlStatus,
    RemoteControlStore,
    WanSurface,
    is_forbidden_wan_bind,
    records_match,
)
from .storage import exclusive_file_lock


class GatewayTransactionError(RemoteControlError):
    """Gateway publication failed without changing installer state."""


class HttpsGatewayTransactionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record: RemoteControlRecord
    applied: bool = False
    rolled_back: bool = False
    contained: bool = False
    failed: bool = False
    error_code: str | None = None
    steps: tuple[str, ...] = ()


def gateway_transaction_lock_path(store_path: Path) -> Path:
    """Lock target for provider publication. Distinct from the store lock file."""

    return store_path.with_name("https-gateway.transaction")


def _require_completed(install_state: InstallState) -> None:
    if install_state is not InstallState.COMPLETED:
        raise InvalidRemoteControlTransition(
            "gateway publication starts only after installation is COMPLETED"
        )


def _provider_identity(provider: HttpsGatewayProvider) -> GatewayProviderName:
    try:
        return GatewayProviderName(provider.name)
    except (TypeError, ValueError) as error:
        raise GatewayTransactionError(
            "gateway provider identity is not a known provider"
        ) from error


def _assert_provider_identity(
    provider: HttpsGatewayProvider, record: RemoteControlRecord
) -> GatewayProviderName:
    if record.intent is None:
        raise GatewayTransactionError("gateway publication requires a remote control intent")
    identity = _provider_identity(provider)
    if identity is not record.intent.gateway_provider:
        raise GatewayTransactionError(
            "gateway provider identity does not match the stored intent"
        )
    return identity


def _assert_loopback_plan(plan: GatewayPlan) -> None:
    for host in (plan.web_bind_host, plan.control_bind_host):
        if is_forbidden_wan_bind(host):
            raise GatewayTransactionError(
                "gateway plan cannot bind PLAIK to a WAN address"
            )
    if (plan.web_bind_host, plan.web_bind_port) != WEB_LOOPBACK:
        raise GatewayTransactionError("gateway plan must target 127.0.0.1:8080")
    if (plan.control_bind_host, plan.control_bind_port) != CONTROL_LOOPBACK:
        raise GatewayTransactionError("gateway plan must target 127.0.0.1:8081")


def _assert_plan_matches_record(plan: GatewayPlan, record: RemoteControlRecord) -> None:
    expected = GatewayPlan.from_record(record)
    if plan.model_dump(mode="json") != expected.model_dump(mode="json"):
        raise GatewayTransactionError(
            "provider plan is not bound to the exact current remote control record"
        )
    if not records_match(plan.record, record):
        raise GatewayTransactionError(
            "provider plan cannot substitute a different remote control record"
        )
    _assert_loopback_plan(plan)


def _assert_record_current(
    store: RemoteControlStore, expected: RemoteControlRecord
) -> None:
    current = store.read()
    if not records_match(current, expected):
        raise GatewayTransactionError(
            "remote control record drifted during gateway publication"
        )


def _assert_inspection_matches_plan(
    inspection: GatewayInspection,
    plan: GatewayPlan,
    expected_provider: GatewayProviderName,
) -> None:
    if inspection.control_port_public:
        raise GatewayTransactionError("Control Center port 8081 must not be public")
    if inspection.installer_open:
        raise GatewayTransactionError("gateway publication cannot reopen the installer")
    if inspection.provider is not expected_provider:
        raise GatewayTransactionError(
            "gateway inspection provider does not match the stored intent"
        )
    if inspection.wan_surface is not plan.wan_surface:
        raise GatewayTransactionError(
            "gateway inspection wan_surface does not match the published plan"
        )


def _assert_closed_inspection(
    inspection: GatewayInspection, expected_provider: GatewayProviderName
) -> None:
    if inspection.control_port_public:
        raise GatewayTransactionError("Control Center port 8081 must not be public")
    if inspection.installer_open:
        raise GatewayTransactionError("gateway publication cannot reopen the installer")
    if inspection.provider is not expected_provider:
        raise GatewayTransactionError(
            "gateway inspection provider does not match the stored intent"
        )
    if inspection.wan_surface is not WanSurface.CLOSED:
        raise GatewayTransactionError("gateway containment did not prove WAN CLOSED")


def _closed_containment_plan(record: RemoteControlRecord) -> GatewayPlan:
    if record.intent is None:
        raise GatewayTransactionError("containment requires a remote control intent")
    closed = RemoteControlRecord(
        intent=record.intent,
        status=RemoteControlStatus.DISABLED,
        enrolled_admin_passkey_rp_id=record.enrolled_admin_passkey_rp_id,
        error_code=None,
    )
    return GatewayPlan.from_record(closed)


class HttpsGatewayTransaction:
    """Fail-closed coordinator around :class:`HttpsGatewayProvider`."""

    def __init__(
        self,
        provider: HttpsGatewayProvider,
        store: RemoteControlStore,
        *,
        lock_path: Path | None = None,
    ) -> None:
        self._provider = provider
        self._store = store
        self.lock_path = lock_path or gateway_transaction_lock_path(store.path)

    def run(self, *, install_state: InstallState) -> HttpsGatewayTransactionResult:
        _require_completed(install_state)
        with exclusive_file_lock(self.lock_path):
            return self._run_locked(install_state=install_state)

    def _run_locked(self, *, install_state: InstallState) -> HttpsGatewayTransactionResult:
        record = self._store.read()
        if record.intent is None:
            return HttpsGatewayTransactionResult(
                record=record,
                steps=("skip_unconfigured",),
            )
        steps: list[str] = []
        applied = False
        apply_attempted = False
        error_code: str | None = None
        expected_provider: GatewayProviderName | None = None
        try:
            try:
                expected_provider = _assert_provider_identity(self._provider, record)
            except Exception as error:
                error_code = "gateway_provider_mismatch"
                raise GatewayTransactionError(
                    "gateway provider identity mismatch"
                ) from error
            try:
                plan = self._provider.plan(record)
            except Exception as error:
                error_code = "gateway_plan_failed"
                raise GatewayTransactionError("gateway plan failed") from error
            steps.append("plan")
            try:
                _assert_plan_matches_record(plan, record)
            except GatewayTransactionError:
                error_code = "gateway_plan_invalid"
                raise
            try:
                self._provider.validate(plan)
            except Exception as error:
                error_code = "gateway_validate_failed"
                raise GatewayTransactionError("gateway validate failed") from error
            steps.append("validate")
            try:
                _assert_record_current(self._store, record)
            except GatewayTransactionError:
                error_code = "gateway_record_drifted"
                raise
            apply_attempted = True
            try:
                self._provider.apply(plan)
            except Exception as error:
                error_code = "gateway_apply_failed"
                raise GatewayTransactionError("gateway apply failed") from error
            applied = True
            steps.append("apply")
            try:
                self._provider.verify()
            except Exception as error:
                error_code = "gateway_verify_failed"
                raise GatewayTransactionError("gateway verify failed") from error
            steps.append("verify")
            try:
                _assert_record_current(self._store, record)
                inspection = self._provider.inspect()
                steps.append("inspect")
                _assert_inspection_matches_plan(
                    inspection, plan, expected_provider
                )
                _assert_record_current(self._store, record)
            except GatewayTransactionError as error:
                if "drifted" in str(error):
                    error_code = "gateway_record_drifted"
                else:
                    error_code = "gateway_inspect_failed"
                raise
            except Exception as error:
                error_code = "gateway_inspect_failed"
                raise GatewayTransactionError("gateway inspect failed") from error
            persisted = record
            if (
                record.status is RemoteControlStatus.PUBLICATION_PENDING
                and plan.wan_surface is WanSurface.CONTROL_CENTER
            ):
                try:
                    persisted = self._store.observe_control_center(
                        record,
                        inspection=inspection,
                        install_state=install_state,
                    )
                    steps.append("observe")
                except InvalidRemoteControlTransition as error:
                    error_code = "gateway_record_drifted"
                    raise GatewayTransactionError(
                        "remote control record drifted during gateway observation"
                    ) from error
            return HttpsGatewayTransactionResult(
                record=persisted,
                applied=True,
                steps=tuple(steps),
            )
        except Exception:
            return self._fail_closed(
                record,
                install_state=install_state,
                steps=steps,
                applied=applied,
                apply_attempted=apply_attempted,
                error_code=error_code or "gateway_inspect_failed",
                expected_provider=expected_provider,
            )

    def _fail_closed(
        self,
        snapshot: RemoteControlRecord,
        *,
        install_state: InstallState,
        steps: list[str],
        applied: bool,
        apply_attempted: bool,
        error_code: str,
        expected_provider: GatewayProviderName | None,
    ) -> HttpsGatewayTransactionResult:
        contained = False
        rolled_back = False
        if expected_provider is not None and snapshot.intent is not None:
            rolled_back, contained = self._contain_closed(
                snapshot,
                steps,
                expected_provider,
                rollback=apply_attempted,
            )
            if not contained:
                error_code = "gateway_containment_failed"
        if error_code == "gateway_record_drifted":
            persisted = self._store.read()
        elif contained:
            persisted = self._store.fail_if_current(
                snapshot,
                error_code,
                install_state=install_state,
            )
        else:
            persisted = self._store.read()
        return HttpsGatewayTransactionResult(
            record=persisted,
            applied=applied,
            rolled_back=rolled_back,
            contained=contained,
            failed=True,
            error_code=error_code,
            steps=tuple(steps),
        )

    def _contain_closed(
        self,
        record: RemoteControlRecord,
        steps: list[str],
        expected_provider: GatewayProviderName,
        *,
        rollback: bool,
    ) -> tuple[bool, bool]:
        rolled_back = False
        try:
            if rollback:
                try:
                    self._provider.rollback()
                    rolled_back = True
                    steps.append("rollback")
                except Exception:
                    steps.append("rollback_failed")
            self._provider.apply(_closed_containment_plan(record))
            steps.append("contain")
            inspection = self._provider.inspect()
            steps.append("contain_inspect")
            _assert_closed_inspection(inspection, expected_provider)
            return rolled_back, True
        except Exception:
            steps.append("contain_failed")
            return rolled_back, False
