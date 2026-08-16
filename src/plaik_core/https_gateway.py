"""Atomic HTTPS gateway publication. Providers stay outside Core domain logic.

This layer runs ``plan → validate → apply → verify → inspect`` against the
current ``RemoteControlRecord``. It never binds WAN listeners itself, never
writes nginx configuration, never reopens the installer, and never moves
installation off ``COMPLETED``. Failure rolls the provider back and marks
Remote Control ``ERROR`` with WAN closed.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .installer import InstallState
from .remote_control import (
    CONTROL_LOOPBACK,
    WEB_LOOPBACK,
    GatewayInspection,
    GatewayPlan,
    HttpsGatewayProvider,
    InvalidRemoteControlTransition,
    RemoteControlError,
    RemoteControlRecord,
    RemoteControlStatus,
    RemoteControlStore,
    WanSurface,
    is_forbidden_wan_bind,
)


class GatewayTransactionError(RemoteControlError):
    """Gateway publication failed without changing installer state."""


class HttpsGatewayTransactionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record: RemoteControlRecord
    applied: bool = False
    rolled_back: bool = False
    failed: bool = False
    error_code: str | None = None
    steps: tuple[str, ...] = ()


def _require_completed(install_state: InstallState) -> None:
    if install_state is not InstallState.COMPLETED:
        raise InvalidRemoteControlTransition(
            "gateway publication starts only after installation is COMPLETED"
        )


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
    if plan.wan_surface is not expected.wan_surface:
        raise GatewayTransactionError(
            "provider plan wan_surface does not match the validated record"
        )
    if plan.record.status is not record.status:
        raise GatewayTransactionError(
            "provider plan cannot substitute a different remote control status"
        )
    if plan.record.wan_surface is not record.wan_surface:
        raise GatewayTransactionError(
            "provider plan cannot substitute a different WAN surface"
        )
    _assert_loopback_plan(plan)


def _assert_inspection_matches_record(
    inspection: GatewayInspection, record: RemoteControlRecord
) -> None:
    if inspection.control_port_public:
        raise GatewayTransactionError("Control Center port 8081 must not be public")
    if inspection.installer_open:
        raise GatewayTransactionError("gateway publication cannot reopen the installer")
    if inspection.wan_surface is not record.wan_surface:
        raise GatewayTransactionError(
            "gateway inspection wan_surface does not match the validated record"
        )


class HttpsGatewayTransaction:
    """Fail-closed coordinator around :class:`HttpsGatewayProvider`."""

    def __init__(
        self,
        provider: HttpsGatewayProvider,
        store: RemoteControlStore,
    ) -> None:
        self._provider = provider
        self._store = store

    def run(self, *, install_state: InstallState) -> HttpsGatewayTransactionResult:
        _require_completed(install_state)
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
        try:
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
                inspection = self._provider.inspect()
                steps.append("inspect")
                _assert_inspection_matches_record(inspection, record)
            except Exception as error:
                error_code = "gateway_inspect_failed"
                raise GatewayTransactionError("gateway inspect failed") from error
            return HttpsGatewayTransactionResult(
                record=self._store.read(),
                applied=True,
                steps=tuple(steps),
            )
        except Exception:
            rolled_back = False
            if apply_attempted:
                try:
                    self._provider.rollback()
                    rolled_back = True
                    steps.append("rollback")
                except Exception:
                    steps.append("rollback_failed")
                    if error_code is None:
                        error_code = "gateway_rollback_failed"
            failed = self._fail_closed(
                error_code or "gateway_inspect_failed",
                install_state=install_state,
            )
            return HttpsGatewayTransactionResult(
                record=failed,
                applied=applied,
                rolled_back=rolled_back,
                failed=True,
                error_code=error_code or "gateway_inspect_failed",
                steps=tuple(steps),
            )

    def _fail_closed(
        self,
        error_code: str,
        *,
        install_state: InstallState,
    ) -> RemoteControlRecord:
        current = self._store.read()
        if current.status is RemoteControlStatus.DISABLED:
            return current
        return self._store.fail(error_code, install_state=install_state)
