"""Admin platform-console projection for installed packages."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .jobs import JobRecord, JobStatus
from .packages import PackageRecord, PackageStatus
from .operation_journal import OperationEvent


def package_console_entry(
    record: PackageRecord,
    *,
    jobs: Mapping[str, JobRecord] | None = None,
    health_issues: tuple[Any, ...] = (),
    last_operation: Mapping[str, Any] | None = None,
    connection_count: int = 0,
    dead_letters: int = 0,
    upgrade_available: bool = False,
) -> dict[str, Any]:
    manifest = record.manifest
    prefix = f"{manifest.id}."
    owned_jobs = [
        job
        for job in (jobs or {}).values()
        if job.type.startswith(prefix)
    ]
    pending = [
        job.id
        for job in owned_jobs
        if job.status in {JobStatus.QUEUED, JobStatus.RUNNING}
    ]
    failed = [job.id for job in owned_jobs if job.status is JobStatus.FAILED]
    issues = [
        issue.model_dump(mode="json")
        for issue in health_issues
        if getattr(issue, "owner", None) == manifest.id
    ]
    return {
        "id": manifest.id,
        "name": manifest.name,
        "type": manifest.type.value,
        "version": manifest.version,
        "status": (
            record.status.value
            if isinstance(record.status, PackageStatus)
            else str(record.status)
        ),
        "capabilities": {
            "provided": [item.model_dump(mode="json") for item in manifest.provides],
            "required": [item.model_dump(mode="json") for item in manifest.requires],
        },
        "health_issues": issues,
        "pending_jobs": pending,
        "failed_jobs": failed,
        "event_dead_letters": dead_letters,
        "migration_state": {
            "declared": [item.version for item in manifest.migrations],
            "has_sql": bool(manifest.migrations),
        },
        "settings": [item.key for item in manifest.settings],
        "connections": connection_count,
        "last_lifecycle_operation": last_operation,
        "upgrade_available": upgrade_available,
    }


def last_package_operation(
    events: tuple[OperationEvent, ...],
    package_id: str,
) -> dict[str, Any] | None:
    prefix = f"package/{package_id}"
    for event in reversed(events):
        if event.target == prefix or event.target.startswith(prefix + "/"):
            return {
                "operation_id": event.operation_id,
                "action": event.action,
                "status": event.status.value,
            }
    return None
