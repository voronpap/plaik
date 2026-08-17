"""Bounded in-process HealthIssue list beside DiagnosticRegistry."""

from __future__ import annotations

import threading

from plaik_contracts import HealthIssue


MAX_HEALTH_ISSUES = 256


class HealthIssueRegistry:
    """Package-owned diagnostic issues. Not process /health or doctor."""

    def __init__(self, *, limit: int = MAX_HEALTH_ISSUES) -> None:
        if not 1 <= limit <= 10_000:
            raise ValueError("health issue limit must be between 1 and 10000")
        self._limit = limit
        self._issues: list[HealthIssue] = []
        self._lock = threading.RLock()

    def report(self, issue: HealthIssue) -> None:
        if not isinstance(issue, HealthIssue):
            raise TypeError("health issue must be a HealthIssue")
        with self._lock:
            self._issues.append(issue)
            overflow = len(self._issues) - self._limit
            if overflow > 0:
                del self._issues[:overflow]

    def issues(self, *, owner: str | None = None) -> tuple[HealthIssue, ...]:
        with self._lock:
            if owner is None:
                return tuple(self._issues)
            return tuple(item for item in self._issues if item.owner == owner)

    def clear(self, *, owner: str | None = None) -> int:
        with self._lock:
            if owner is None:
                removed = len(self._issues)
                self._issues.clear()
                return removed
            kept = [item for item in self._issues if item.owner != owner]
            removed = len(self._issues) - len(kept)
            self._issues = kept
            return removed
