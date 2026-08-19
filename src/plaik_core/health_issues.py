"""Bounded in-process HealthIssue list beside DiagnosticRegistry."""

from __future__ import annotations

import threading

from plaik_contracts import HealthIssue


MAX_HEALTH_ISSUES = 256


class HealthIssueRegistry:
    """Package-owned diagnostic issues. Not process /health or doctor.

    The registry keeps a global bound. Overflow evicts the oldest issue of the
    owner that currently holds the most entries, so a noisy package cannot drop
    a quieter owner's last remaining issue.
    """

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
            while len(self._issues) > self._limit:
                self._evict_one_locked()

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

    def _evict_one_locked(self) -> None:
        counts: dict[str, int] = {}
        for item in self._issues:
            counts[item.owner] = counts.get(item.owner, 0) + 1
        noisiest = max(counts.values())
        for index, item in enumerate(self._issues):
            if counts[item.owner] == noisiest:
                del self._issues[index]
                return
