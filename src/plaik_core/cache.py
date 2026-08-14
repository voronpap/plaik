"""Domain-neutral, namespaced runtime cache primitives."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


_NAMESPACE = re.compile(r"^[a-z][a-z0-9.-]{1,127}$")
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_MISSING = object()


@dataclass(frozen=True, slots=True)
class CacheStats:
    hits: int
    misses: int
    writes: int
    evictions: int
    entries: int


@dataclass(slots=True)
class _CacheEntry:
    value: Any
    expires_at: float


@dataclass(frozen=True, slots=True)
class _InflightProducer:
    event: threading.Event
    generation: int


class NamespacedTTLCache:
    """Process-local TTL cache with deterministic invalidation and coalescing.

    Cache values are never a source of truth. Package namespaces keep unrelated
    extensions from invalidating or enumerating one another's entries. Resident
    entries are bounded; when capacity is full, the oldest resident entry is
    evicted after expired entries have first been purged.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        coalescing_wait_timeout: float = 30.0,
        maximum_entries: int = 4096,
    ) -> None:
        if not 0 < coalescing_wait_timeout <= 300:
            raise ValueError(
                "cache coalescing wait timeout must be between 0 and 300 seconds"
            )
        if not isinstance(maximum_entries, int) or isinstance(maximum_entries, bool):
            raise TypeError("cache maximum entries must be an integer")
        if not 1 <= maximum_entries <= 1_000_000:
            raise ValueError("cache maximum entries must be between 1 and 1000000")
        self._clock = clock
        self._coalescing_wait_timeout = coalescing_wait_timeout
        self._maximum_entries = maximum_entries
        self._lock = threading.RLock()
        self._entries: dict[tuple[str, str], _CacheEntry] = {}
        self._inflight: dict[tuple[str, str], _InflightProducer] = {}
        self._generations: dict[tuple[str, str], int] = {}
        self._hits = 0
        self._misses = 0
        self._writes = 0
        self._evictions = 0

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        cache_key = self._validated_key(namespace, key)
        with self._lock:
            value = self._get_locked(cache_key)
            if value is _MISSING:
                self._misses += 1
                return default
            self._hits += 1
            return value

    def set(self, namespace: str, key: str, value: Any, *, ttl: float) -> None:
        cache_key = self._validated_key(namespace, key)
        if not 0 < ttl <= 31_536_000:
            raise ValueError("cache ttl must be between 0 and 31536000 seconds")
        with self._lock:
            if cache_key in self._inflight:
                self._bump_generation_locked(cache_key)
            self._store_locked(cache_key, value, ttl=ttl)

    def get_or_set(
        self,
        namespace: str,
        key: str,
        producer: Callable[[], Any],
        *,
        ttl: float,
    ) -> Any:
        cache_key = self._validated_key(namespace, key)
        if not callable(producer):
            raise TypeError("cache producer must be callable")
        if not 0 < ttl <= 31_536_000:
            raise ValueError("cache ttl must be between 0 and 31536000 seconds")

        while True:
            with self._lock:
                cached = self._get_locked(cache_key)
                if cached is not _MISSING:
                    self._hits += 1
                    return cached
                inflight = self._inflight.get(cache_key)
                if inflight is None:
                    inflight = _InflightProducer(
                        event=threading.Event(),
                        generation=self._generations.get(cache_key, 0),
                    )
                    self._inflight[cache_key] = inflight
                    self._misses += 1
                    owner = True
                else:
                    owner = False
            if owner:
                break
            if not inflight.event.wait(timeout=self._coalescing_wait_timeout):
                raise TimeoutError("cache producer wait timed out")

        try:
            value = producer()
            with self._lock:
                if self._generations.get(cache_key, 0) == inflight.generation:
                    self._store_locked(cache_key, value, ttl=ttl)
            return value
        finally:
            with self._lock:
                completed = self._inflight.pop(cache_key, None)
                if completed is not None:
                    completed.event.set()
                if cache_key not in self._entries:
                    self._generations.pop(cache_key, None)

    def delete(self, namespace: str, key: str) -> bool:
        cache_key = self._validated_key(namespace, key)
        with self._lock:
            removed = self._entries.pop(cache_key, None) is not None
            if cache_key in self._inflight:
                self._bump_generation_locked(cache_key)
            else:
                self._generations.pop(cache_key, None)
            if removed:
                self._evictions += 1
            return removed

    def invalidate_namespace(self, namespace: str, *, prefix: str | None = None) -> int:
        namespace = self._validate_namespace(namespace)
        if prefix is not None and (not prefix or len(prefix) > 256):
            raise ValueError("cache prefix must contain 1..256 characters")
        with self._lock:
            entry_targets = {
                cache_key
                for cache_key in self._entries
                if cache_key[0] == namespace
                and (prefix is None or cache_key[1].startswith(prefix))
            }
            inflight_targets = {
                cache_key
                for cache_key in self._inflight
                if cache_key[0] == namespace
                and (prefix is None or cache_key[1].startswith(prefix))
            }
            for cache_key in entry_targets:
                del self._entries[cache_key]
            for cache_key in entry_targets | inflight_targets:
                if cache_key in self._inflight:
                    self._bump_generation_locked(cache_key)
                else:
                    self._generations.pop(cache_key, None)
            self._evictions += len(entry_targets)
            return len(entry_targets)

    def stats(self) -> CacheStats:
        with self._lock:
            self._purge_expired_locked()
            return CacheStats(
                hits=self._hits,
                misses=self._misses,
                writes=self._writes,
                evictions=self._evictions,
                entries=len(self._entries),
            )

    def _get_locked(self, cache_key: tuple[str, str]) -> Any:
        entry = self._entries.get(cache_key)
        if entry is None:
            return _MISSING
        if self._clock() >= entry.expires_at:
            del self._entries[cache_key]
            if cache_key not in self._inflight:
                self._generations.pop(cache_key, None)
            self._evictions += 1
            return _MISSING
        return entry.value

    def _store_locked(self, cache_key: tuple[str, str], value: Any, *, ttl: float) -> None:
        self._purge_expired_locked()
        if cache_key not in self._entries and len(self._entries) >= self._maximum_entries:
            oldest = next(iter(self._entries))
            del self._entries[oldest]
            if oldest in self._inflight:
                self._bump_generation_locked(oldest)
            else:
                self._generations.pop(oldest, None)
            self._evictions += 1
        self._entries[cache_key] = _CacheEntry(
            value=value,
            expires_at=self._clock() + ttl,
        )
        self._writes += 1

    def _purge_expired_locked(self) -> None:
        now = self._clock()
        expired = [
            cache_key
            for cache_key, entry in self._entries.items()
            if now >= entry.expires_at
        ]
        for cache_key in expired:
            del self._entries[cache_key]
            if cache_key not in self._inflight:
                self._generations.pop(cache_key, None)
        self._evictions += len(expired)

    def _bump_generation_locked(self, cache_key: tuple[str, str]) -> None:
        self._generations[cache_key] = self._generations.get(cache_key, 0) + 1

    @classmethod
    def _validated_key(cls, namespace: str, key: str) -> tuple[str, str]:
        return cls._validate_namespace(namespace), cls._validate_key(key)

    @staticmethod
    def _validate_namespace(namespace: str) -> str:
        if not isinstance(namespace, str) or not _NAMESPACE.fullmatch(namespace):
            raise ValueError("invalid cache namespace")
        return namespace

    @staticmethod
    def _validate_key(key: str) -> str:
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise ValueError("invalid cache key")
        return key
