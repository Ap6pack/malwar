# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""In-memory LRU cache backend with TTL expiry.

This is the default backend and requires no external services.  It uses
a plain ``dict`` (insertion-ordered in Python 3.7+) with per-entry
expiry timestamps to approximate LRU behaviour.
"""

from __future__ import annotations

import time
from collections import OrderedDict

from malwar.cache.base import CacheBackend

# Default maximum number of entries before eviction kicks in.
_DEFAULT_MAX_SIZE = 4096


class _Entry:
    """A cache entry with an optional expiry timestamp."""

    __slots__ = ("expires_at", "value")

    def __init__(self, value: str, expires_at: float | None) -> None:
        self.value = value
        self.expires_at = expires_at

    def is_expired(self) -> bool:
        return self.expires_at is not None and time.monotonic() > self.expires_at


class MemoryCacheBackend(CacheBackend):
    """In-memory LRU cache with TTL support.

    Args:
        max_size: Maximum number of entries.  When exceeded the oldest
            entry is evicted.
    """

    def __init__(self, max_size: int = _DEFAULT_MAX_SIZE) -> None:
        self._store: OrderedDict[str, _Entry] = OrderedDict()
        self._max_size = max_size

    # ------------------------------------------------------------------
    # CacheBackend interface
    # ------------------------------------------------------------------

    async def get(self, key: str) -> str | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        if entry.is_expired():
            del self._store[key]
            return None
        # Move to end (most recently used)
        self._store.move_to_end(key)
        return entry.value

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        expires_at = (time.monotonic() + ttl) if ttl is not None else None
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = _Entry(value=value, expires_at=expires_at)
        # Evict oldest if over capacity
        while len(self._store) > self._max_size:
            self._store.popitem(last=False)

    async def delete(self, key: str) -> bool:
        try:
            del self._store[key]
        except KeyError:
            return False
        return True

    async def exists(self, key: str) -> bool:
        entry = self._store.get(key)
        if entry is None:
            return False
        if entry.is_expired():
            del self._store[key]
            return False
        return True

    async def clear(self) -> int:
        count = len(self._store)
        self._store.clear()
        return count

    async def size(self) -> int:
        # Prune expired entries first
        self._prune_expired()
        return len(self._store)

    async def close(self) -> None:
        self._store.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune_expired(self) -> None:
        """Remove all expired entries."""
        expired_keys = [k for k, v in self._store.items() if v.is_expired()]
        for k in expired_keys:
            del self._store[k]
