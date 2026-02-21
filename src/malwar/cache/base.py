# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Abstract cache backend interface with TTL support."""

from __future__ import annotations

import abc


class CacheBackend(abc.ABC):
    """Abstract base class for cache backends.

    All backends must support async get/set/delete/exists operations
    with optional TTL (time-to-live) in seconds.
    """

    @abc.abstractmethod
    async def get(self, key: str) -> str | None:
        """Retrieve a cached value by key.

        Returns:
            The cached string value, or ``None`` if the key does not
            exist or has expired.
        """

    @abc.abstractmethod
    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        """Store a value in the cache.

        Args:
            key: Cache key.
            value: String value to store.
            ttl: Time-to-live in seconds.  ``None`` means no expiry.
        """

    @abc.abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a key from the cache.

        Returns:
            ``True`` if the key existed and was deleted, ``False`` otherwise.
        """

    @abc.abstractmethod
    async def exists(self, key: str) -> bool:
        """Check whether a key exists (and has not expired).

        Returns:
            ``True`` if the key exists and is valid.
        """

    @abc.abstractmethod
    async def clear(self) -> int:
        """Flush all keys from this cache.

        Returns:
            The number of keys removed.
        """

    @abc.abstractmethod
    async def size(self) -> int:
        """Return the number of live (non-expired) entries in the cache."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Release any resources held by the backend."""
