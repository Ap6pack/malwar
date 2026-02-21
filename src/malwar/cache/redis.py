# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Redis cache backend using the ``redis`` async client.

This backend is **optional** -- if the ``redis`` package is not installed
the module can still be imported but :class:`RedisCacheBackend` will raise
a clear error at instantiation time.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from malwar.cache.base import CacheBackend

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger("malwar.cache.redis")

_KEY_PREFIX = "malwar:cache:"

try:
    import redis.asyncio as aioredis

    _REDIS_AVAILABLE = True
except ImportError:  # pragma: no cover
    aioredis = None  # type: ignore[assignment]
    _REDIS_AVAILABLE = False


def redis_available() -> bool:
    """Return ``True`` if the ``redis`` package is installed."""
    return _REDIS_AVAILABLE


class RedisCacheBackend(CacheBackend):
    """Redis-backed cache using ``redis-py`` async client.

    Args:
        redis_url: Redis connection URL (e.g. ``redis://localhost:6379/0``).
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        if not _REDIS_AVAILABLE:
            raise RuntimeError(
                "The 'redis' package is required for the Redis cache backend. "
                "Install it with: pip install 'malwar[cache]'"
            )
        self._client: Redis = aioredis.from_url(redis_url, decode_responses=True)

    # ------------------------------------------------------------------
    # CacheBackend interface
    # ------------------------------------------------------------------

    async def get(self, key: str) -> str | None:
        result = await self._client.get(self._prefixed(key))
        return str(result) if result is not None else None

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        if ttl is not None:
            await self._client.setex(self._prefixed(key), ttl, value)
        else:
            await self._client.set(self._prefixed(key), value)

    async def delete(self, key: str) -> bool:
        result = await self._client.delete(self._prefixed(key))
        return bool(result)

    async def exists(self, key: str) -> bool:
        result = await self._client.exists(self._prefixed(key))
        return bool(result)

    async def clear(self) -> int:
        """Delete all keys with the malwar cache prefix.

        Uses SCAN to avoid blocking Redis with a KEYS command.
        """
        count = 0
        async for key in self._client.scan_iter(match=f"{_KEY_PREFIX}*"):
            await self._client.delete(key)
            count += 1
        return count

    async def size(self) -> int:
        """Count all keys with the malwar cache prefix."""
        count = 0
        async for _key in self._client.scan_iter(match=f"{_KEY_PREFIX}*"):
            count += 1
        return count

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _prefixed(key: str) -> str:
        return f"{_KEY_PREFIX}{key}"
