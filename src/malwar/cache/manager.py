# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Cache manager that wraps cache operations with key generation.

The :class:`CacheManager` is the primary public interface for the caching
layer.  It generates deterministic cache keys from content + scan config,
serialises :class:`~malwar.models.scan.ScanResult` to/from JSON, and
tracks hit/miss statistics.
"""

from __future__ import annotations

import hashlib
import logging

from malwar.cache.base import CacheBackend
from malwar.cache.memory import MemoryCacheBackend
from malwar.models.scan import ScanResult

logger = logging.getLogger("malwar.cache.manager")

# Module-level singleton
_manager: CacheManager | None = None


class CacheStats:
    """Simple hit/miss counter."""

    __slots__ = ("hits", "misses")

    def __init__(self) -> None:
        self.hits: int = 0
        self.misses: int = 0

    @property
    def total(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        return self.hits / self.total if self.total else 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "total": self.total,
            "hit_rate": round(self.hit_rate, 4),
        }


class CacheManager:
    """High-level cache interface for scan deduplication.

    Wraps a :class:`CacheBackend` and provides content-addressed key
    generation, JSON serialisation of scan results, and hit/miss
    statistics.

    Args:
        backend: The cache backend to use.
        default_ttl: Default time-to-live in seconds (``3600`` = 1 hour).
    """

    def __init__(
        self,
        backend: CacheBackend | None = None,
        default_ttl: int = 3600,
    ) -> None:
        self._backend = backend or MemoryCacheBackend()
        self._default_ttl = default_ttl
        self._stats = CacheStats()

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    @staticmethod
    def make_cache_key(content: str, layers: list[str], config_hash: str = "") -> str:
        """Generate a deterministic cache key.

        The key is the hex SHA-256 digest of:
            ``content + sorted(layers) + config_hash``

        Args:
            content: Raw SKILL.md content.
            layers: List of layer names to include in the key.
            config_hash: Optional configuration hash for further
                differentiation.

        Returns:
            64-character lowercase hex SHA-256 digest.
        """
        normalised_layers = ",".join(sorted(layers))
        payload = f"{content}{normalised_layers}{config_hash}"
        return hashlib.sha256(payload.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Cache operations
    # ------------------------------------------------------------------

    async def get_cached_result(
        self,
        content: str,
        layers: list[str],
        config_hash: str = "",
    ) -> ScanResult | None:
        """Look up a cached scan result.

        Returns:
            The cached :class:`ScanResult`, or ``None`` on a miss.
        """
        key = self.make_cache_key(content, layers, config_hash)
        raw = await self._backend.get(key)
        if raw is None:
            self._stats.misses += 1
            logger.debug("Cache MISS for key %s", key[:12])
            return None
        self._stats.hits += 1
        logger.debug("Cache HIT for key %s", key[:12])
        return ScanResult.model_validate_json(raw)

    async def store_result(
        self,
        content: str,
        layers: list[str],
        result: ScanResult,
        config_hash: str = "",
        ttl: int | None = None,
    ) -> None:
        """Store a scan result in the cache.

        Args:
            content: Raw SKILL.md content (used for key generation).
            layers: Layer names used in the scan.
            result: The scan result to cache.
            config_hash: Optional configuration hash.
            ttl: Override TTL in seconds; uses ``default_ttl`` if ``None``.
        """
        key = self.make_cache_key(content, layers, config_hash)
        serialised = result.model_dump_json()
        await self._backend.set(key, serialised, ttl=ttl or self._default_ttl)
        logger.debug("Cached result for key %s (ttl=%s)", key[:12], ttl or self._default_ttl)

    async def invalidate(
        self,
        content: str,
        layers: list[str],
        config_hash: str = "",
    ) -> bool:
        """Remove a specific cached result.

        Returns:
            ``True`` if the entry existed and was removed.
        """
        key = self.make_cache_key(content, layers, config_hash)
        return await self._backend.delete(key)

    async def clear(self) -> int:
        """Flush all cached scan results.

        Returns:
            Number of entries removed.
        """
        count = await self._backend.clear()
        logger.info("Cache cleared: %d entries removed", count)
        return count

    async def size(self) -> int:
        """Return the number of live entries in the cache."""
        return await self._backend.size()

    @property
    def stats(self) -> CacheStats:
        """Return the hit/miss statistics object."""
        return self._stats

    @property
    def backend(self) -> CacheBackend:
        """Return the underlying cache backend."""
        return self._backend

    async def close(self) -> None:
        """Release resources held by the backend."""
        await self._backend.close()


def _create_backend_from_settings() -> CacheBackend:
    """Instantiate the cache backend based on application settings."""
    from malwar.core.config import get_settings

    settings = get_settings()
    backend_type = getattr(settings, "cache_backend", "memory")

    if backend_type == "redis":
        from malwar.cache.redis import RedisCacheBackend, redis_available

        if not redis_available():
            logger.warning(
                "Redis cache backend requested but redis package not installed. "
                "Falling back to in-memory cache."
            )
            return MemoryCacheBackend()
        redis_url = getattr(settings, "redis_url", "redis://localhost:6379/0")
        return RedisCacheBackend(redis_url=redis_url)

    return MemoryCacheBackend()


def get_cache_manager() -> CacheManager:
    """Return the module-level :class:`CacheManager` singleton.

    Creates a new instance on first call using application settings.
    """
    global _manager
    if _manager is None:
        from malwar.core.config import get_settings

        settings = get_settings()
        backend = _create_backend_from_settings()
        ttl = getattr(settings, "cache_ttl", 3600)
        _manager = CacheManager(backend=backend, default_ttl=ttl)
    return _manager


def reset_cache_manager() -> None:
    """Reset the singleton (useful for testing)."""
    global _manager
    _manager = None
