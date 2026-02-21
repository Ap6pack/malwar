# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for the caching layer: backends, TTL expiry, key generation, and pipeline integration."""

from __future__ import annotations

import hashlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from malwar.cache.base import CacheBackend
from malwar.cache.manager import CacheManager, CacheStats, reset_cache_manager
from malwar.cache.memory import MemoryCacheBackend

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def memory_backend() -> MemoryCacheBackend:
    return MemoryCacheBackend(max_size=128)


@pytest.fixture
def cache_manager(memory_backend: MemoryCacheBackend) -> CacheManager:
    return CacheManager(backend=memory_backend, default_ttl=3600)


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Ensure the module-level singleton is cleared between tests."""
    reset_cache_manager()
    yield
    reset_cache_manager()


# ---------------------------------------------------------------------------
# Abstract base class contract
# ---------------------------------------------------------------------------


class TestCacheBackendInterface:
    """Verify that MemoryCacheBackend satisfies the CacheBackend interface."""

    def test_is_subclass(self) -> None:
        assert issubclass(MemoryCacheBackend, CacheBackend)


# ---------------------------------------------------------------------------
# MemoryCacheBackend
# ---------------------------------------------------------------------------


class TestMemoryCacheBackend:
    async def test_get_set(self, memory_backend: MemoryCacheBackend) -> None:
        await memory_backend.set("k1", "v1")
        assert await memory_backend.get("k1") == "v1"

    async def test_get_missing(self, memory_backend: MemoryCacheBackend) -> None:
        assert await memory_backend.get("nonexistent") is None

    async def test_exists(self, memory_backend: MemoryCacheBackend) -> None:
        assert await memory_backend.exists("k1") is False
        await memory_backend.set("k1", "v1")
        assert await memory_backend.exists("k1") is True

    async def test_delete(self, memory_backend: MemoryCacheBackend) -> None:
        await memory_backend.set("k1", "v1")
        assert await memory_backend.delete("k1") is True
        assert await memory_backend.delete("k1") is False
        assert await memory_backend.get("k1") is None

    async def test_clear(self, memory_backend: MemoryCacheBackend) -> None:
        await memory_backend.set("a", "1")
        await memory_backend.set("b", "2")
        count = await memory_backend.clear()
        assert count == 2
        assert await memory_backend.size() == 0

    async def test_size(self, memory_backend: MemoryCacheBackend) -> None:
        assert await memory_backend.size() == 0
        await memory_backend.set("a", "1")
        await memory_backend.set("b", "2")
        assert await memory_backend.size() == 2

    async def test_ttl_expiry(self, memory_backend: MemoryCacheBackend) -> None:
        """Entries with TTL=0 should expire immediately on next access."""
        # Use a very short TTL that will expire by the time we access it.
        # We set TTL to 1 second and then patch monotonic to simulate time passing.
        await memory_backend.set("k1", "v1", ttl=1)

        # Verify it's there immediately
        assert await memory_backend.get("k1") == "v1"

        # Fast-forward time by patching the entry's expires_at
        entry = memory_backend._store["k1"]
        entry.expires_at = time.monotonic() - 1  # Expired 1 second ago

        # Now it should be gone
        assert await memory_backend.get("k1") is None
        assert await memory_backend.exists("k1") is False

    async def test_ttl_none_means_no_expiry(
        self, memory_backend: MemoryCacheBackend
    ) -> None:
        await memory_backend.set("k1", "v1", ttl=None)
        entry = memory_backend._store["k1"]
        assert entry.expires_at is None
        assert entry.is_expired() is False

    async def test_lru_eviction(self) -> None:
        """Oldest entries are evicted when max_size is exceeded."""
        backend = MemoryCacheBackend(max_size=3)
        await backend.set("a", "1")
        await backend.set("b", "2")
        await backend.set("c", "3")
        # This should evict "a"
        await backend.set("d", "4")

        assert await backend.get("a") is None
        assert await backend.get("b") == "2"
        assert await backend.get("d") == "4"

    async def test_lru_access_refreshes_position(self) -> None:
        """Accessing a key moves it to the end, protecting it from eviction."""
        backend = MemoryCacheBackend(max_size=3)
        await backend.set("a", "1")
        await backend.set("b", "2")
        await backend.set("c", "3")

        # Access "a" to refresh it
        await backend.get("a")

        # Now "b" is the oldest; inserting "d" should evict "b"
        await backend.set("d", "4")
        assert await backend.get("a") == "1"  # Still there
        assert await backend.get("b") is None  # Evicted

    async def test_overwrite_existing_key(
        self, memory_backend: MemoryCacheBackend
    ) -> None:
        await memory_backend.set("k1", "old")
        await memory_backend.set("k1", "new")
        assert await memory_backend.get("k1") == "new"
        assert await memory_backend.size() == 1

    async def test_close_clears_store(
        self, memory_backend: MemoryCacheBackend
    ) -> None:
        await memory_backend.set("k1", "v1")
        await memory_backend.close()
        assert await memory_backend.size() == 0

    async def test_prune_expired_in_size(self) -> None:
        """size() should not count expired entries."""
        backend = MemoryCacheBackend()
        await backend.set("k1", "v1", ttl=1)
        await backend.set("k2", "v2", ttl=None)

        # Force k1 to be expired
        backend._store["k1"].expires_at = time.monotonic() - 1

        assert await backend.size() == 1  # Only k2 remains


# ---------------------------------------------------------------------------
# RedisCacheBackend — import guard
# ---------------------------------------------------------------------------


class TestRedisCacheBackend:
    def test_redis_available_returns_bool(self) -> None:
        from malwar.cache.redis import redis_available

        # Should return a bool regardless of whether redis is installed
        assert isinstance(redis_available(), bool)

    def test_import_does_not_fail_without_redis(self) -> None:
        """The redis module should be importable even without the redis package."""
        # This test passes if the import at the top of this module didn't fail.
        from malwar.cache.redis import RedisCacheBackend  # noqa: F401

    def test_graceful_degradation_in_manager(self) -> None:
        """When redis backend is requested but not installed, fall back to memory."""
        mock_settings_obj = MagicMock(
            cache_backend="redis",
            cache_ttl=3600,
            redis_url="redis://localhost:6379/0",
        )
        with (
            patch("malwar.core.config.get_settings", return_value=mock_settings_obj),
            patch("malwar.cache.redis._REDIS_AVAILABLE", False),
        ):
            from malwar.cache.manager import _create_backend_from_settings

            backend = _create_backend_from_settings()
            assert isinstance(backend, MemoryCacheBackend)


# ---------------------------------------------------------------------------
# CacheStats
# ---------------------------------------------------------------------------


class TestCacheStats:
    def test_initial_state(self) -> None:
        stats = CacheStats()
        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.total == 0
        assert stats.hit_rate == 0.0

    def test_hit_rate_calculation(self) -> None:
        stats = CacheStats()
        stats.hits = 3
        stats.misses = 1
        assert stats.total == 4
        assert stats.hit_rate == 0.75

    def test_to_dict(self) -> None:
        stats = CacheStats()
        stats.hits = 10
        stats.misses = 5
        d = stats.to_dict()
        assert d["hits"] == 10
        assert d["misses"] == 5
        assert d["total"] == 15
        assert d["hit_rate"] == 0.6667


# ---------------------------------------------------------------------------
# CacheManager — key generation
# ---------------------------------------------------------------------------


class TestCacheKeyGeneration:
    def test_deterministic(self) -> None:
        """Same inputs always produce the same key."""
        key1 = CacheManager.make_cache_key("hello", ["rule_engine", "url_crawler"])
        key2 = CacheManager.make_cache_key("hello", ["rule_engine", "url_crawler"])
        assert key1 == key2

    def test_layer_order_irrelevant(self) -> None:
        """Layer order should not affect the key (sorted internally)."""
        key1 = CacheManager.make_cache_key("hello", ["url_crawler", "rule_engine"])
        key2 = CacheManager.make_cache_key("hello", ["rule_engine", "url_crawler"])
        assert key1 == key2

    def test_different_content_different_key(self) -> None:
        key1 = CacheManager.make_cache_key("content_a", ["rule_engine"])
        key2 = CacheManager.make_cache_key("content_b", ["rule_engine"])
        assert key1 != key2

    def test_different_layers_different_key(self) -> None:
        key1 = CacheManager.make_cache_key("hello", ["rule_engine"])
        key2 = CacheManager.make_cache_key("hello", ["rule_engine", "llm_analyzer"])
        assert key1 != key2

    def test_config_hash_affects_key(self) -> None:
        key1 = CacheManager.make_cache_key("hello", ["rule_engine"], config_hash="abc")
        key2 = CacheManager.make_cache_key("hello", ["rule_engine"], config_hash="xyz")
        assert key1 != key2

    def test_key_is_sha256_hex(self) -> None:
        key = CacheManager.make_cache_key("test", ["rule_engine"])
        assert len(key) == 64
        # Verify it's a valid hex string
        int(key, 16)

    def test_key_matches_manual_sha256(self) -> None:
        content = "my content"
        layers = ["llm_analyzer", "rule_engine"]
        normalised = ",".join(sorted(layers))
        payload = f"{content}{normalised}"
        expected = hashlib.sha256(payload.encode()).hexdigest()
        assert CacheManager.make_cache_key(content, layers) == expected


# ---------------------------------------------------------------------------
# CacheManager — cache operations
# ---------------------------------------------------------------------------


class TestCacheManager:
    async def test_store_and_retrieve(self, cache_manager: CacheManager) -> None:
        from malwar.models.scan import ScanResult

        result = ScanResult(scan_id="test-1", target="SKILL.md", skill_sha256="abc123")

        await cache_manager.store_result(
            content="# My Skill",
            layers=["rule_engine"],
            result=result,
        )

        cached = await cache_manager.get_cached_result(
            content="# My Skill",
            layers=["rule_engine"],
        )
        assert cached is not None
        assert cached.scan_id == "test-1"
        assert cached.target == "SKILL.md"

    async def test_miss_returns_none(self, cache_manager: CacheManager) -> None:
        result = await cache_manager.get_cached_result(
            content="not cached",
            layers=["rule_engine"],
        )
        assert result is None

    async def test_hit_miss_stats(self, cache_manager: CacheManager) -> None:
        from malwar.models.scan import ScanResult

        result = ScanResult(scan_id="test-2", target="SKILL.md", skill_sha256="abc")

        # Miss
        await cache_manager.get_cached_result("x", ["rule_engine"])
        assert cache_manager.stats.misses == 1
        assert cache_manager.stats.hits == 0

        # Store and hit
        await cache_manager.store_result("x", ["rule_engine"], result)
        await cache_manager.get_cached_result("x", ["rule_engine"])
        assert cache_manager.stats.hits == 1
        assert cache_manager.stats.misses == 1

    async def test_clear(self, cache_manager: CacheManager) -> None:
        from malwar.models.scan import ScanResult

        result = ScanResult(scan_id="test-3", target="SKILL.md", skill_sha256="abc")
        await cache_manager.store_result("x", ["rule_engine"], result)
        assert await cache_manager.size() == 1

        count = await cache_manager.clear()
        assert count == 1
        assert await cache_manager.size() == 0

    async def test_invalidate(self, cache_manager: CacheManager) -> None:
        from malwar.models.scan import ScanResult

        result = ScanResult(scan_id="test-4", target="SKILL.md", skill_sha256="abc")
        await cache_manager.store_result("x", ["rule_engine"], result)

        removed = await cache_manager.invalidate("x", ["rule_engine"])
        assert removed is True

        # Should be gone now
        cached = await cache_manager.get_cached_result("x", ["rule_engine"])
        assert cached is None

    async def test_invalidate_nonexistent(self, cache_manager: CacheManager) -> None:
        removed = await cache_manager.invalidate("nonexistent", ["rule_engine"])
        assert removed is False

    async def test_ttl_override(self, cache_manager: CacheManager) -> None:
        from malwar.models.scan import ScanResult

        result = ScanResult(scan_id="test-5", target="SKILL.md", skill_sha256="abc")
        await cache_manager.store_result("x", ["rule_engine"], result, ttl=1)

        # Still there immediately
        cached = await cache_manager.get_cached_result("x", ["rule_engine"])
        assert cached is not None

        # Force expiry
        key = CacheManager.make_cache_key("x", ["rule_engine"])
        entry = cache_manager.backend._store[key]
        entry.expires_at = time.monotonic() - 1

        # Now expired
        cached = await cache_manager.get_cached_result("x", ["rule_engine"])
        assert cached is None

    async def test_close(self, cache_manager: CacheManager) -> None:
        await cache_manager.close()
        # After close, backend should be cleared
        assert await cache_manager.size() == 0


# ---------------------------------------------------------------------------
# Pipeline integration (mocked cache)
# ---------------------------------------------------------------------------


class TestPipelineIntegration:
    """Test that the scan pipeline integrates with the cache correctly."""

    async def test_cache_hit_skips_detectors(self) -> None:
        """When a cached result exists, detectors should not be executed."""
        from malwar.models.scan import ScanResult
        from malwar.models.skill import SkillContent
        from malwar.scanner.pipeline import ScanPipeline

        cached_result = ScanResult(
            scan_id="cached-1",
            target="SKILL.md",
            skill_sha256="abc",
        )

        mock_cache = AsyncMock(spec=CacheManager)
        mock_cache.get_cached_result = AsyncMock(return_value=cached_result)
        mock_cache.store_result = AsyncMock()

        skill = SkillContent(
            file_path="SKILL.md",
            raw_content="# Test Skill\nSome content",
            sha256_hash="abc",
        )

        pipeline = ScanPipeline(cache_manager=mock_cache)
        result = await pipeline.scan(skill, layers=["rule_engine"])

        assert result.scan_id == "cached-1"
        mock_cache.get_cached_result.assert_called_once()
        mock_cache.store_result.assert_not_called()

    async def test_cache_miss_runs_detectors_and_stores(self) -> None:
        """When no cached result, detectors run and result is stored."""
        from malwar.models.skill import SkillContent
        from malwar.scanner.pipeline import ScanPipeline

        mock_cache = AsyncMock(spec=CacheManager)
        mock_cache.get_cached_result = AsyncMock(return_value=None)
        mock_cache.store_result = AsyncMock()

        skill = SkillContent(
            file_path="SKILL.md",
            raw_content="# Test Skill\nSome content",
            sha256_hash="abc",
        )

        pipeline = ScanPipeline(cache_manager=mock_cache)
        result = await pipeline.scan(skill, layers=["rule_engine"])

        assert result.scan_id  # Should have a new scan ID
        mock_cache.get_cached_result.assert_called_once()
        mock_cache.store_result.assert_called_once()

    async def test_cache_exception_does_not_break_scan(self) -> None:
        """If cache raises, the scan should still proceed normally."""
        from malwar.models.skill import SkillContent
        from malwar.scanner.pipeline import ScanPipeline

        mock_cache = AsyncMock(spec=CacheManager)
        mock_cache.get_cached_result = AsyncMock(side_effect=RuntimeError("redis down"))
        mock_cache.store_result = AsyncMock(side_effect=RuntimeError("redis down"))

        skill = SkillContent(
            file_path="SKILL.md",
            raw_content="# Test Skill\nSome content",
            sha256_hash="abc",
        )

        pipeline = ScanPipeline(cache_manager=mock_cache)
        result = await pipeline.scan(skill, layers=["rule_engine"])

        # Scan should complete despite cache errors
        assert result.scan_id
        assert result.status == "completed"

    async def test_pipeline_without_cache_manager(self) -> None:
        """Pipeline works fine when cache_manager is None (no caching)."""
        from malwar.models.skill import SkillContent
        from malwar.scanner.pipeline import ScanPipeline

        skill = SkillContent(
            file_path="SKILL.md",
            raw_content="# Test Skill",
            sha256_hash="abc",
        )

        # Patch get_cache_manager to return None (simulating no cache configured)
        with patch("malwar.cache.manager.get_cache_manager", return_value=None):
            pipeline = ScanPipeline(cache_manager=None)
            # Override the _get_cache_manager to return None
            pipeline._cache_manager = None
            pipeline._get_cache_manager = lambda: None
            result = await pipeline.scan(skill, layers=["rule_engine"])
            assert result.scan_id


# ---------------------------------------------------------------------------
# Config integration
# ---------------------------------------------------------------------------


class TestCacheConfig:
    def test_default_settings(self) -> None:
        """Default config values for cache settings."""
        with patch.dict("os.environ", {}, clear=False):
            from malwar.core.config import Settings

            s = Settings()
            assert s.cache_backend == "memory"
            assert s.cache_ttl == 3600
            assert s.redis_url == "redis://localhost:6379/0"

    def test_env_override(self) -> None:
        """Cache settings can be overridden via environment variables."""
        import os

        env = {
            "MALWAR_CACHE_BACKEND": "redis",
            "MALWAR_CACHE_TTL": "7200",
            "MALWAR_REDIS_URL": "redis://myhost:6380/1",
        }
        with patch.dict(os.environ, env, clear=False):
            from malwar.core.config import Settings

            s = Settings()
            assert s.cache_backend == "redis"
            assert s.cache_ttl == 7200
            assert s.redis_url == "redis://myhost:6380/1"


# ---------------------------------------------------------------------------
# Singleton management
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_cache_manager_returns_same_instance(self) -> None:
        from malwar.cache.manager import get_cache_manager, reset_cache_manager

        reset_cache_manager()
        mgr1 = get_cache_manager()
        mgr2 = get_cache_manager()
        assert mgr1 is mgr2

    def test_reset_clears_singleton(self) -> None:
        from malwar.cache.manager import get_cache_manager, reset_cache_manager

        reset_cache_manager()
        mgr1 = get_cache_manager()
        reset_cache_manager()
        mgr2 = get_cache_manager()
        assert mgr1 is not mgr2
