# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for per-API-key and per-IP rate limiting (issue #10)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.api.middleware import _request_log
from malwar.storage.database import close_db, init_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_rate_limit():
    """Ensure rate-limit state is clean for every test."""
    _request_log.clear()
    yield
    _request_log.clear()


@pytest.fixture
def app_no_auth(tmp_path, monkeypatch):
    """App with low per-IP rate limit, no API key auth."""
    db_path = tmp_path / "test_rl.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    monkeypatch.setenv("MALWAR_RATE_LIMIT_PER_IP", "3")
    monkeypatch.setenv("MALWAR_RATE_LIMIT_PER_KEY", "6")
    return create_app()


@pytest.fixture
async def client_no_auth(app_no_auth, tmp_path):
    db_path = tmp_path / "test_rl.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app_no_auth), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


@pytest.fixture
def app_with_auth(tmp_path, monkeypatch):
    """App with API key auth enabled and distinct per-key / per-IP limits."""
    db_path = tmp_path / "test_rl_auth.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    monkeypatch.setenv("MALWAR_API_KEYS", '["key-alpha","key-beta"]')
    monkeypatch.setenv("MALWAR_RATE_LIMIT_PER_IP", "2")
    monkeypatch.setenv("MALWAR_RATE_LIMIT_PER_KEY", "5")
    return create_app()


@pytest.fixture
async def client_with_auth(app_with_auth, tmp_path):
    db_path = tmp_path / "test_rl_auth.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_auth), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


# ---------------------------------------------------------------------------
# Tests: Unauthenticated (IP-based) rate limiting
# ---------------------------------------------------------------------------


class TestUnauthenticatedRateLimit:
    """Unauthenticated requests are rate-limited by IP at the lower limit."""

    async def test_under_limit_succeeds(self, client_no_auth) -> None:
        """Requests within the per-IP limit should succeed."""
        for _ in range(3):
            resp = await client_no_auth.get("/api/v1/scans")
            assert resp.status_code == 200

    async def test_over_limit_returns_429(self, client_no_auth) -> None:
        """The request exceeding the per-IP limit gets 429."""
        for _ in range(3):
            resp = await client_no_auth.get("/api/v1/scans")
            assert resp.status_code == 200

        resp = await client_no_auth.get("/api/v1/scans")
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    async def test_rate_limit_headers_present(self, client_no_auth) -> None:
        """Every response must include X-RateLimit-* headers."""
        resp = await client_no_auth.get("/api/v1/scans")
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers
        assert "X-RateLimit-Reset" in resp.headers
        assert resp.headers["X-RateLimit-Limit"] == "3"

    async def test_429_includes_rate_limit_headers(self, client_no_auth) -> None:
        """The 429 response also carries X-RateLimit-* headers."""
        for _ in range(3):
            await client_no_auth.get("/api/v1/scans")
        resp = await client_no_auth.get("/api/v1/scans")
        assert resp.status_code == 429
        assert resp.headers["X-RateLimit-Limit"] == "3"
        assert resp.headers["X-RateLimit-Remaining"] == "0"
        assert "X-RateLimit-Reset" in resp.headers


# ---------------------------------------------------------------------------
# Tests: Authenticated (API-key-based) rate limiting
# ---------------------------------------------------------------------------


class TestAuthenticatedRateLimit:
    """Authenticated requests get the higher per-key limit."""

    async def test_authenticated_gets_higher_limit(self, client_with_auth) -> None:
        """Authenticated requests should succeed up to per-key limit (5)."""
        headers = {"X-API-Key": "key-alpha"}
        for _ in range(5):
            resp = await client_with_auth.get("/api/v1/scans", headers=headers)
            assert resp.status_code == 200

        # 6th request should be rate-limited
        resp = await client_with_auth.get("/api/v1/scans", headers=headers)
        assert resp.status_code == 429

    async def test_authenticated_limit_header_value(self, client_with_auth) -> None:
        """X-RateLimit-Limit should reflect the per-key limit."""
        headers = {"X-API-Key": "key-alpha"}
        resp = await client_with_auth.get("/api/v1/scans", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["X-RateLimit-Limit"] == "5"

    async def test_different_keys_independent_limits(self, client_with_auth) -> None:
        """Two different API keys should have independent rate-limit counters."""
        headers_a = {"X-API-Key": "key-alpha"}
        headers_b = {"X-API-Key": "key-beta"}

        # Exhaust key-alpha's limit
        for _ in range(5):
            resp = await client_with_auth.get("/api/v1/scans", headers=headers_a)
            assert resp.status_code == 200

        resp = await client_with_auth.get("/api/v1/scans", headers=headers_a)
        assert resp.status_code == 429

        # key-beta should still have its full allowance
        for _ in range(5):
            resp = await client_with_auth.get("/api/v1/scans", headers=headers_b)
            assert resp.status_code == 200

    async def test_remaining_decrements(self, client_with_auth) -> None:
        """X-RateLimit-Remaining should decrease with each request."""
        headers = {"X-API-Key": "key-alpha"}
        resp1 = await client_with_auth.get("/api/v1/scans", headers=headers)
        rem1 = int(resp1.headers["X-RateLimit-Remaining"])

        resp2 = await client_with_auth.get("/api/v1/scans", headers=headers)
        rem2 = int(resp2.headers["X-RateLimit-Remaining"])

        assert rem2 == rem1 - 1


# ---------------------------------------------------------------------------
# Tests: Health endpoint bypasses rate limiting
# ---------------------------------------------------------------------------


class TestHealthBypassesRateLimit:
    """The /api/v1/health endpoint is never rate-limited."""

    async def test_health_not_rate_limited(self, client_no_auth) -> None:
        """Health endpoint should succeed even when IP limit is exhausted."""
        # Exhaust per-IP limit on a normal endpoint
        for _ in range(3):
            await client_no_auth.get("/api/v1/scans")
        resp = await client_no_auth.get("/api/v1/scans")
        assert resp.status_code == 429

        # Health should still work
        resp = await client_no_auth.get("/api/v1/health")
        assert resp.status_code == 200
