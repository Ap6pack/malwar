# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the analytics endpoint (issue #9)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.storage.database import close_db, init_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app(tmp_path, monkeypatch):
    db_path = tmp_path / "test_analytics.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    db_path = tmp_path / "test_analytics.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


async def _seed_usage(rows: list[tuple[str, str, str, int, str]]) -> None:
    """Insert test data into the api_usage table.

    Each row is (api_key, endpoint, method, status_code, timestamp).
    """
    from malwar.storage.database import get_db

    db = await get_db()
    for row in rows:
        await db.execute(
            "INSERT INTO api_usage (api_key, endpoint, method, status_code, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            row,
        )
    await db.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAnalyticsEndpoint:
    """GET /api/v1/analytics returns usage statistics."""

    async def test_empty_stats_when_no_usage(self, client) -> None:
        """With no recorded usage, all counters should be zero / empty."""
        resp = await client.get("/api/v1/analytics")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_requests"] == 0
        assert data["requests_by_endpoint"] == []
        assert data["requests_by_verdict"] == []
        assert data["requests_over_time"] == []

    async def test_returns_aggregated_stats(self, client) -> None:
        """Seeded usage data should be reflected in the analytics response."""
        await _seed_usage([
            ("key-1", "/api/v1/scan", "POST", 200, "2026-02-15T10:00:00"),
            ("key-1", "/api/v1/scan", "POST", 200, "2026-02-15T11:00:00"),
            ("key-2", "/api/v1/scans", "GET", 200, "2026-02-15T12:00:00"),
            ("key-1", "/api/v1/health", "GET", 200, "2026-02-16T08:00:00"),
        ])

        resp = await client.get("/api/v1/analytics")
        assert resp.status_code == 200
        data = resp.json()

        assert data["total_requests"] == 4

        # Verify endpoints are grouped
        endpoint_map = {e["endpoint"]: e["count"] for e in data["requests_by_endpoint"]}
        assert endpoint_map["/api/v1/scan"] == 2
        assert endpoint_map["/api/v1/scans"] == 1
        assert endpoint_map["/api/v1/health"] == 1

        # Verify daily buckets
        time_map = {b["date"]: b["count"] for b in data["requests_over_time"]}
        assert time_map["2026-02-15"] == 3
        assert time_map["2026-02-16"] == 1

    async def test_filter_by_date_range(self, client) -> None:
        """Filtering by start_date and end_date narrows the results."""
        await _seed_usage([
            ("key-1", "/api/v1/scan", "POST", 200, "2026-02-10T09:00:00"),
            ("key-1", "/api/v1/scan", "POST", 200, "2026-02-15T10:00:00"),
            ("key-1", "/api/v1/scan", "POST", 200, "2026-02-20T11:00:00"),
        ])

        # Only the middle record falls within [2026-02-14, 2026-02-16]
        resp = await client.get(
            "/api/v1/analytics",
            params={"start_date": "2026-02-14", "end_date": "2026-02-16"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_requests"] == 1

    async def test_filter_by_api_key(self, client) -> None:
        """Filtering by api_key shows only that key's usage."""
        await _seed_usage([
            ("key-1", "/api/v1/scan", "POST", 200, "2026-02-15T10:00:00"),
            ("key-2", "/api/v1/scans", "GET", 200, "2026-02-15T12:00:00"),
            ("key-1", "/api/v1/health", "GET", 200, "2026-02-15T14:00:00"),
        ])

        resp = await client.get("/api/v1/analytics", params={"api_key": "key-1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_requests"] == 2

    async def test_filter_by_start_date_only(self, client) -> None:
        """Using only start_date excludes earlier records."""
        await _seed_usage([
            ("key-1", "/api/v1/scan", "POST", 200, "2026-01-01T00:00:00"),
            ("key-1", "/api/v1/scan", "POST", 200, "2026-02-15T10:00:00"),
        ])

        resp = await client.get(
            "/api/v1/analytics", params={"start_date": "2026-02-01"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_requests"] == 1

    async def test_response_structure(self, client) -> None:
        """Verify the response contains all expected top-level keys."""
        resp = await client.get("/api/v1/analytics")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "requests_by_endpoint" in data
        assert "requests_by_verdict" in data
        assert "requests_over_time" in data
