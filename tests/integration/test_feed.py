# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the public IOC feed endpoint."""

from __future__ import annotations

import csv
import io

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.storage.database import close_db, init_db


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a FastAPI app with a temporary database."""
    db_path = tmp_path / "test_feed.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    """Provide an async HTTP client bound to the test app, with DB initialized."""
    db_path = tmp_path / "test_feed.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


# ---------------------------------------------------------------------------
# 1. Basic feed retrieval
# ---------------------------------------------------------------------------
class TestFeedBasic:
    """Basic IOC feed endpoint tests."""

    async def test_feed_returns_200(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs")
        assert resp.status_code == 200

    async def test_feed_contains_seeded_iocs(self, client) -> None:
        """Seed data includes IOCs from ClawHavoc, SnykToxic, and ShadowPkg."""
        resp = await client.get("/api/v1/feed/iocs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 12  # 4 ClawHavoc + 4 SnykToxic + 4 ShadowPkg

        ioc_ids = [item["id"] for item in data["items"]]
        # At least one from each campaign
        assert any("clawhavoc" in ioc_id for ioc_id in ioc_ids)
        assert any("snyktoxic" in ioc_id for ioc_id in ioc_ids)
        assert any("shadowpkg" in ioc_id for ioc_id in ioc_ids)

    async def test_feed_response_structure(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs")
        data = resp.json()
        assert "total" in data
        assert "offset" in data
        assert "limit" in data
        assert "items" in data
        assert isinstance(data["items"], list)

        if data["items"]:
            item = data["items"][0]
            required_fields = {
                "id",
                "name",
                "pattern_value",
                "severity",
                "source",
            }
            assert required_fields.issubset(set(item.keys()))

    async def test_feed_has_etag_header(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs")
        assert resp.status_code == 200
        assert "etag" in resp.headers


# ---------------------------------------------------------------------------
# 2. Filter by campaign_id
# ---------------------------------------------------------------------------
class TestFilterByCampaign:
    """Tests for campaign_id filter."""

    async def test_filter_clawhavoc(self, client) -> None:
        resp = await client.get(
            "/api/v1/feed/iocs?campaign_id=campaign-clawhavoc-001"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 4
        for item in data["items"]:
            assert item["campaign_id"] == "campaign-clawhavoc-001"

    async def test_filter_snyktoxic(self, client) -> None:
        resp = await client.get(
            "/api/v1/feed/iocs?campaign_id=campaign-snyktoxic-001"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 4
        for item in data["items"]:
            assert item["campaign_id"] == "campaign-snyktoxic-001"

    async def test_filter_shadowpkg(self, client) -> None:
        resp = await client.get(
            "/api/v1/feed/iocs?campaign_id=campaign-shadowpkg-001"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 4
        for item in data["items"]:
            assert item["campaign_id"] == "campaign-shadowpkg-001"

    async def test_filter_nonexistent_campaign(self, client) -> None:
        resp = await client.get(
            "/api/v1/feed/iocs?campaign_id=campaign-does-not-exist"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []


# ---------------------------------------------------------------------------
# 3. Filter by ioc_type
# ---------------------------------------------------------------------------
class TestFilterByIocType:
    """Tests for ioc_type filter."""

    async def test_filter_ip(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?ioc_type=ip")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["ioc_type"] == "ip"

    async def test_filter_domain(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?ioc_type=domain")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["ioc_type"] == "domain"

    async def test_filter_url(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?ioc_type=url")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["ioc_type"] == "url"

    async def test_filter_no_match(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?ioc_type=email")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []


# ---------------------------------------------------------------------------
# 4. CSV format
# ---------------------------------------------------------------------------
class TestCSVFormat:
    """Tests for CSV output format."""

    async def test_csv_returns_text_csv(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?format=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    async def test_csv_has_header_row(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?format=csv")
        reader = csv.reader(io.StringIO(resp.text))
        header = next(reader)
        assert "id" in header
        assert "name" in header
        assert "pattern_value" in header
        assert "severity" in header

    async def test_csv_has_data_rows(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?format=csv")
        reader = csv.reader(io.StringIO(resp.text))
        rows = list(reader)
        # Header + at least 12 data rows from seeded signatures
        assert len(rows) >= 13

    async def test_csv_has_etag(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?format=csv")
        assert "etag" in resp.headers


# ---------------------------------------------------------------------------
# 5. ETag / If-None-Match
# ---------------------------------------------------------------------------
class TestETag:
    """Tests for ETag-based conditional requests."""

    async def test_etag_304_when_unchanged(self, client) -> None:
        # First request to get the ETag
        resp1 = await client.get("/api/v1/feed/iocs")
        assert resp1.status_code == 200
        etag = resp1.headers["etag"]
        assert etag

        # Second request with If-None-Match
        resp2 = await client.get(
            "/api/v1/feed/iocs", headers={"If-None-Match": etag}
        )
        assert resp2.status_code == 304

    async def test_etag_200_when_different(self, client) -> None:
        resp = await client.get(
            "/api/v1/feed/iocs",
            headers={"If-None-Match": '"completely-wrong-etag"'},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 6. Pagination
# ---------------------------------------------------------------------------
class TestPagination:
    """Tests for limit/offset pagination."""

    async def test_limit_restricts_results(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?limit=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["limit"] == 2
        assert data["total"] >= 12  # total is unaffected by limit

    async def test_offset_skips_results(self, client) -> None:
        # Get all items
        resp_all = await client.get("/api/v1/feed/iocs?limit=100")
        all_items = resp_all.json()["items"]

        # Get with offset=2
        resp_offset = await client.get("/api/v1/feed/iocs?limit=100&offset=2")
        offset_items = resp_offset.json()["items"]
        assert resp_offset.json()["offset"] == 2

        # The offset result should skip the first 2 items
        assert len(offset_items) == len(all_items) - 2

    async def test_offset_beyond_total_returns_empty(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?offset=9999")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] >= 12


# ---------------------------------------------------------------------------
# 7. Empty result
# ---------------------------------------------------------------------------
class TestEmptyResult:
    """Tests for empty result sets."""

    async def test_empty_when_no_matches(self, client) -> None:
        resp = await client.get(
            "/api/v1/feed/iocs?campaign_id=nonexistent&ioc_type=email&severity=info"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["offset"] == 0


# ---------------------------------------------------------------------------
# 8. Filter by severity
# ---------------------------------------------------------------------------
class TestFilterBySeverity:
    """Tests for severity filter."""

    async def test_filter_critical(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?severity=critical")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["severity"] == "critical"

    async def test_filter_high(self, client) -> None:
        resp = await client.get("/api/v1/feed/iocs?severity=high")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["severity"] == "high"
