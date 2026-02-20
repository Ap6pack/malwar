# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the campaigns API endpoints."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.storage.database import close_db, init_db


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a FastAPI app with a temporary database."""
    db_path = tmp_path / "test_campaigns.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    """Provide an async HTTP client bound to the test app, with DB initialized."""
    db_path = tmp_path / "test_campaigns.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


# ---------------------------------------------------------------------------
# 1. GET /api/v1/campaigns
# ---------------------------------------------------------------------------
class TestListCampaigns:
    """Campaign list endpoint tests."""

    async def test_list_campaigns_returns_200(self, client) -> None:
        resp = await client.get("/api/v1/campaigns")
        assert resp.status_code == 200

    async def test_list_campaigns_contains_seed_data(self, client) -> None:
        """The DB migration seeds a ClawHavoc campaign, so it should appear."""
        resp = await client.get("/api/v1/campaigns")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        assert any(c["id"] == "campaign-clawhavoc-001" for c in data)

    async def test_list_campaigns_response_structure(self, client) -> None:
        resp = await client.get("/api/v1/campaigns")
        data = resp.json()
        campaign = data[0]
        required_fields = {
            "id",
            "name",
            "description",
            "first_seen",
            "last_seen",
            "attributed_to",
            "iocs",
            "total_skills_affected",
            "status",
        }
        assert required_fields.issubset(set(campaign.keys()))


# ---------------------------------------------------------------------------
# 2. GET /api/v1/campaigns/{campaign_id}
# ---------------------------------------------------------------------------
class TestGetCampaign:
    """Campaign detail endpoint tests."""

    async def test_get_campaign_returns_200(self, client) -> None:
        resp = await client.get("/api/v1/campaigns/campaign-clawhavoc-001")
        assert resp.status_code == 200

    async def test_get_campaign_detail(self, client) -> None:
        resp = await client.get("/api/v1/campaigns/campaign-clawhavoc-001")
        data = resp.json()
        assert data["id"] == "campaign-clawhavoc-001"
        assert data["name"] == "ClawHavoc"
        assert data["status"] == "active"
        assert "signature_count" in data
        assert data["signature_count"] >= 1

    async def test_get_campaign_not_found(self, client) -> None:
        resp = await client.get("/api/v1/campaigns/does-not-exist")
        assert resp.status_code == 404
