# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the STIX/TAXII export API endpoints."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.storage.database import close_db, init_db


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a FastAPI app with a temporary database."""
    db_path = tmp_path / "test_export.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    """Provide an async HTTP client bound to the test app, with DB initialized."""
    db_path = tmp_path / "test_export.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


# ---------------------------------------------------------------------------
# STIX Bundle endpoint
# ---------------------------------------------------------------------------


class TestStixBundleEndpoint:
    """Tests for GET /api/v1/export/stix."""

    async def test_stix_returns_200(self, client) -> None:
        resp = await client.get("/api/v1/export/stix")
        assert resp.status_code == 200

    async def test_stix_returns_valid_json(self, client) -> None:
        resp = await client.get("/api/v1/export/stix")
        data = resp.json()
        assert data["type"] == "bundle"
        assert data["id"].startswith("bundle--")
        assert "objects" in data

    async def test_stix_bundle_contains_identity(self, client) -> None:
        resp = await client.get("/api/v1/export/stix")
        data = resp.json()
        types = [obj["type"] for obj in data["objects"]]
        assert "identity" in types

    async def test_stix_bundle_contains_seeded_campaigns(self, client) -> None:
        """The DB seeds at least one campaign (ClawHavoc); it should appear."""
        resp = await client.get("/api/v1/export/stix")
        data = resp.json()
        types = [obj["type"] for obj in data["objects"]]
        assert "campaign" in types
        assert "threat-actor" in types

    async def test_stix_bundle_contains_indicators(self, client) -> None:
        """Seeded signatures should appear as indicators."""
        resp = await client.get("/api/v1/export/stix")
        data = resp.json()
        types = [obj["type"] for obj in data["objects"]]
        assert "indicator" in types

    async def test_stix_all_objects_have_spec_version(self, client) -> None:
        resp = await client.get("/api/v1/export/stix")
        data = resp.json()
        for obj in data["objects"]:
            assert obj.get("spec_version") == "2.1", (
                f"Object {obj['id']} missing spec_version 2.1"
            )


# ---------------------------------------------------------------------------
# Campaign filtering
# ---------------------------------------------------------------------------


class TestStixCampaignFiltering:
    """Tests for GET /api/v1/export/stix?campaign=<name>."""

    async def test_filter_by_known_campaign(self, client) -> None:
        resp = await client.get("/api/v1/export/stix?campaign=ClawHavoc")
        assert resp.status_code == 200
        data = resp.json()
        campaigns = [
            obj for obj in data["objects"] if obj["type"] == "campaign"
        ]
        assert len(campaigns) == 1
        assert campaigns[0]["name"] == "ClawHavoc"

    async def test_filter_by_unknown_campaign_returns_404(self, client) -> None:
        resp = await client.get("/api/v1/export/stix?campaign=DoesNotExist")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# TAXII Discovery
# ---------------------------------------------------------------------------


class TestTaxiiDiscoveryEndpoint:
    """Tests for GET /api/v1/export/taxii/discovery."""

    async def test_discovery_returns_200(self, client) -> None:
        resp = await client.get("/api/v1/export/taxii/discovery")
        assert resp.status_code == 200

    async def test_discovery_has_api_roots(self, client) -> None:
        resp = await client.get("/api/v1/export/taxii/discovery")
        data = resp.json()
        assert "api_roots" in data
        assert len(data["api_roots"]) >= 1

    async def test_discovery_has_title(self, client) -> None:
        resp = await client.get("/api/v1/export/taxii/discovery")
        data = resp.json()
        assert "title" in data


# ---------------------------------------------------------------------------
# TAXII Collections
# ---------------------------------------------------------------------------


class TestTaxiiCollectionsEndpoint:
    """Tests for GET /api/v1/export/taxii/collections."""

    async def test_collections_returns_200(self, client) -> None:
        resp = await client.get("/api/v1/export/taxii/collections")
        assert resp.status_code == 200

    async def test_collections_has_collection_list(self, client) -> None:
        resp = await client.get("/api/v1/export/taxii/collections")
        data = resp.json()
        assert "collections" in data
        assert len(data["collections"]) >= 1

    async def test_collection_has_id(self, client) -> None:
        resp = await client.get("/api/v1/export/taxii/collections")
        coll = resp.json()["collections"][0]
        assert "id" in coll
        assert coll["id"] == "malwar-threat-intel-001"


# ---------------------------------------------------------------------------
# TAXII Collection Objects
# ---------------------------------------------------------------------------


class TestTaxiiCollectionObjectsEndpoint:
    """Tests for GET /api/v1/export/taxii/collections/{id}/objects."""

    async def test_objects_returns_200(self, client) -> None:
        resp = await client.get(
            "/api/v1/export/taxii/collections/malwar-threat-intel-001/objects"
        )
        assert resp.status_code == 200

    async def test_objects_has_envelope_format(self, client) -> None:
        resp = await client.get(
            "/api/v1/export/taxii/collections/malwar-threat-intel-001/objects"
        )
        data = resp.json()
        assert "more" in data
        assert "objects" in data
        assert isinstance(data["objects"], list)

    async def test_objects_contains_stix_objects(self, client) -> None:
        resp = await client.get(
            "/api/v1/export/taxii/collections/malwar-threat-intel-001/objects"
        )
        data = resp.json()
        types = [obj["type"] for obj in data["objects"]]
        assert "identity" in types

    async def test_unknown_collection_returns_404(self, client) -> None:
        resp = await client.get(
            "/api/v1/export/taxii/collections/does-not-exist/objects"
        )
        assert resp.status_code == 404
