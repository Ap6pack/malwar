# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the signatures CRUD API endpoints."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.storage.database import close_db, init_db


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a FastAPI app with a temporary database."""
    db_path = tmp_path / "test_signatures.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    """Provide an async HTTP client bound to the test app, with DB initialized."""
    db_path = tmp_path / "test_signatures.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_SIGNATURE = {
    "name": "Test Malicious IP",
    "description": "A test signature for a known malicious IP",
    "severity": "high",
    "category": "known_malware",
    "pattern_type": "exact",
    "pattern_value": "198.51.100.42",
    "ioc_type": "ip",
    "source": "test",
}


async def _create_signature(client: AsyncClient, **overrides) -> dict:
    """Helper: POST a signature and return the response JSON."""
    payload = {**SAMPLE_SIGNATURE, **overrides}
    resp = await client.post("/api/v1/signatures", json=payload)
    assert resp.status_code == 201
    return resp.json()


# ---------------------------------------------------------------------------
# 1. POST /api/v1/signatures - Create
# ---------------------------------------------------------------------------
class TestCreateSignature:
    """Signature creation endpoint tests."""

    async def test_create_returns_201(self, client) -> None:
        resp = await client.post("/api/v1/signatures", json=SAMPLE_SIGNATURE)
        assert resp.status_code == 201

    async def test_create_returns_full_record(self, client) -> None:
        data = await _create_signature(client)
        assert data["id"].startswith("sig-")
        assert data["name"] == "Test Malicious IP"
        assert data["severity"] == "high"
        assert data["pattern_type"] == "exact"
        assert data["pattern_value"] == "198.51.100.42"
        assert data["ioc_type"] == "ip"
        assert data["source"] == "test"
        assert data["enabled"] is True
        assert data["created_at"] is not None

    async def test_create_with_minimal_fields(self, client) -> None:
        payload = {
            "name": "Minimal Sig",
            "description": "Minimal test",
            "severity": "low",
            "category": "suspicious_command",
            "pattern_type": "regex",
            "pattern_value": "curl.*evil\\.com",
        }
        resp = await client.post("/api/v1/signatures", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["ioc_type"] is None
        assert data["campaign_id"] is None
        assert data["source"] == "manual"

    async def test_create_missing_required_returns_422(self, client) -> None:
        resp = await client.post("/api/v1/signatures", json={"name": "incomplete"})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 2. GET /api/v1/signatures - List
# ---------------------------------------------------------------------------
class TestListSignatures:
    """Signature listing endpoint tests."""

    async def test_list_includes_seeded_data(self, client) -> None:
        """The DB migration seeds initial signatures; they should appear."""
        resp = await client.get("/api/v1/signatures")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1  # seeded signatures exist

    async def test_list_includes_created_signature(self, client) -> None:
        created = await _create_signature(client)
        resp = await client.get("/api/v1/signatures")
        assert resp.status_code == 200
        ids = [s["id"] for s in resp.json()]
        assert created["id"] in ids

    async def test_list_filter_by_pattern_type(self, client) -> None:
        await _create_signature(client, pattern_type="regex", pattern_value="test.*")
        resp = await client.get("/api/v1/signatures?pattern_type=regex")
        assert resp.status_code == 200
        data = resp.json()
        assert all(s["pattern_type"] == "regex" for s in data)

    async def test_list_filter_by_ioc_type(self, client) -> None:
        await _create_signature(client, ioc_type="domain", pattern_value="evil.test")
        resp = await client.get("/api/v1/signatures?ioc_type=domain")
        assert resp.status_code == 200
        data = resp.json()
        assert all(s["ioc_type"] == "domain" for s in data)

    async def test_list_filter_by_campaign_id(self, client) -> None:
        resp = await client.get(
            "/api/v1/signatures?campaign_id=campaign-clawhavoc-001"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        assert all(s["campaign_id"] == "campaign-clawhavoc-001" for s in data)


# ---------------------------------------------------------------------------
# 3. GET /api/v1/signatures/{sig_id} - Get by ID
# ---------------------------------------------------------------------------
class TestGetSignature:
    """Signature retrieval endpoint tests."""

    async def test_get_by_id(self, client) -> None:
        created = await _create_signature(client)
        resp = await client.get(f"/api/v1/signatures/{created['id']}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == created["id"]
        assert data["name"] == created["name"]
        assert data["severity"] == created["severity"]
        assert data["pattern_value"] == created["pattern_value"]

    async def test_get_nonexistent_returns_404(self, client) -> None:
        resp = await client.get("/api/v1/signatures/does-not-exist")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4. PUT /api/v1/signatures/{sig_id} - Update
# ---------------------------------------------------------------------------
class TestUpdateSignature:
    """Signature update endpoint tests."""

    async def test_update_changes_fields(self, client) -> None:
        created = await _create_signature(client)
        resp = await client.put(
            f"/api/v1/signatures/{created['id']}",
            json={"severity": "critical", "description": "Updated description"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["severity"] == "critical"
        assert data["description"] == "Updated description"
        # Unchanged fields preserved
        assert data["name"] == created["name"]
        assert data["pattern_value"] == created["pattern_value"]

    async def test_update_nonexistent_returns_404(self, client) -> None:
        resp = await client.put(
            "/api/v1/signatures/does-not-exist",
            json={"severity": "low"},
        )
        assert resp.status_code == 404

    async def test_update_no_changes(self, client) -> None:
        created = await _create_signature(client)
        resp = await client.put(
            f"/api/v1/signatures/{created['id']}", json={}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == created["name"]


# ---------------------------------------------------------------------------
# 5. DELETE /api/v1/signatures/{sig_id} - Delete
# ---------------------------------------------------------------------------
class TestDeleteSignature:
    """Signature deletion endpoint tests."""

    async def test_delete_returns_204(self, client) -> None:
        created = await _create_signature(client)
        resp = await client.delete(f"/api/v1/signatures/{created['id']}")
        assert resp.status_code == 204

    async def test_delete_removes_from_list(self, client) -> None:
        created = await _create_signature(client)
        await client.delete(f"/api/v1/signatures/{created['id']}")

        resp = await client.get(f"/api/v1/signatures/{created['id']}")
        assert resp.status_code == 404

        list_resp = await client.get("/api/v1/signatures")
        ids = [s["id"] for s in list_resp.json()]
        assert created["id"] not in ids

    async def test_delete_nonexistent_returns_404(self, client) -> None:
        resp = await client.delete("/api/v1/signatures/does-not-exist")
        assert resp.status_code == 404
