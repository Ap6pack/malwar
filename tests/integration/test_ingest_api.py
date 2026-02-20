# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the POST /api/v1/ingest endpoint."""

from __future__ import annotations

import json
import textwrap

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.storage.database import close_db, init_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a FastAPI app with a temporary database."""
    db_path = tmp_path / "test_ingest.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    # No API keys configured = auth disabled (open access for tests)
    monkeypatch.delenv("MALWAR_API_KEYS", raising=False)
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    """Provide an async HTTP client bound to the test app, with DB initialized."""
    db_path = tmp_path / "test_ingest.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


SAMPLE_JSON_PAYLOAD = json.dumps(
    {
        "campaigns": [
            {
                "name": "APICampaign",
                "attributed_to": "API-Actor",
                "first_seen": "2026-02-01",
                "iocs": [
                    {"type": "domain", "value": "api-evil.com"},
                    {"type": "ip", "value": "172.16.0.1"},
                ],
                "signatures": [
                    {
                        "pattern_type": "exact",
                        "pattern_value": "api-evil.com",
                        "ioc_type": "domain",
                        "severity": "critical",
                    },
                ],
            }
        ]
    }
)

SAMPLE_CSV_PAYLOAD = textwrap.dedent("""\
    campaign,ioc_type,ioc_value,severity
    CSVApiCampaign,domain,csv-evil.com,high
    CSVApiCampaign,ip,10.10.10.10,medium
""")

SAMPLE_STIX_PAYLOAD = json.dumps(
    {
        "type": "bundle",
        "id": "bundle--api-test-001",
        "objects": [
            {
                "type": "campaign",
                "spec_version": "2.1",
                "id": "campaign--api-test-001",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "name": "StixApiCampaign",
                "first_seen": "2026-01-15T00:00:00.000Z",
                "last_seen": "2026-02-01T00:00:00.000Z",
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--api-test-001",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "name": "STIX Indicator",
                "indicator_types": ["malicious-activity"],
                "pattern": "[domain-name:value = 'stix-api-evil.com']",
                "pattern_type": "stix",
                "valid_from": "2026-01-15T00:00:00.000Z",
                "labels": ["severity:critical"],
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--api-test-ind",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "relationship_type": "indicates",
                "source_ref": "indicator--api-test-001",
                "target_ref": "campaign--api-test-001",
            },
        ],
    }
)


# =========================================================================
# POST /api/v1/ingest tests
# =========================================================================


class TestIngestEndpoint:
    """Tests for the ingest API endpoint."""

    async def test_ingest_json_returns_200(self, client) -> None:
        resp = await client.post(
            "/api/v1/ingest",
            json={"source_type": "json", "data": SAMPLE_JSON_PAYLOAD},
        )
        assert resp.status_code == 200

    async def test_ingest_json_returns_result(self, client) -> None:
        resp = await client.post(
            "/api/v1/ingest",
            json={"source_type": "json", "data": SAMPLE_JSON_PAYLOAD},
        )
        data = resp.json()
        assert data["campaigns_added"] == 1
        assert data["signatures_added"] == 1
        assert data["errors"] == []

    async def test_ingest_csv_returns_200(self, client) -> None:
        resp = await client.post(
            "/api/v1/ingest",
            json={"source_type": "csv", "data": SAMPLE_CSV_PAYLOAD},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["campaigns_added"] == 1
        assert data["signatures_added"] == 2

    async def test_ingest_stix_returns_200(self, client) -> None:
        resp = await client.post(
            "/api/v1/ingest",
            json={"source_type": "stix", "data": SAMPLE_STIX_PAYLOAD},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["campaigns_added"] == 1
        assert data["signatures_added"] == 1

    async def test_ingest_invalid_source_type_returns_422(self, client) -> None:
        resp = await client.post(
            "/api/v1/ingest",
            json={"source_type": "xml", "data": "<bad/>"},
        )
        assert resp.status_code == 422

    async def test_ingest_invalid_json_data_returns_422(self, client) -> None:
        resp = await client.post(
            "/api/v1/ingest",
            json={"source_type": "json", "data": "not valid json"},
        )
        assert resp.status_code == 422

    async def test_ingest_empty_data_returns_422(self, client) -> None:
        resp = await client.post(
            "/api/v1/ingest",
            json={"source_type": "json", "data": ""},
        )
        assert resp.status_code == 422


class TestIngestDuplication:
    """Tests for duplicate handling through the API."""

    async def test_duplicate_import_skips_signatures(self, client) -> None:
        # First import
        resp1 = await client.post(
            "/api/v1/ingest",
            json={"source_type": "json", "data": SAMPLE_JSON_PAYLOAD},
        )
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["campaigns_added"] == 1

        # Second identical import
        resp2 = await client.post(
            "/api/v1/ingest",
            json={"source_type": "json", "data": SAMPLE_JSON_PAYLOAD},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["campaigns_added"] == 0
        assert data2["campaigns_updated"] == 1
        assert data2["signatures_skipped"] == 1


class TestIngestAuth:
    """Tests that the ingest endpoint requires API key auth when configured."""

    async def test_ingest_requires_api_key_when_configured(
        self, tmp_path, monkeypatch
    ) -> None:
        db_path = tmp_path / "test_ingest_auth.db"
        monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
        monkeypatch.setenv("MALWAR_API_KEYS", '["secret-key-123"]')

        app = create_app()
        await init_db(db_path)

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                # Without API key
                resp = await ac.post(
                    "/api/v1/ingest",
                    json={"source_type": "json", "data": SAMPLE_JSON_PAYLOAD},
                )
                assert resp.status_code == 401

                # With valid API key
                resp = await ac.post(
                    "/api/v1/ingest",
                    json={"source_type": "json", "data": SAMPLE_JSON_PAYLOAD},
                    headers={"X-API-Key": "secret-key-123"},
                )
                assert resp.status_code == 200

                # With invalid API key
                resp = await ac.post(
                    "/api/v1/ingest",
                    json={"source_type": "json", "data": SAMPLE_JSON_PAYLOAD},
                    headers={"X-API-Key": "wrong-key"},
                )
                assert resp.status_code == 403
        finally:
            await close_db()
