# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the batch scan API endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.storage.database import close_db, init_db

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "skills"
BENIGN_DIR = FIXTURES_DIR / "benign"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a FastAPI app with a temporary database."""
    db_path = tmp_path / "test_batch.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    """Provide an async HTTP client bound to the test app, with DB initialized."""
    db_path = tmp_path / "test_batch.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


# ---------------------------------------------------------------------------
# POST /api/v1/scan/batch
# ---------------------------------------------------------------------------
class TestBatchScan:
    """Batch scan endpoint tests."""

    async def test_batch_scan_mixed_results(self, client) -> None:
        """Submit 1 malicious + 1 benign skill, verify array of 2 results."""
        malicious_content = (MALICIOUS_DIR / "prompt_injection_basic.md").read_text()
        benign_content = (BENIGN_DIR / "hello_world.md").read_text()

        resp = await client.post(
            "/api/v1/scan/batch",
            json={
                "skills": [
                    {
                        "content": malicious_content,
                        "file_name": "prompt_injection_basic.md",
                        "layers": ["rule_engine", "threat_intel"],
                        "use_llm": False,
                    },
                    {
                        "content": benign_content,
                        "file_name": "hello_world.md",
                        "layers": ["rule_engine", "threat_intel"],
                        "use_llm": False,
                    },
                ]
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 2

        # First result should be malicious
        assert data[0]["verdict"] == "MALICIOUS"
        assert data[0]["finding_count"] > 0

        # Second result should be clean
        assert data[1]["verdict"] == "CLEAN"
        assert data[1]["finding_count"] == 0

    async def test_batch_scan_empty_list(self, client) -> None:
        """Submit an empty batch, should return empty list."""
        resp = await client.post(
            "/api/v1/scan/batch",
            json={"skills": []},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data == []

    async def test_batch_scan_all_persisted(self, client) -> None:
        """Each scan in a batch should be persisted and retrievable."""
        benign_content = (BENIGN_DIR / "hello_world.md").read_text()

        resp = await client.post(
            "/api/v1/scan/batch",
            json={
                "skills": [
                    {
                        "content": benign_content,
                        "file_name": "hello_world.md",
                        "layers": ["rule_engine"],
                        "use_llm": False,
                    },
                    {
                        "content": benign_content,
                        "file_name": "hello_world.md",
                        "layers": ["rule_engine"],
                        "use_llm": False,
                    },
                ]
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

        # Verify each scan is retrievable individually
        for result in data:
            get_resp = await client.get(f"/api/v1/scan/{result['scan_id']}")
            assert get_resp.status_code == 200

    async def test_batch_scan_response_structure(self, client) -> None:
        """Each item in the batch response should match ScanResponseBody."""
        benign_content = (BENIGN_DIR / "hello_world.md").read_text()

        resp = await client.post(
            "/api/v1/scan/batch",
            json={
                "skills": [
                    {
                        "content": benign_content,
                        "layers": ["rule_engine"],
                        "use_llm": False,
                    },
                ]
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        result = data[0]

        required_fields = {
            "scan_id",
            "status",
            "verdict",
            "risk_score",
            "overall_severity",
            "finding_count",
            "finding_count_by_severity",
            "findings",
            "skill_name",
            "skill_author",
            "duration_ms",
        }
        assert required_fields.issubset(set(result.keys()))
