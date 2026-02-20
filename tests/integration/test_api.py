# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the FastAPI API endpoints."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "skills"
BENIGN_DIR = FIXTURES_DIR / "benign"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a FastAPI app with a temporary database."""
    db_path = tmp_path / "test_malwar.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app):
    """Provide an async HTTP client bound to the test app."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# 1. GET /api/v1/health returns 200
# ---------------------------------------------------------------------------
class TestHealthEndpoint:
    """Health check endpoint tests."""

    async def test_health_returns_200(self, client) -> None:
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200

    async def test_health_response_body(self, client) -> None:
        resp = await client.get("/api/v1/health")
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "malwar"
        assert data["version"] == "0.1.0"


# ---------------------------------------------------------------------------
# 2. POST /api/v1/scan with malicious content returns MALICIOUS
# ---------------------------------------------------------------------------
class TestScanMalicious:
    """Scan endpoint with malicious SKILL.md content."""

    async def test_malicious_prompt_injection(self, client) -> None:
        content = (MALICIOUS_DIR / "prompt_injection_basic.md").read_text()

        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "prompt_injection_basic.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "MALICIOUS"
        assert data["risk_score"] >= 75
        assert data["finding_count"] > 0
        assert any(
            f["rule_id"] == "MALWAR-PI-001" for f in data["findings"]
        )

    async def test_malicious_base64_reverse_shell(self, client) -> None:
        content = (MALICIOUS_DIR / "base64_reverse_shell.md").read_text()

        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "base64_reverse_shell.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "MALICIOUS"
        assert data["risk_score"] >= 75
        assert any(
            f["rule_id"] == "MALWAR-OBF-001" for f in data["findings"]
        )

    async def test_malicious_credential_harvester(self, client) -> None:
        content = (MALICIOUS_DIR / "credential_harvester.md").read_text()

        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "credential_harvester.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "MALICIOUS"
        assert data["finding_count"] > 0


# ---------------------------------------------------------------------------
# 3. POST /api/v1/scan with benign content returns CLEAN
# ---------------------------------------------------------------------------
class TestScanBenign:
    """Scan endpoint with benign SKILL.md content."""

    async def test_benign_hello_world(self, client) -> None:
        content = (BENIGN_DIR / "hello_world.md").read_text()

        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "hello_world.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "CLEAN"
        assert data["risk_score"] == 0
        assert data["finding_count"] == 0
        assert data["findings"] == []

    async def test_benign_code_formatter(self, client) -> None:
        content = (BENIGN_DIR / "code_formatter.md").read_text()

        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "code_formatter.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "CLEAN"
        assert data["risk_score"] == 0

    async def test_scan_response_structure(self, client) -> None:
        """Verify the full response structure matches ScanResponseBody."""
        content = (BENIGN_DIR / "hello_world.md").read_text()

        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "hello_world.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()

        # Verify all expected fields are present
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
        assert required_fields.issubset(set(data.keys()))
        assert data["status"] == "completed"
        assert data["skill_name"] == "Hello World"
        assert data["skill_author"] == "Jane Smith"


# ---------------------------------------------------------------------------
# 4. POST /api/v1/scan with invalid content returns appropriate response
# ---------------------------------------------------------------------------
class TestScanInvalid:
    """Scan endpoint with invalid or edge-case inputs."""

    async def test_empty_body_returns_422(self, client) -> None:
        """Missing required 'content' field returns 422."""
        resp = await client.post("/api/v1/scan", json={})
        assert resp.status_code == 422

    async def test_missing_content_type_returns_422(self, client) -> None:
        """Sending non-JSON body returns 422."""
        resp = await client.post(
            "/api/v1/scan",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    async def test_minimal_content_is_accepted(self, client) -> None:
        """Plain text without frontmatter should still be scannable."""
        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": "# Simple Skill\n\nJust some text.",
                "layers": ["rule_engine"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "CLEAN"

    async def test_scan_with_no_layers_uses_defaults(self, client) -> None:
        """When layers list is provided, only those layers run."""
        content = (BENIGN_DIR / "hello_world.md").read_text()

        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "hello_world.md",
                "layers": ["rule_engine"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
