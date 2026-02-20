# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the FastAPI API endpoints."""

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
    db_path = tmp_path / "test_malwar.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    """Provide an async HTTP client bound to the test app, with DB initialized."""
    db_path = tmp_path / "test_malwar.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


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


# ---------------------------------------------------------------------------
# 5. GET /api/v1/scan/{scan_id} retrieves a persisted scan
# ---------------------------------------------------------------------------
class TestGetScan:
    """Scan retrieval endpoint tests."""

    async def _submit_scan(self, client) -> str:
        """Helper: submit a scan and return its scan_id."""
        content = (MALICIOUS_DIR / "prompt_injection_basic.md").read_text()
        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "prompt_injection_basic.md",
                "layers": ["rule_engine"],
                "use_llm": False,
            },
        )
        assert resp.status_code == 200
        return resp.json()["scan_id"]

    async def test_get_scan_by_id(self, client) -> None:
        scan_id = await self._submit_scan(client)
        resp = await client.get(f"/api/v1/scan/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["verdict"] == "MALICIOUS"
        assert data["finding_count"] > 0

    async def test_get_scan_findings_hydrated(self, client) -> None:
        scan_id = await self._submit_scan(client)
        resp = await client.get(f"/api/v1/scan/{scan_id}")
        data = resp.json()
        assert len(data["findings"]) == data["finding_count"]
        for f in data["findings"]:
            assert "rule_id" in f
            assert "severity" in f
            assert "detector_layer" in f

    async def test_get_scan_not_found(self, client) -> None:
        resp = await client.get("/api/v1/scan/does-not-exist")
        assert resp.status_code == 404

    async def test_get_scan_sarif(self, client) -> None:
        scan_id = await self._submit_scan(client)
        resp = await client.get(f"/api/v1/scan/{scan_id}/sarif")
        assert resp.status_code == 200
        data = resp.json()
        assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) > 0


# ---------------------------------------------------------------------------
# 6. GET /api/v1/scans lists recent scans
# ---------------------------------------------------------------------------
class TestListScans:
    """Scan list endpoint tests."""

    async def test_list_scans_empty(self, client) -> None:
        resp = await client.get("/api/v1/scans")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_scans_after_submission(self, client) -> None:
        content = (BENIGN_DIR / "hello_world.md").read_text()
        submit = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "hello_world.md",
                "layers": ["rule_engine"],
                "use_llm": False,
            },
        )
        scan_id = submit.json()["scan_id"]

        resp = await client.get("/api/v1/scans")
        assert resp.status_code == 200
        scans = resp.json()
        assert len(scans) >= 1
        assert any(s["scan_id"] == scan_id for s in scans)

    async def test_list_scans_limit(self, client) -> None:
        # Submit 3 scans
        content = (BENIGN_DIR / "hello_world.md").read_text()
        for _ in range(3):
            await client.post(
                "/api/v1/scan",
                json={
                    "content": content,
                    "layers": ["rule_engine"],
                    "use_llm": False,
                },
            )
        resp = await client.get("/api/v1/scans?limit=2")
        assert resp.status_code == 200
        assert len(resp.json()) == 2


# ---------------------------------------------------------------------------
# 7. API key authentication
# ---------------------------------------------------------------------------
class TestAuth:
    """API key authentication tests."""

    @pytest.fixture
    def auth_app(self, tmp_path, monkeypatch):
        """App with API key auth enabled."""
        db_path = tmp_path / "test_auth.db"
        monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
        monkeypatch.setenv("MALWAR_API_KEYS", '["valid-key-1","valid-key-2"]')
        return create_app()

    @pytest.fixture
    async def auth_client(self, auth_app, tmp_path):
        db_path = tmp_path / "test_auth.db"
        await init_db(db_path)
        try:
            async with AsyncClient(
                transport=ASGITransport(app=auth_app), base_url="http://test"
            ) as ac:
                yield ac
        finally:
            await close_db()

    async def test_no_key_returns_401(self, auth_client) -> None:
        resp = await auth_client.get("/api/v1/scans")
        assert resp.status_code == 401

    async def test_wrong_key_returns_403(self, auth_client) -> None:
        resp = await auth_client.get(
            "/api/v1/scans", headers={"X-API-Key": "wrong"}
        )
        assert resp.status_code == 403

    async def test_valid_key_returns_200(self, auth_client) -> None:
        resp = await auth_client.get(
            "/api/v1/scans", headers={"X-API-Key": "valid-key-1"}
        )
        assert resp.status_code == 200

    async def test_second_valid_key_works(self, auth_client) -> None:
        resp = await auth_client.get(
            "/api/v1/scans", headers={"X-API-Key": "valid-key-2"}
        )
        assert resp.status_code == 200

    async def test_health_requires_no_auth(self, auth_client) -> None:
        """Health endpoint should work without auth."""
        resp = await auth_client.get("/api/v1/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 8. Rate limiting
# ---------------------------------------------------------------------------
class TestRateLimit:
    """Rate-limit middleware tests."""

    @pytest.fixture
    def rl_app(self, tmp_path, monkeypatch):
        """App with rate limit set to 2 requests per minute."""
        db_path = tmp_path / "test_rl.db"
        monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
        monkeypatch.setenv("MALWAR_RATE_LIMIT_RPM", "2")
        monkeypatch.setenv("MALWAR_RATE_LIMIT_PER_IP", "2")
        # Clear any leftover rate-limit state from other tests
        from malwar.api.middleware import _request_log

        _request_log.clear()
        return create_app()

    @pytest.fixture
    async def rl_client(self, rl_app, tmp_path):
        db_path = tmp_path / "test_rl.db"
        await init_db(db_path)
        try:
            async with AsyncClient(
                transport=ASGITransport(app=rl_app), base_url="http://test"
            ) as ac:
                yield ac
        finally:
            await close_db()

    async def test_rate_limit_returns_429(self, rl_client) -> None:
        """Third request within the window should be rejected with 429."""
        resp1 = await rl_client.get("/api/v1/scans")
        assert resp1.status_code == 200

        resp2 = await rl_client.get("/api/v1/scans")
        assert resp2.status_code == 200

        resp3 = await rl_client.get("/api/v1/scans")
        assert resp3.status_code == 429
        assert "Retry-After" in resp3.headers
