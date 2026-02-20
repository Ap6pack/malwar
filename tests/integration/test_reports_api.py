# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the Reports API endpoints."""

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
    db_path = tmp_path / "test_reports.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    """Provide an async HTTP client bound to the test app, with DB initialized."""
    db_path = tmp_path / "test_reports.db"
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


async def _submit_scan(
    client: AsyncClient,
    *,
    malicious: bool = False,
    file_name: str | None = None,
) -> dict:
    """Submit a scan and return the response JSON."""
    if malicious:
        content = (MALICIOUS_DIR / "prompt_injection_basic.md").read_text()
        file_name = file_name or "prompt_injection_basic.md"
    else:
        content = (BENIGN_DIR / "hello_world.md").read_text()
        file_name = file_name or "hello_world.md"

    resp = await client.post(
        "/api/v1/scan",
        json={
            "content": content,
            "file_name": file_name,
            "layers": ["rule_engine"],
            "use_llm": False,
        },
    )
    assert resp.status_code == 200
    return resp.json()


# ---------------------------------------------------------------------------
# 1. List reports (empty) -> 200, empty list
# ---------------------------------------------------------------------------
class TestListReportsEmpty:
    async def test_list_reports_empty(self, client) -> None:
        resp = await client.get("/api/v1/reports")
        assert resp.status_code == 200
        assert resp.json() == []


# ---------------------------------------------------------------------------
# 2. Submit a scan, then list reports -> the scan appears
# ---------------------------------------------------------------------------
class TestListReportsAfterScan:
    async def test_scan_appears_in_reports(self, client) -> None:
        scan_data = await _submit_scan(client)
        scan_id = scan_data["scan_id"]

        resp = await client.get("/api/v1/reports")
        assert resp.status_code == 200
        reports = resp.json()
        assert len(reports) >= 1
        assert any(r["scan_id"] == scan_id for r in reports)


# ---------------------------------------------------------------------------
# 3. Filter by verdict -> only matching scans returned
# ---------------------------------------------------------------------------
class TestFilterByVerdict:
    async def test_filter_verdict_malicious(self, client) -> None:
        # Submit one malicious and one benign scan
        mal = await _submit_scan(client, malicious=True)
        await _submit_scan(client, malicious=False)

        resp = await client.get("/api/v1/reports?verdict=MALICIOUS")
        assert resp.status_code == 200
        reports = resp.json()
        assert any(r["scan_id"] == mal["scan_id"] for r in reports)
        assert all(
            (r.get("verdict") or "").upper() == "MALICIOUS" for r in reports
        )

    async def test_filter_verdict_clean(self, client) -> None:
        await _submit_scan(client, malicious=True)
        ben = await _submit_scan(client, malicious=False)

        resp = await client.get("/api/v1/reports?verdict=CLEAN")
        assert resp.status_code == 200
        reports = resp.json()
        assert any(r["scan_id"] == ben["scan_id"] for r in reports)
        assert all(
            (r.get("verdict") or "").upper() == "CLEAN" for r in reports
        )


# ---------------------------------------------------------------------------
# 4. Filter by min_risk_score -> only matching scans returned
# ---------------------------------------------------------------------------
class TestFilterByMinRiskScore:
    async def test_filter_min_risk_score(self, client) -> None:
        mal = await _submit_scan(client, malicious=True)
        await _submit_scan(client, malicious=False)

        # Malicious scans have high risk; benign have 0
        resp = await client.get("/api/v1/reports?min_risk_score=50")
        assert resp.status_code == 200
        reports = resp.json()
        # Should include malicious scan
        assert any(r["scan_id"] == mal["scan_id"] for r in reports)
        # All returned scans must meet the threshold
        assert all(
            (r.get("risk_score") or 0) >= 50 for r in reports
        )

    async def test_filter_min_risk_score_zero_returns_all(self, client) -> None:
        await _submit_scan(client, malicious=True)
        await _submit_scan(client, malicious=False)

        resp = await client.get("/api/v1/reports?min_risk_score=0")
        assert resp.status_code == 200
        reports = resp.json()
        assert len(reports) >= 2


# ---------------------------------------------------------------------------
# 5. Get report by scan_id -> includes breakdowns
# ---------------------------------------------------------------------------
class TestGetReportDetail:
    async def test_report_includes_breakdowns(self, client) -> None:
        scan_data = await _submit_scan(client, malicious=True)
        scan_id = scan_data["scan_id"]

        resp = await client.get(f"/api/v1/reports/{scan_id}")
        assert resp.status_code == 200
        report = resp.json()

        assert report["scan_id"] == scan_id
        assert report["verdict"] == "MALICIOUS"
        assert report["finding_count"] > 0
        assert len(report["findings"]) == report["finding_count"]

        # Breakdowns must be present and non-empty for malicious scan
        assert isinstance(report["severity_breakdown"], dict)
        assert len(report["severity_breakdown"]) > 0
        assert isinstance(report["category_breakdown"], dict)
        assert len(report["category_breakdown"]) > 0
        assert isinstance(report["detector_breakdown"], dict)
        assert len(report["detector_breakdown"]) > 0

    async def test_report_breakdown_counts_match_findings(self, client) -> None:
        scan_data = await _submit_scan(client, malicious=True)
        scan_id = scan_data["scan_id"]

        resp = await client.get(f"/api/v1/reports/{scan_id}")
        report = resp.json()

        # Sum of severity breakdown should equal finding count
        total_severity = sum(report["severity_breakdown"].values())
        assert total_severity == report["finding_count"]

        # Sum of category breakdown should equal finding count
        total_category = sum(report["category_breakdown"].values())
        assert total_category == report["finding_count"]

        # Sum of detector breakdown should equal finding count
        total_detector = sum(report["detector_breakdown"].values())
        assert total_detector == report["finding_count"]

    async def test_clean_report_has_empty_breakdowns(self, client) -> None:
        scan_data = await _submit_scan(client, malicious=False)
        scan_id = scan_data["scan_id"]

        resp = await client.get(f"/api/v1/reports/{scan_id}")
        assert resp.status_code == 200
        report = resp.json()

        assert report["finding_count"] == 0
        assert report["severity_breakdown"] == {}
        assert report["category_breakdown"] == {}
        assert report["detector_breakdown"] == {}


# ---------------------------------------------------------------------------
# 6. Get report for non-existent scan -> 404
# ---------------------------------------------------------------------------
class TestGetReportNotFound:
    async def test_report_not_found(self, client) -> None:
        resp = await client.get("/api/v1/reports/does-not-exist")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 7. Middleware: X-Request-ID header is present
# ---------------------------------------------------------------------------
class TestMiddleware:
    async def test_request_id_header_present(self, client) -> None:
        resp = await client.get("/api/v1/reports")
        assert "X-Request-ID" in resp.headers
        assert len(resp.headers["X-Request-ID"]) > 0
