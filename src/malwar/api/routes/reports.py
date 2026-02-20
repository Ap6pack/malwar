# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Reports API endpoints — scan results with enriched breakdowns."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from malwar.api.auth import require_api_key

logger = logging.getLogger("malwar.api.reports")

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ReportFinding(BaseModel):
    id: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    category: str
    detector_layer: str
    evidence: list[str]
    line_start: int | None = None
    remediation: str | None = None


class ReportListItem(BaseModel):
    scan_id: str
    target: str
    verdict: str | None
    risk_score: int | None
    overall_severity: str | None
    skill_name: str | None
    skill_author: str | None
    finding_count: int
    created_at: str | None
    duration_ms: int | None


class ReportDetail(BaseModel):
    scan_id: str
    target: str
    status: str
    verdict: str | None
    risk_score: int | None
    overall_severity: str | None
    skill_name: str | None
    skill_author: str | None
    created_at: str | None
    completed_at: str | None
    duration_ms: int | None
    layers_executed: list[str]
    finding_count: int
    findings: list[ReportFinding]
    severity_breakdown: dict[str, int]
    category_breakdown: dict[str, int]
    detector_breakdown: dict[str, int]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compute_breakdown(findings: list[dict], key: str) -> dict[str, int]:
    """Count occurrences of a given key across finding dicts."""
    counts: dict[str, int] = {}
    for f in findings:
        val = f.get(key, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/reports", response_model=list[ReportListItem])
async def list_reports(
    verdict: str | None = None,
    min_risk_score: int | None = None,
    limit: int = 50,
    _api_key: str = Depends(require_api_key),
) -> list[ReportListItem]:
    """List completed scans as reports with optional filtering."""
    from malwar.storage.database import get_db
    from malwar.storage.repositories.scans import ScanRepository

    db = await get_db()
    scan_repo = ScanRepository(db)
    rows = await scan_repo.list_recent(limit=limit)

    # Filter by verdict if specified
    if verdict is not None:
        verdict_upper = verdict.upper()
        rows = [r for r in rows if (r.get("verdict") or "").upper() == verdict_upper]

    # Filter by minimum risk score if specified
    if min_risk_score is not None:
        rows = [r for r in rows if (r.get("risk_score") or 0) >= min_risk_score]

    # Compute finding counts per scan
    results: list[ReportListItem] = []
    for row in rows:
        scan_id = row["id"]
        cursor = await db.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
        )
        count_row = await cursor.fetchone()
        finding_count = count_row[0] if count_row else 0

        results.append(
            ReportListItem(
                scan_id=scan_id,
                target=row["target"],
                verdict=row.get("verdict"),
                risk_score=row.get("risk_score"),
                overall_severity=row.get("overall_severity"),
                skill_name=row.get("skill_name"),
                skill_author=row.get("skill_author"),
                finding_count=finding_count,
                created_at=row.get("created_at"),
                duration_ms=row.get("duration_ms"),
            )
        )

    return results


@router.get("/reports/{scan_id}", response_model=ReportDetail)
async def get_report(
    scan_id: str,
    _api_key: str = Depends(require_api_key),
) -> ReportDetail:
    """Get a full report for a scan including findings and breakdowns."""
    from malwar.storage.database import get_db
    from malwar.storage.repositories.findings import FindingRepository

    db = await get_db()
    finding_repo = FindingRepository(db)

    # Read the raw scan row to preserve stored verdict/risk_score/severity
    # (ScanResult uses computed properties that recompute from findings=[])
    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    scan_row = dict(row)

    finding_rows = await finding_repo.get_by_scan(scan_id)

    # Build finding response objects
    findings = [
        ReportFinding(
            id=f["id"],
            rule_id=f["rule_id"],
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            confidence=f["confidence"],
            category=f["category"],
            detector_layer=f["detector_layer"],
            evidence=json.loads(f.get("evidence") or "[]"),
            line_start=f.get("line_start"),
            remediation=f.get("remediation"),
        )
        for f in finding_rows
    ]

    # Compute breakdowns from raw finding rows
    severity_breakdown = _compute_breakdown(finding_rows, "severity")
    category_breakdown = _compute_breakdown(finding_rows, "category")
    detector_breakdown = _compute_breakdown(finding_rows, "detector_layer")

    return ReportDetail(
        scan_id=scan_row["id"],
        target=scan_row["target"],
        status=scan_row["status"],
        verdict=scan_row.get("verdict"),
        risk_score=scan_row.get("risk_score"),
        overall_severity=scan_row.get("overall_severity"),
        skill_name=scan_row.get("skill_name"),
        skill_author=scan_row.get("skill_author"),
        created_at=scan_row.get("created_at"),
        completed_at=scan_row.get("completed_at"),
        duration_ms=scan_row.get("duration_ms"),
        layers_executed=json.loads(scan_row.get("layers_executed") or "[]"),
        finding_count=len(findings),
        findings=findings,
        severity_breakdown=severity_breakdown,
        category_breakdown=category_breakdown,
        detector_breakdown=detector_breakdown,
    )
