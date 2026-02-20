# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Scan API endpoints with DB persistence."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from malwar.api.auth import require_api_key
from malwar.core.config import get_settings
from malwar.detectors.llm_analyzer.detector import LlmAnalyzerDetector
from malwar.detectors.rule_engine.detector import RuleEngineDetector
from malwar.detectors.threat_intel.detector import ThreatIntelDetector
from malwar.detectors.url_crawler.detector import UrlCrawlerDetector
from malwar.models.scan import ScanResult
from malwar.parsers.skill_parser import parse_skill_content
from malwar.scanner.pipeline import ScanPipeline

logger = logging.getLogger("malwar.api.scan")

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanRequestBody(BaseModel):
    content: str = Field(description="Raw SKILL.md content")
    file_name: str = Field(default="SKILL.md")
    layers: list[str] = Field(
        default=["rule_engine", "url_crawler", "llm_analyzer", "threat_intel"]
    )
    use_llm: bool = True


class FindingResponse(BaseModel):
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


class ScanResponseBody(BaseModel):
    scan_id: str
    status: str
    verdict: str
    risk_score: int
    overall_severity: str
    finding_count: int
    finding_count_by_severity: dict[str, int]
    findings: list[FindingResponse]
    skill_name: str | None
    skill_author: str | None
    duration_ms: int | None


class ScanListItem(BaseModel):
    scan_id: str
    target: str
    verdict: str | None
    risk_score: int | None
    status: str
    skill_name: str | None
    created_at: str | None
    duration_ms: int | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result_to_response(result: ScanResult) -> ScanResponseBody:
    return ScanResponseBody(
        scan_id=result.scan_id,
        status=result.status,
        verdict=result.verdict,
        risk_score=result.risk_score,
        overall_severity=result.overall_severity,
        finding_count=len(result.findings),
        finding_count_by_severity=result.finding_count_by_severity,
        findings=[
            FindingResponse(
                id=f.id,
                rule_id=f.rule_id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                confidence=f.confidence,
                category=f.category,
                detector_layer=f.detector_layer,
                evidence=f.evidence,
                line_start=f.location.line_start if f.location else None,
            )
            for f in result.findings
        ],
        skill_name=result.skill_name,
        skill_author=result.skill_author,
        duration_ms=result.duration_ms,
    )


async def _persist_result(result: ScanResult) -> None:
    """Store scan result and findings in the database."""
    try:
        from malwar.storage.database import get_db
        from malwar.storage.repositories.findings import FindingRepository
        from malwar.storage.repositories.scans import ScanRepository

        db = await get_db()
        scan_repo = ScanRepository(db)
        finding_repo = FindingRepository(db)

        await scan_repo.create(result)
        if result.findings:
            await finding_repo.create_many(result.scan_id, result.findings)
    except Exception:
        logger.exception("Failed to persist scan %s", result.scan_id)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=ScanResponseBody)
async def scan_skill(
    body: ScanRequestBody,
    _api_key: str = Depends(require_api_key),
) -> ScanResponseBody:
    """Submit a SKILL.md for scanning."""
    settings = get_settings()

    try:
        skill = parse_skill_content(body.content, file_path=body.file_name)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Parse error: {exc}") from exc

    layers = list(body.layers)
    if not body.use_llm and "llm_analyzer" in layers:
        layers.remove("llm_analyzer")

    pipeline = ScanPipeline(settings=settings)
    pipeline.register_detector(RuleEngineDetector())
    pipeline.register_detector(UrlCrawlerDetector())
    pipeline.register_detector(LlmAnalyzerDetector(settings=settings))
    pipeline.register_detector(ThreatIntelDetector())

    result = await pipeline.scan(skill, layers=layers)

    await _persist_result(result)

    return _result_to_response(result)


@router.get("/scan/{scan_id}", response_model=ScanResponseBody)
async def get_scan(
    scan_id: str,
    _api_key: str = Depends(require_api_key),
) -> ScanResponseBody:
    """Retrieve a scan result by ID."""
    from malwar.storage.database import get_db
    from malwar.storage.repositories.findings import FindingRepository
    from malwar.storage.repositories.scans import ScanRepository

    db = await get_db()
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)

    result = await scan_repo.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    # Hydrate findings
    finding_rows = await finding_repo.get_by_scan(scan_id)
    if finding_rows:
        import json

        from malwar.models.finding import Finding, Location

        result.findings = [
            Finding(
                id=row["id"],
                rule_id=row["rule_id"],
                title=row["title"],
                description=row["description"],
                severity=row["severity"],
                confidence=row["confidence"],
                category=row["category"],
                detector_layer=row["detector_layer"],
                location=Location(
                    line_start=row["line_start"],
                    line_end=row.get("line_end"),
                    snippet=row.get("snippet"),
                ) if row.get("line_start") else None,
                evidence=json.loads(row.get("evidence") or "[]"),
                ioc_values=json.loads(row.get("ioc_values") or "[]"),
                remediation=row.get("remediation"),
            )
            for row in finding_rows
        ]

    return _result_to_response(result)


@router.get("/scan/{scan_id}/sarif")
async def get_scan_sarif(
    scan_id: str,
    _api_key: str = Depends(require_api_key),
) -> dict:
    """Get SARIF 2.1.0 output for a scan."""
    import json

    response = await get_scan(scan_id)

    # Reconstruct a minimal ScanResult for the SARIF formatter
    from malwar.cli.formatters.sarif import format_sarif
    from malwar.models.finding import Finding, Location
    from malwar.models.scan import ScanResult as ScanResultModel

    result = ScanResultModel(
        scan_id=response.scan_id,
        target="",
        status=response.status,
        skill_sha256="",
        findings=[
            Finding(
                id=f.id,
                rule_id=f.rule_id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                confidence=f.confidence,
                category=f.category,
                detector_layer=f.detector_layer,
                evidence=f.evidence,
                location=Location(line_start=f.line_start) if f.line_start else None,
            )
            for f in response.findings
        ],
    )

    return json.loads(format_sarif(result))


@router.get("/scans", response_model=list[ScanListItem])
async def list_scans(
    limit: int = 50,
    _api_key: str = Depends(require_api_key),
) -> list[ScanListItem]:
    """List recent scans."""
    from malwar.storage.database import get_db
    from malwar.storage.repositories.scans import ScanRepository

    db = await get_db()
    scan_repo = ScanRepository(db)
    rows = await scan_repo.list_recent(limit=limit)

    return [
        ScanListItem(
            scan_id=row["id"],
            target=row["target"],
            verdict=row.get("verdict"),
            risk_score=row.get("risk_score"),
            status=row["status"],
            skill_name=row.get("skill_name"),
            created_at=row.get("created_at"),
            duration_ms=row.get("duration_ms"),
        )
        for row in rows
    ]
