# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Scan API endpoints with DB persistence."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from malwar.api.auth import require_api_key  # noqa: F401 — kept for backward compat
from malwar.api.rbac import require_scan_create, require_scan_read
from malwar.core.config import Settings, get_settings
from malwar.detectors.llm_analyzer.detector import LlmAnalyzerDetector
from malwar.detectors.rule_engine.detector import RuleEngineDetector
from malwar.detectors.threat_intel.detector import ThreatIntelDetector
from malwar.detectors.url_crawler.detector import UrlCrawlerDetector
from malwar.models.scan import ScanResult
from malwar.notifications.events import NotificationEvent
from malwar.notifications.factory import build_router as build_notification_router
from malwar.notifications.webhook import WebhookNotifier
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


class BatchScanRequestBody(BaseModel):
    skills: list[ScanRequestBody]


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


async def _send_webhook(result: ScanResult, settings: Settings) -> None:
    """Fire webhook notifications for malicious/suspicious results."""
    urls = list(settings.webhook_urls)
    if settings.webhook_url:
        urls.append(settings.webhook_url)
    if not urls:
        return
    notifier = WebhookNotifier(
        urls=urls,
        secret=settings.webhook_secret,
        verdicts=settings.webhook_verdicts,
    )
    await notifier.notify(result)


async def _dispatch_notifications(result: ScanResult, settings: Settings) -> None:
    """Dispatch notifications via all configured channels."""
    try:
        notification_router = build_notification_router(settings)
        if not notification_router.channels:
            return
        event = NotificationEvent.from_scan_result(result)
        await notification_router.dispatch(event)
    except Exception:
        logger.exception("Failed to dispatch notifications for scan %s", result.scan_id)


async def _audit_scan(result: ScanResult, *, actor: str = "cli") -> None:
    """Fire audit events for a completed scan and its findings."""
    try:
        from malwar.audit.logger import get_audit_logger, hash_api_key

        audit = get_audit_logger()
        hashed_actor = hash_api_key(actor)

        await audit.log_scan_started(
            scan_id=result.scan_id,
            target=result.target,
            actor=hashed_actor,
            layers=result.layers_executed,
        )
        await audit.log_scan_completed(
            scan_id=result.scan_id,
            verdict=result.verdict,
            risk_score=result.risk_score,
            finding_count=len(result.findings),
            actor=hashed_actor,
            duration_ms=result.duration_ms,
        )
        for finding in result.findings:
            await audit.log_finding(
                scan_id=result.scan_id,
                rule_id=finding.rule_id,
                severity=finding.severity,
                actor=hashed_actor,
                title=finding.title,
            )
    except Exception:
        logger.exception("Failed to audit scan %s", result.scan_id)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=ScanResponseBody)
async def scan_skill(
    body: ScanRequestBody,
    _auth: object = Depends(require_scan_create),
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
    asyncio.create_task(_send_webhook(result, settings))  # noqa: RUF006
    asyncio.create_task(_dispatch_notifications(result, settings))  # noqa: RUF006

    # Audit logging
    actor = getattr(_auth, "key_id", "anonymous") if _auth else "anonymous"
    await _audit_scan(result, actor=actor)

    return _result_to_response(result)


@router.post("/scan/batch", response_model=list[ScanResponseBody])
async def scan_batch(
    body: BatchScanRequestBody,
    _auth: object = Depends(require_scan_create),
) -> list[ScanResponseBody]:
    """Submit a batch of SKILL.md files for scanning."""
    settings = get_settings()
    results: list[ScanResponseBody] = []

    for skill_request in body.skills:
        try:
            skill = parse_skill_content(
                skill_request.content, file_path=skill_request.file_name
            )
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Parse error for {skill_request.file_name}: {exc}",
            ) from exc

        layers = list(skill_request.layers)
        if not skill_request.use_llm and "llm_analyzer" in layers:
            layers.remove("llm_analyzer")

        pipeline = ScanPipeline(settings=settings)
        pipeline.register_detector(RuleEngineDetector())
        pipeline.register_detector(UrlCrawlerDetector())
        pipeline.register_detector(LlmAnalyzerDetector(settings=settings))
        pipeline.register_detector(ThreatIntelDetector())

        result = await pipeline.scan(skill, layers=layers)
        await _persist_result(result)
        asyncio.create_task(_send_webhook(result, settings))  # noqa: RUF006
        asyncio.create_task(_dispatch_notifications(result, settings))  # noqa: RUF006
        results.append(_result_to_response(result))

    return results


@router.get("/scan/{scan_id}", response_model=ScanResponseBody)
async def get_scan(
    scan_id: str,
    _auth: object = Depends(require_scan_read),
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

        from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
        from malwar.models.finding import Finding, Location

        result.findings = [
            Finding(
                id=str(row["id"]),
                rule_id=str(row["rule_id"]),
                title=str(row["title"]),
                description=str(row["description"]),
                severity=Severity(str(row["severity"])),
                confidence=float(row["confidence"]),
                category=ThreatCategory(str(row["category"])),
                detector_layer=DetectorLayer(str(row["detector_layer"])),
                location=Location(
                    line_start=int(row["line_start"]),
                    line_end=int(row["line_end"]) if row.get("line_end") else None,
                    snippet=str(row["snippet"]) if row.get("snippet") else "",
                ) if row.get("line_start") else None,
                evidence=json.loads(row.get("evidence") or "[]"),
                ioc_values=json.loads(row.get("ioc_values") or "[]"),
                remediation=str(row["remediation"]) if row.get("remediation") else "",
            )
            for row in finding_rows
        ]

    return _result_to_response(result)


@router.get("/scan/{scan_id}/sarif")
async def get_scan_sarif(
    scan_id: str,
    _auth: object = Depends(require_scan_read),
) -> dict:
    """Get SARIF 2.1.0 output for a scan."""
    import json

    response = await get_scan(scan_id)

    # Reconstruct a minimal ScanResult for the SARIF formatter
    from malwar.cli.formatters.sarif import format_sarif
    from malwar.core.constants import DetectorLayer, ScanStatus, Severity, ThreatCategory
    from malwar.models.finding import Finding, Location
    from malwar.models.scan import ScanResult as ScanResultModel

    result = ScanResultModel(
        scan_id=response.scan_id,
        target="",
        status=ScanStatus(response.status),
        skill_sha256="",
        findings=[
            Finding(
                id=f.id,
                rule_id=f.rule_id,
                title=f.title,
                description=f.description,
                severity=Severity(f.severity),
                confidence=f.confidence,
                category=ThreatCategory(f.category),
                detector_layer=DetectorLayer(f.detector_layer),
                evidence=f.evidence,
                location=Location(line_start=f.line_start) if f.line_start else None,
            )
            for f in response.findings
        ],
    )

    sarif_output: dict[str, object] = json.loads(format_sarif(result))
    return sarif_output


@router.get("/scans", response_model=list[ScanListItem])
async def list_scans(
    limit: int = 50,
    _auth: object = Depends(require_scan_read),
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
