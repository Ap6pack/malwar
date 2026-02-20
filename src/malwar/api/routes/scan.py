# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Scan API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from malwar.core.config import get_settings
from malwar.detectors.llm_analyzer.detector import LlmAnalyzerDetector
from malwar.detectors.rule_engine.detector import RuleEngineDetector
from malwar.detectors.threat_intel.detector import ThreatIntelDetector
from malwar.detectors.url_crawler.detector import UrlCrawlerDetector
from malwar.models.scan import ScanResult
from malwar.parsers.skill_parser import parse_skill_content
from malwar.scanner.pipeline import ScanPipeline

router = APIRouter()


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


@router.post("/scan", response_model=ScanResponseBody)
async def scan_skill(body: ScanRequestBody) -> ScanResponseBody:
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
    return _result_to_response(result)
