# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Diff scanning API endpoint — compare two versions of a skill."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from malwar.api.auth import require_api_key
from malwar.scanner.diff import DiffResult, diff_scan

logger = logging.getLogger("malwar.api.diff")

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class DiffRequestBody(BaseModel):
    """Request body for the diff scan endpoint."""

    old_content: str = Field(description="Raw SKILL.md content (old version)")
    new_content: str = Field(description="Raw SKILL.md content (new version)")
    file_name: str = Field(default="SKILL.md")
    layers: list[str] | None = Field(default=None)
    use_llm: bool = True


class DiffFindingResponse(BaseModel):
    """A single finding in the diff response."""

    rule_id: str
    title: str
    severity: str
    confidence: float
    category: str
    detector_layer: str
    evidence: list[str]


class DiffResponseBody(BaseModel):
    """Response body for the diff scan endpoint."""

    verdict_changed: bool
    old_verdict: str
    new_verdict: str
    risk_delta: int
    old_risk_score: int
    new_risk_score: int
    new_findings: list[DiffFindingResponse]
    removed_findings: list[DiffFindingResponse]
    unchanged_findings: list[DiffFindingResponse]
    old_scan_id: str
    new_scan_id: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_to_response(f) -> DiffFindingResponse:
    return DiffFindingResponse(
        rule_id=f.rule_id,
        title=f.title,
        severity=str(f.severity),
        confidence=f.confidence,
        category=str(f.category),
        detector_layer=str(f.detector_layer),
        evidence=f.evidence,
    )


def _result_to_response(result: DiffResult) -> DiffResponseBody:
    return DiffResponseBody(
        verdict_changed=result.verdict_changed,
        old_verdict=result.old_verdict,
        new_verdict=result.new_verdict,
        risk_delta=result.risk_delta,
        old_risk_score=result.old_scan.risk_score,
        new_risk_score=result.new_scan.risk_score,
        new_findings=[_finding_to_response(f) for f in result.new_findings],
        removed_findings=[
            _finding_to_response(f) for f in result.removed_findings
        ],
        unchanged_findings=[
            _finding_to_response(f) for f in result.unchanged_findings
        ],
        old_scan_id=result.old_scan.scan_id,
        new_scan_id=result.new_scan.scan_id,
    )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post("/scan/diff", response_model=DiffResponseBody)
async def scan_diff(
    body: DiffRequestBody,
    _api_key: str = Depends(require_api_key),
) -> DiffResponseBody:
    """Compare two versions of a SKILL.md and return the diff."""
    use_llm = body.use_llm
    layers = body.layers

    # When layers is explicitly set, respect it; otherwise honour use_llm flag
    if layers is not None and not use_llm and "llm_analyzer" in layers:
        layers = [la for la in layers if la != "llm_analyzer"]

    result = await diff_scan(
        body.old_content,
        body.new_content,
        file_name=body.file_name,
        use_llm=use_llm,
        use_urls=True,
        layers=layers,
    )

    return _result_to_response(result)
