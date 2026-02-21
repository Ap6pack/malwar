# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Scan request and result models."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field, computed_field

from malwar.core.constants import SEVERITY_WEIGHTS, ScanStatus, Severity
from malwar.models.finding import Finding


class ScanRequest(BaseModel):
    """Input for initiating a scan."""

    target: str = Field(description="File path, directory path, or URL")
    layers: list[str] = Field(
        default=["rule_engine", "url_crawler", "llm_analyzer", "threat_intel"],
    )
    follow_urls: bool = True
    use_llm: bool = True
    max_url_depth: int = Field(default=2, ge=0, le=5)


class ScanResult(BaseModel):
    """Complete result of scanning a single SKILL.md."""

    scan_id: str
    target: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_ms: int | None = None
    findings: list[Finding] = Field(default_factory=list)
    skill_sha256: str = ""
    skill_name: str | None = None
    skill_author: str | None = None
    layers_executed: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    ml_risk_score: float | None = Field(
        default=None,
        description="ML model risk probability [0.0, 1.0], None if ML disabled",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_score(self) -> int:
        if not self.findings:
            return 0
        return min(
            100,
            sum(
                int(SEVERITY_WEIGHTS[f.severity] * f.confidence) for f in self.findings
            ),
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def overall_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(self.findings, key=lambda f: SEVERITY_WEIGHTS[f.severity]).severity

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict(self) -> str:
        if self.risk_score >= 75:
            return "MALICIOUS"
        if self.risk_score >= 40:
            return "SUSPICIOUS"
        if self.risk_score >= 15:
            return "CAUTION"
        return "CLEAN"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def finding_count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
