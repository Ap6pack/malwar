# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Scan context passed through the detection pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from malwar.models.finding import Finding
from malwar.models.skill import SkillContent


@dataclass
class ScanContext:
    """Mutable context passed through the detection pipeline.

    Each layer can read previous findings and add enrichments.
    """

    skill: SkillContent
    scan_id: str
    findings: list[Finding] = field(default_factory=list)
    url_analysis_results: dict[str, Any] = field(default_factory=dict)
    llm_analysis: dict[str, Any] = field(default_factory=dict)
    matched_campaigns: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_findings(self, new_findings: list[Finding]) -> None:
        self.findings.extend(new_findings)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)

    @property
    def current_risk_score(self) -> int:
        from malwar.core.constants import SEVERITY_WEIGHTS

        if not self.findings:
            return 0
        return min(
            100,
            sum(
                int(SEVERITY_WEIGHTS[f.severity] * f.confidence)
                for f in self.findings
            ),
        )
