# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Severity aggregation and verdict computation."""

from __future__ import annotations

from malwar.core.constants import SEVERITY_WEIGHTS, Severity
from malwar.models.finding import Finding


def aggregate_severity(findings: list[Finding]) -> Severity:
    """Return the highest severity across all findings."""
    if not findings:
        return Severity.INFO
    return max(findings, key=lambda f: SEVERITY_WEIGHTS[f.severity]).severity


def compute_risk_score(findings: list[Finding]) -> int:
    """Weighted sum of severity * confidence, capped at 100."""
    if not findings:
        return 0
    return min(
        100,
        sum(int(SEVERITY_WEIGHTS[f.severity] * f.confidence) for f in findings),
    )


def compute_verdict(risk_score: int) -> str:
    """Map risk score to human-readable verdict."""
    if risk_score >= 75:
        return "MALICIOUS"
    if risk_score >= 40:
        return "SUSPICIOUS"
    if risk_score >= 15:
        return "CAUTION"
    return "CLEAN"
