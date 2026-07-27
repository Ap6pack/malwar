"""Severity aggregation and verdict computation."""

from __future__ import annotations

from malwar.core.constants import (
    FRAGILE_MAX_RISK,
    SEVERITY_WEIGHTS,
    Severity,
    is_fragile_rule_set,
)
from malwar.models.finding import Finding


def aggregate_severity(findings: list[Finding]) -> Severity:
    """Return the highest severity across all non-suppressed findings."""
    active = [f for f in findings if not f.suppressed]
    if not active:
        return Severity.INFO
    return max(active, key=lambda f: SEVERITY_WEIGHTS[f.severity]).severity


def compute_risk_score(findings: list[Finding]) -> int:
    """Calibrated risk score over non-suppressed findings, 0-100.

    Weighted sum of severity * confidence, capped at 100 -- then capped again
    at :data:`FRAGILE_MAX_RISK` when every active finding comes from a single
    high-false-positive rule, so an uncorroborated one-regex match cannot
    reach a MALICIOUS verdict on its own. See
    :func:`malwar.core.constants.is_fragile_rule_set`.

    This is the single source of truth for risk scoring; ``ScanResult`` and the
    pipeline's running context both delegate here so every surface (CLI, SDK,
    API, registry monitor) applies identical calibration.
    """
    active = [f for f in findings if not f.suppressed]
    if not active:
        return 0
    score = min(
        100,
        sum(int(SEVERITY_WEIGHTS[f.severity] * f.confidence) for f in active),
    )
    if is_fragile_rule_set({f.rule_id for f in active}):
        return min(score, FRAGILE_MAX_RISK)
    return score


def compute_verdict(risk_score: int) -> str:
    """Map risk score to human-readable verdict."""
    if risk_score >= 75:
        return "MALICIOUS"
    if risk_score >= 40:
        return "SUSPICIOUS"
    if risk_score >= 15:
        return "CAUTION"
    return "CLEAN"
