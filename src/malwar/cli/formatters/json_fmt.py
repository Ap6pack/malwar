# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""JSON output formatter."""

from __future__ import annotations

import json

from malwar.models.scan import ScanResult


def format_json(result: ScanResult) -> str:
    """Return scan result as formatted JSON string."""
    return result.model_dump_json(indent=2)


def format_json_summary(result: ScanResult) -> str:
    """Return a compact JSON summary (no full findings detail)."""
    data = {
        "scan_id": result.scan_id,
        "target": result.target,
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "overall_severity": result.overall_severity,
        "finding_count": len(result.findings),
        "finding_count_by_severity": result.finding_count_by_severity,
        "skill_name": result.skill_name,
        "skill_author": result.skill_author,
        "duration_ms": result.duration_ms,
    }
    return json.dumps(data, indent=2)
