# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""SARIF 2.1.0 output formatter."""

from __future__ import annotations

import json
from typing import Any

from malwar import __version__
from malwar.core.constants import Severity
from malwar.models.scan import ScanResult

SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def scan_result_to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to SARIF 2.1.0 format."""
    rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    results: list[dict[str, Any]] = []

    for finding in result.findings:
        # Add rule definition if not already added
        if finding.rule_id not in seen_rules:
            seen_rules.add(finding.rule_id)
            rules.append({
                "id": finding.rule_id,
                "name": finding.rule_id.replace("-", "_"),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
                },
            })

        # Build result entry
        sarif_result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.description},
        }

        if finding.location:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": result.target},
                    "region": {"startLine": finding.location.line_start},
                }
            }
            if finding.location.line_end:
                location["physicalLocation"]["region"]["endLine"] = finding.location.line_end
            sarif_result["locations"] = [location]

        if finding.evidence:
            sarif_result["properties"] = {
                "evidence": finding.evidence,
                "confidence": finding.confidence,
                "category": finding.category,
            }

        results.append(sarif_result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "malwar",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def format_sarif(result: ScanResult) -> str:
    """Return SARIF JSON string."""
    return json.dumps(scan_result_to_sarif(result), indent=2)
