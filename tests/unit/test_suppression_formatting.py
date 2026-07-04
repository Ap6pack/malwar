# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for how suppressed findings surface in output formats and
notifications (issue #1): transparent in every output, excluded from scoring.
"""

from __future__ import annotations

import json

from malwar.cli.formatters.json_fmt import format_json_summary
from malwar.cli.formatters.sarif import scan_result_to_sarif
from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.models.finding import Finding, Location
from malwar.models.scan import ScanResult
from malwar.notifications.events import EventType, NotificationEvent


def _finding(
    finding_id: str,
    severity: Severity = Severity.HIGH,
    suppressed: bool = False,
    reason: str | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        rule_id="MALWAR-CRED-001",
        title="AWS access key",
        description="Detected AWS access key pattern",
        severity=severity,
        confidence=1.0,
        category=ThreatCategory.CREDENTIAL_EXPOSURE,
        detector_layer=DetectorLayer.RULE_ENGINE,
        location=Location(line_start=10, snippet="AKIAIOSFODNN7EXAMPLE"),
        suppressed=suppressed,
        suppressed_reason=reason,
        suppressed_by=DetectorLayer.LLM_ANALYZER if suppressed else None,
    )


def _result(findings: list[Finding]) -> ScanResult:
    return ScanResult(scan_id="test-scan", target="securityreview.md", findings=findings)


class TestSarifSuppressions:
    """SARIF output uses the format's native suppressions mechanism."""

    def test_suppressed_finding_gets_sarif_suppressions_block(self):
        result = _result([
            _finding("f1", suppressed=True, reason="AWS documentation example key"),
        ])
        sarif = scan_result_to_sarif(result)
        sarif_result = sarif["runs"][0]["results"][0]

        assert sarif_result["suppressions"] == [{
            "kind": "external",
            "justification": "AWS documentation example key",
        }]

    def test_suppressed_finding_still_present_in_results(self):
        """Transparency: suppressed findings are not dropped from SARIF output."""
        result = _result([_finding("f1", suppressed=True, reason="example key")])
        sarif = scan_result_to_sarif(result)
        assert len(sarif["runs"][0]["results"]) == 1

    def test_active_finding_has_no_suppressions_key(self):
        result = _result([_finding("f1", suppressed=False)])
        sarif = scan_result_to_sarif(result)
        assert "suppressions" not in sarif["runs"][0]["results"][0]

    def test_suppressed_without_reason_gets_default_justification(self):
        result = _result([_finding("f1", suppressed=True, reason=None)])
        sarif = scan_result_to_sarif(result)
        assert sarif["runs"][0]["results"][0]["suppressions"][0]["justification"]


class TestJsonSummarySuppression:
    """The compact JSON summary reports active vs. suppressed counts separately."""

    def test_suppressed_finding_excluded_from_finding_count(self):
        result = _result([
            _finding("f1", suppressed=True),
            _finding("f2", severity=Severity.MEDIUM, suppressed=False),
        ])
        summary = json.loads(format_json_summary(result))
        assert summary["finding_count"] == 1
        assert summary["suppressed_finding_count"] == 1

    def test_all_suppressed_gives_clean_summary(self):
        result = _result([_finding("f1", suppressed=True), _finding("f2", suppressed=True)])
        summary = json.loads(format_json_summary(result))
        assert summary["finding_count"] == 0
        assert summary["suppressed_finding_count"] == 2
        assert summary["verdict"] == "CLEAN"
        assert summary["risk_score"] == 0


class TestNotificationEventSuppression:
    """Notification payloads must not alert on suppressed false positives —
    this is the 'alert fatigue' impact called out in issue #1."""

    def test_all_findings_suppressed_yields_clean_event(self):
        result = _result([
            _finding("f1", suppressed=True, reason="example key"),
            _finding("f2", suppressed=True, reason="example key"),
        ])
        event = NotificationEvent.from_scan_result(result)

        assert event.event_type == EventType.SCAN_COMPLETE
        assert event.verdict == "CLEAN"
        assert event.finding_count == 0
        assert event.findings_summary == []

    def test_suppressed_finding_excluded_from_summary_list(self):
        result = _result([
            _finding("f1", suppressed=True, reason="example key"),
            _finding("f2", severity=Severity.CRITICAL, suppressed=False),
        ])
        event = NotificationEvent.from_scan_result(result)

        assert event.finding_count == 1
        assert len(event.findings_summary) == 1
        assert event.findings_summary[0].severity == "critical"
