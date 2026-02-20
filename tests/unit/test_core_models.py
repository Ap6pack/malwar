# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for core models and utility modules: severity, logging, report, sarif, signature."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from malwar.core.constants import (
    DetectorLayer,
    Severity,
    ThreatCategory,
)
from malwar.core.logging import (
    JsonFormatter,
    TextFormatter,
    redact_sensitive,
    setup_logging,
)
from malwar.models.finding import Finding, Location
from malwar.models.report import BatchScanReport
from malwar.models.sarif import (
    SarifArtifactLocation,
    SarifDriver,
    SarifLocation,
    SarifMessage,
    SarifPhysicalLocation,
    SarifRegion,
    SarifReport,
    SarifResult,
    SarifRule,
    SarifRuleConfig,
    SarifRun,
    SarifTool,
)
from malwar.models.scan import ScanResult
from malwar.models.signature import Campaign, ThreatSignature
from malwar.scanner.severity import aggregate_severity, compute_risk_score, compute_verdict

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    finding_id: str = "MALWAR-TEST-001",
    rule_id: str = "rule-test-001",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
) -> Finding:
    """Create a Finding for testing."""
    return Finding(
        id=finding_id,
        rule_id=rule_id,
        title="Test Finding",
        description="A test finding",
        severity=severity,
        confidence=confidence,
        category=ThreatCategory.SUSPICIOUS_COMMAND,
        detector_layer=DetectorLayer.RULE_ENGINE,
        location=Location(line_start=10, line_end=15, snippet="suspicious code"),
        evidence=["matched pattern"],
        ioc_values=[],
        remediation="Remove suspicious code",
    )


# ===========================================================================
# severity.py tests
# ===========================================================================


class TestAggregateSeverity:
    """Tests for aggregate_severity()."""

    def test_empty_findings_returns_info(self):
        """Empty findings list should return INFO severity."""
        result = aggregate_severity([])
        assert result == Severity.INFO

    def test_single_critical_finding(self):
        """A single critical finding returns CRITICAL."""
        findings = [_make_finding(severity=Severity.CRITICAL)]
        assert aggregate_severity(findings) == Severity.CRITICAL

    def test_single_low_finding(self):
        """A single low finding returns LOW."""
        findings = [_make_finding(severity=Severity.LOW)]
        assert aggregate_severity(findings) == Severity.LOW

    def test_multiple_findings_returns_highest(self):
        """Multiple findings of different severities returns the highest."""
        findings = [
            _make_finding(finding_id="f1", severity=Severity.LOW),
            _make_finding(finding_id="f2", severity=Severity.CRITICAL),
            _make_finding(finding_id="f3", severity=Severity.MEDIUM),
        ]
        assert aggregate_severity(findings) == Severity.CRITICAL

    def test_all_info_returns_info(self):
        """All INFO findings returns INFO."""
        findings = [
            _make_finding(finding_id="f1", severity=Severity.INFO, confidence=0.5),
            _make_finding(finding_id="f2", severity=Severity.INFO, confidence=0.3),
        ]
        assert aggregate_severity(findings) == Severity.INFO

    def test_high_and_medium_returns_high(self):
        """HIGH and MEDIUM findings returns HIGH."""
        findings = [
            _make_finding(finding_id="f1", severity=Severity.MEDIUM),
            _make_finding(finding_id="f2", severity=Severity.HIGH),
        ]
        assert aggregate_severity(findings) == Severity.HIGH


class TestComputeRiskScore:
    """Tests for compute_risk_score()."""

    def test_empty_findings_returns_zero(self):
        """Empty findings list should return 0."""
        assert compute_risk_score([]) == 0

    def test_single_critical_full_confidence(self):
        """CRITICAL (weight=100) at confidence 1.0 should give 100."""
        findings = [_make_finding(severity=Severity.CRITICAL, confidence=1.0)]
        assert compute_risk_score(findings) == 100

    def test_single_info_returns_zero(self):
        """INFO (weight=0) at any confidence should give 0."""
        findings = [_make_finding(severity=Severity.INFO, confidence=1.0)]
        assert compute_risk_score(findings) == 0

    def test_single_low_half_confidence(self):
        """LOW (weight=25) at confidence 0.5 should give 12."""
        findings = [_make_finding(severity=Severity.LOW, confidence=0.5)]
        assert compute_risk_score(findings) == 12

    def test_capped_at_100(self):
        """Multiple high-severity findings should cap at 100."""
        findings = [
            _make_finding(finding_id="f1", severity=Severity.CRITICAL, confidence=1.0),
            _make_finding(finding_id="f2", severity=Severity.CRITICAL, confidence=1.0),
        ]
        assert compute_risk_score(findings) == 100

    def test_multiple_mixed_severities(self):
        """Weighted sum of multiple findings with different severities."""
        findings = [
            _make_finding(finding_id="f1", severity=Severity.HIGH, confidence=0.5),
            _make_finding(finding_id="f2", severity=Severity.MEDIUM, confidence=0.4),
        ]
        # HIGH: int(75 * 0.5) = 37, MEDIUM: int(50 * 0.4) = 20 => 57
        assert compute_risk_score(findings) == 57

    def test_single_medium_full_confidence(self):
        """MEDIUM (weight=50) at confidence 1.0 should give 50."""
        findings = [_make_finding(severity=Severity.MEDIUM, confidence=1.0)]
        assert compute_risk_score(findings) == 50


class TestComputeVerdict:
    """Tests for compute_verdict()."""

    def test_malicious_at_75(self):
        assert compute_verdict(75) == "MALICIOUS"

    def test_malicious_at_100(self):
        assert compute_verdict(100) == "MALICIOUS"

    def test_suspicious_at_40(self):
        assert compute_verdict(40) == "SUSPICIOUS"

    def test_suspicious_at_74(self):
        assert compute_verdict(74) == "SUSPICIOUS"

    def test_caution_at_15(self):
        assert compute_verdict(15) == "CAUTION"

    def test_caution_at_39(self):
        assert compute_verdict(39) == "CAUTION"

    def test_clean_at_14(self):
        assert compute_verdict(14) == "CLEAN"

    def test_clean_at_zero(self):
        assert compute_verdict(0) == "CLEAN"


# ===========================================================================
# logging.py tests
# ===========================================================================


class TestRedactSensitive:
    """Tests for the redact_sensitive() function."""

    def test_no_sensitive_data(self):
        """Plain text should pass through unchanged."""
        text = "This is a normal log message"
        assert redact_sensitive(text) == text

    def test_redacts_anthropic_api_key(self):
        """Anthropic API keys (sk-ant-...) should be redacted."""
        text = "Using key sk-ant-abc123XYZ0-extrasecretchars"
        result = redact_sensitive(text)
        assert "extrasecretchars" not in result
        assert "sk-ant-abc123XYZ0" in result
        assert "[REDACTED]" in result

    def test_redacts_openai_api_key(self):
        """OpenAI API keys (sk-...) should be redacted."""
        text = "Key is sk-abcdefghij1234567890extra"
        result = redact_sensitive(text)
        assert "sk-abcdefghij" in result
        assert "[REDACTED]" in result
        assert "1234567890extra" not in result

    def test_redacts_aws_access_key(self):
        """AWS access keys (AKIA...) should be redacted."""
        text = "AWS key: AKIAIOSFODNN7EXAMPLE"
        result = redact_sensitive(text)
        assert "AKIAIOSF" in result
        assert "[REDACTED]" in result
        assert "ODNN7EXAMPLE" not in result

    def test_redacts_github_token(self):
        """GitHub personal access tokens (ghp_...) should be redacted."""
        text = "Token: ghp_abcd1234567890abcdef1234567890abcdef12"
        result = redact_sensitive(text)
        assert "ghp_abcd" in result
        assert "[REDACTED]" in result

    def test_redacts_bearer_token(self):
        """Bearer tokens should be redacted."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.verylongsecretpayload"
        result = redact_sensitive(text)
        assert "[REDACTED]" in result
        assert "verylongsecretpayload" not in result

    def test_empty_string(self):
        """Empty string should return empty string."""
        assert redact_sensitive("") == ""

    def test_multiple_secrets_redacted(self):
        """Multiple secrets in the same string should all be redacted."""
        text = "key1=sk-ant-abc123XYZ0-secret key2=AKIAIOSFODNN7EXAMPLE"
        result = redact_sensitive(text)
        assert result.count("[REDACTED]") == 2


class TestJsonFormatter:
    """Tests for JsonFormatter."""

    def test_format_produces_valid_json(self):
        """JsonFormatter output should be valid JSON."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="malwar.test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "WARNING"
        assert parsed["logger"] == "malwar.test"
        assert parsed["message"] == "Test message"

    def test_format_redacts_secrets_in_message(self):
        """Secrets in the log message should be redacted."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="malwar.test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Using key sk-ant-abc123XYZ0-extrasecretvalue",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "[REDACTED]" in parsed["message"]
        assert "extrasecretvalue" not in parsed["message"]

    def test_format_includes_exception(self):
        """Exceptions should be included in the JSON output."""
        formatter = JsonFormatter()
        try:
            raise ValueError("error with key sk-ant-abc123XYZ0-secretpart")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="malwar.test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Something broke",
            args=None,
            exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert "[REDACTED]" in parsed["exception"]
        assert "secretpart" not in parsed["exception"]


class TestTextFormatter:
    """Tests for TextFormatter."""

    def test_format_redacts_secrets(self):
        """TextFormatter should redact sensitive data."""
        formatter = TextFormatter("%(message)s")
        record = logging.LogRecord(
            name="malwar.test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Token: ghp_abcd1234567890abcdef1234567890abcdef12",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        assert "[REDACTED]" in output

    def test_format_plain_message(self):
        """Plain messages should pass through the formatter."""
        formatter = TextFormatter("%(message)s")
        record = logging.LogRecord(
            name="malwar.test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Normal log message",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        assert output == "Normal log message"


class TestSetupLogging:
    """Tests for setup_logging()."""

    def test_setup_json_format(self):
        """setup_logging with json format configures JsonFormatter."""
        setup_logging(level="DEBUG", fmt="json")
        logger = logging.getLogger("malwar")
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, JsonFormatter)

    def test_setup_text_format(self):
        """setup_logging with text format configures TextFormatter."""
        setup_logging(level="WARNING", fmt="text")
        logger = logging.getLogger("malwar")
        assert logger.level == logging.WARNING
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, TextFormatter)

    def test_setup_clears_previous_handlers(self):
        """Calling setup_logging twice should not duplicate handlers."""
        setup_logging(level="INFO", fmt="json")
        setup_logging(level="INFO", fmt="json")
        logger = logging.getLogger("malwar")
        assert len(logger.handlers) == 1

    def test_setup_invalid_level_defaults_to_info(self):
        """Invalid log level string should default to INFO."""
        setup_logging(level="NONEXISTENT", fmt="json")
        logger = logging.getLogger("malwar")
        assert logger.level == logging.INFO


# ===========================================================================
# report.py tests
# ===========================================================================


class TestBatchScanReport:
    """Tests for BatchScanReport model."""

    def test_minimal_instantiation(self):
        """Create a BatchScanReport with only required fields."""
        report = BatchScanReport(
            report_id="report-001",
            started_at=datetime(2026, 2, 20, 12, 0, 0, tzinfo=UTC),
        )
        assert report.report_id == "report-001"
        assert report.completed_at is None
        assert report.total_skills == 0
        assert report.skills_scanned == 0
        assert report.skills_malicious == 0
        assert report.skills_suspicious == 0
        assert report.skills_clean == 0
        assert report.skills_errored == 0
        assert report.results == []
        assert report.top_threats == []
        assert report.campaign_matches == []

    def test_full_instantiation(self):
        """Create a BatchScanReport with all fields populated."""
        scan_result = ScanResult(
            scan_id="scan-001",
            target="/tmp/skill/SKILL.md",
        )
        report = BatchScanReport(
            report_id="report-002",
            started_at=datetime(2026, 2, 20, 12, 0, 0, tzinfo=UTC),
            completed_at=datetime(2026, 2, 20, 12, 5, 0, tzinfo=UTC),
            total_skills=10,
            skills_scanned=10,
            skills_malicious=2,
            skills_suspicious=3,
            skills_clean=4,
            skills_errored=1,
            results=[scan_result],
            top_threats=["ClawHavoc", "PromptInjection"],
            campaign_matches=["campaign-clawhavoc-001"],
        )
        assert report.total_skills == 10
        assert report.skills_malicious == 2
        assert len(report.results) == 1
        assert report.results[0].scan_id == "scan-001"
        assert report.top_threats == ["ClawHavoc", "PromptInjection"]
        assert report.campaign_matches == ["campaign-clawhavoc-001"]

    def test_serialization_roundtrip(self):
        """Serialize to dict and back."""
        report = BatchScanReport(
            report_id="report-003",
            started_at=datetime(2026, 2, 20, 12, 0, 0, tzinfo=UTC),
            total_skills=5,
            skills_clean=5,
        )
        data = report.model_dump()
        restored = BatchScanReport(**data)
        assert restored.report_id == report.report_id
        assert restored.total_skills == 5


# ===========================================================================
# sarif.py tests
# ===========================================================================


class TestSarifModels:
    """Tests for SARIF 2.1.0 Pydantic models."""

    def test_sarif_message(self):
        msg = SarifMessage(text="A finding")
        assert msg.text == "A finding"

    def test_sarif_artifact_location(self):
        loc = SarifArtifactLocation(uri="file:///tmp/SKILL.md")
        assert loc.uri == "file:///tmp/SKILL.md"

    def test_sarif_region_minimal(self):
        region = SarifRegion(startLine=1)
        assert region.startLine == 1
        assert region.endLine is None
        assert region.startColumn is None
        assert region.endColumn is None

    def test_sarif_region_full(self):
        region = SarifRegion(startLine=1, endLine=5, startColumn=10, endColumn=20)
        assert region.endLine == 5
        assert region.startColumn == 10
        assert region.endColumn == 20

    def test_sarif_physical_location(self):
        loc = SarifPhysicalLocation(
            artifactLocation=SarifArtifactLocation(uri="file:///test.md"),
            region=SarifRegion(startLine=3, endLine=7),
        )
        assert loc.artifactLocation.uri == "file:///test.md"
        assert loc.region is not None
        assert loc.region.startLine == 3

    def test_sarif_physical_location_no_region(self):
        loc = SarifPhysicalLocation(
            artifactLocation=SarifArtifactLocation(uri="file:///test.md"),
        )
        assert loc.region is None

    def test_sarif_location(self):
        sarif_loc = SarifLocation(
            physicalLocation=SarifPhysicalLocation(
                artifactLocation=SarifArtifactLocation(uri="file:///x.md"),
            )
        )
        assert sarif_loc.physicalLocation.artifactLocation.uri == "file:///x.md"

    def test_sarif_rule_config_default(self):
        config = SarifRuleConfig()
        assert config.level == "warning"

    def test_sarif_rule_config_custom(self):
        config = SarifRuleConfig(level="error")
        assert config.level == "error"

    def test_sarif_rule_minimal(self):
        rule = SarifRule(
            id="MALWAR-001",
            name="SuspiciousCommand",
            shortDescription=SarifMessage(text="Detects suspicious commands"),
        )
        assert rule.id == "MALWAR-001"
        assert rule.name == "SuspiciousCommand"
        assert rule.fullDescription is None
        assert rule.defaultConfiguration.level == "warning"

    def test_sarif_rule_full(self):
        rule = SarifRule(
            id="MALWAR-002",
            name="PromptInjection",
            shortDescription=SarifMessage(text="Short desc"),
            fullDescription=SarifMessage(text="Full description of the rule"),
            defaultConfiguration=SarifRuleConfig(level="error"),
        )
        assert rule.fullDescription is not None
        assert rule.fullDescription.text == "Full description of the rule"
        assert rule.defaultConfiguration.level == "error"

    def test_sarif_driver_defaults(self):
        driver = SarifDriver()
        assert driver.name == "malwar"
        assert driver.version == "0.1.0"
        assert driver.informationUri == "https://github.com/veritasaequitas/malwar"
        assert driver.rules == []

    def test_sarif_driver_with_rules(self):
        rule = SarifRule(
            id="R001",
            name="TestRule",
            shortDescription=SarifMessage(text="Test"),
        )
        driver = SarifDriver(rules=[rule])
        assert len(driver.rules) == 1
        assert driver.rules[0].id == "R001"

    def test_sarif_tool_default(self):
        tool = SarifTool()
        assert tool.driver.name == "malwar"

    def test_sarif_result(self):
        result = SarifResult(
            ruleId="MALWAR-001",
            level="error",
            message=SarifMessage(text="Found threat"),
            locations=[
                SarifLocation(
                    physicalLocation=SarifPhysicalLocation(
                        artifactLocation=SarifArtifactLocation(uri="file:///skill.md"),
                        region=SarifRegion(startLine=10),
                    )
                )
            ],
        )
        assert result.ruleId == "MALWAR-001"
        assert result.level == "error"
        assert len(result.locations) == 1

    def test_sarif_result_defaults(self):
        result = SarifResult(
            ruleId="MALWAR-002",
            message=SarifMessage(text="Warning"),
        )
        assert result.level == "warning"
        assert result.locations == []

    def test_sarif_run_default(self):
        run = SarifRun()
        assert run.tool.driver.name == "malwar"
        assert run.results == []

    def test_sarif_report_default(self):
        report = SarifReport()
        assert report.version == "2.1.0"
        assert report.runs == []

    def test_sarif_report_full_structure(self):
        """Build a complete SARIF report and verify the structure."""
        rule = SarifRule(
            id="MALWAR-OBF-001",
            name="ObfuscatedCommand",
            shortDescription=SarifMessage(text="Detects obfuscated commands"),
        )
        result = SarifResult(
            ruleId="MALWAR-OBF-001",
            level="error",
            message=SarifMessage(text="Found obfuscated base64 command"),
            locations=[
                SarifLocation(
                    physicalLocation=SarifPhysicalLocation(
                        artifactLocation=SarifArtifactLocation(uri="file:///SKILL.md"),
                        region=SarifRegion(startLine=42, endLine=42, startColumn=1, endColumn=80),
                    )
                )
            ],
        )
        run = SarifRun(
            tool=SarifTool(driver=SarifDriver(rules=[rule])),
            results=[result],
        )
        report = SarifReport(version="2.1.0", runs=[run])

        assert len(report.runs) == 1
        assert len(report.runs[0].results) == 1
        assert report.runs[0].results[0].ruleId == "MALWAR-OBF-001"
        assert len(report.runs[0].tool.driver.rules) == 1

    def test_sarif_report_serialization(self):
        """SARIF report should serialize to a dict suitable for JSON output."""
        report = SarifReport(
            runs=[
                SarifRun(
                    results=[
                        SarifResult(
                            ruleId="R1",
                            message=SarifMessage(text="Test"),
                        )
                    ]
                )
            ]
        )
        data = report.model_dump()
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert data["runs"][0]["results"][0]["ruleId"] == "R1"


# ===========================================================================
# signature.py tests
# ===========================================================================


class TestThreatSignature:
    """Tests for ThreatSignature model."""

    def test_minimal_instantiation(self):
        """Create a ThreatSignature with required fields only."""
        sig = ThreatSignature(
            id="sig-001",
            name="Test Signature",
            description="Detects test threats",
            severity=Severity.HIGH,
            category=ThreatCategory.SUSPICIOUS_COMMAND,
            pattern_type="regex",
            pattern_value=r"rm\s+-rf\s+/",
        )
        assert sig.id == "sig-001"
        assert sig.name == "Test Signature"
        assert sig.severity == Severity.HIGH
        assert sig.category == ThreatCategory.SUSPICIOUS_COMMAND
        assert sig.pattern_type == "regex"
        assert sig.pattern_value == r"rm\s+-rf\s+/"
        assert sig.ioc_type is None
        assert sig.campaign_id is None
        assert sig.source == "manual"
        assert sig.enabled is True
        assert isinstance(sig.created_at, datetime)
        assert isinstance(sig.updated_at, datetime)

    def test_full_instantiation(self):
        """Create a ThreatSignature with all fields populated."""
        now = datetime(2026, 2, 20, 12, 0, 0, tzinfo=UTC)
        sig = ThreatSignature(
            id="sig-002",
            name="C2 IP IOC",
            description="Known command-and-control IP",
            severity=Severity.CRITICAL,
            category=ThreatCategory.KNOWN_MALWARE,
            pattern_type="ioc",
            pattern_value="185.243.115.0/24",
            ioc_type="ip",
            campaign_id="campaign-clawhavoc-001",
            source="threat-intel-feed",
            enabled=False,
            created_at=now,
            updated_at=now,
        )
        assert sig.ioc_type == "ip"
        assert sig.campaign_id == "campaign-clawhavoc-001"
        assert sig.source == "threat-intel-feed"
        assert sig.enabled is False
        assert sig.created_at == now

    def test_serialization_roundtrip(self):
        """Serialize to dict and back."""
        sig = ThreatSignature(
            id="sig-003",
            name="Roundtrip Test",
            description="Testing roundtrip",
            severity=Severity.MEDIUM,
            category=ThreatCategory.DATA_EXFILTRATION,
            pattern_type="exact",
            pattern_value="exfil.example.com",
        )
        data = sig.model_dump()
        restored = ThreatSignature(**data)
        assert restored.id == sig.id
        assert restored.severity == sig.severity
        assert restored.pattern_value == sig.pattern_value

    def test_all_severity_values(self):
        """ThreatSignature should accept all Severity enum values."""
        for sev in Severity:
            sig = ThreatSignature(
                id=f"sig-{sev}",
                name=f"Sig {sev}",
                description="test",
                severity=sev,
                category=ThreatCategory.SUSPICIOUS_COMMAND,
                pattern_type="regex",
                pattern_value=".*",
            )
            assert sig.severity == sev

    def test_all_category_values(self):
        """ThreatSignature should accept all ThreatCategory enum values."""
        for cat in ThreatCategory:
            sig = ThreatSignature(
                id=f"sig-{cat}",
                name=f"Sig {cat}",
                description="test",
                severity=Severity.INFO,
                category=cat,
                pattern_type="regex",
                pattern_value=".*",
            )
            assert sig.category == cat


class TestCampaign:
    """Tests for Campaign model."""

    def test_minimal_instantiation(self):
        """Create a Campaign with required fields only."""
        now = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        campaign = Campaign(
            id="campaign-001",
            name="TestCampaign",
            description="A test campaign",
            first_seen=now,
            last_seen=now,
        )
        assert campaign.id == "campaign-001"
        assert campaign.name == "TestCampaign"
        assert campaign.attributed_to is None
        assert campaign.iocs == []
        assert campaign.signature_ids == []
        assert campaign.total_skills_affected == 0
        assert campaign.status == "active"

    def test_full_instantiation(self):
        """Create a Campaign with all fields populated."""
        campaign = Campaign(
            id="campaign-clawhavoc-001",
            name="ClawHavoc",
            description="AMOS infostealer distribution via MCP skills",
            first_seen=datetime(2025, 12, 1, tzinfo=UTC),
            last_seen=datetime(2026, 2, 15, tzinfo=UTC),
            attributed_to="Unknown APT",
            iocs=["185.243.115.237", "glot.io", "github.com/user/malrepo"],
            signature_ids=["sig-clawhavoc-c2-ip", "sig-clawhavoc-glot"],
            total_skills_affected=42,
            status="active",
        )
        assert campaign.attributed_to == "Unknown APT"
        assert len(campaign.iocs) == 3
        assert len(campaign.signature_ids) == 2
        assert campaign.total_skills_affected == 42
        assert campaign.status == "active"

    def test_inactive_campaign(self):
        """Campaign with inactive status."""
        campaign = Campaign(
            id="campaign-002",
            name="OldCampaign",
            description="No longer active",
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 6, 1, tzinfo=UTC),
            status="inactive",
        )
        assert campaign.status == "inactive"

    def test_serialization_roundtrip(self):
        """Serialize to dict and back."""
        campaign = Campaign(
            id="campaign-003",
            name="Roundtrip",
            description="Testing roundtrip",
            first_seen=datetime(2026, 1, 1, tzinfo=UTC),
            last_seen=datetime(2026, 2, 1, tzinfo=UTC),
            iocs=["example.com"],
        )
        data = campaign.model_dump()
        restored = Campaign(**data)
        assert restored.id == campaign.id
        assert restored.iocs == campaign.iocs
        assert restored.first_seen == campaign.first_seen
