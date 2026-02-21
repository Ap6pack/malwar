# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for CI/CD integration module.

Tests cover:
- CI exit codes and verdict-to-exit-code mapping
- GitLab Code Quality JSON formatter
- Azure DevOps logging command formatter
- Pipeline template YAML validity
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from malwar.ci.exit_codes import CIExitCode, verdict_to_exit_code
from malwar.ci.parser import format_azure_annotations, format_gitlab_code_quality
from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.models.finding import Finding, Location
from malwar.models.scan import ScanResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"


def _make_finding(
    *,
    rule_id: str = "MALWAR-TEST-001",
    title: str = "Test finding",
    description: str = "A test finding for unit tests.",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    category: ThreatCategory = ThreatCategory.OBFUSCATED_COMMAND,
    line_start: int = 10,
    line_end: int | None = 12,
    snippet: str = "suspicious content",
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    return Finding(
        id=f"{rule_id}-L{line_start}",
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        category=category,
        detector_layer=DetectorLayer.RULE_ENGINE,
        location=Location(
            line_start=line_start,
            line_end=line_end,
            snippet=snippet,
        ),
        evidence=["encoded base64 payload detected"],
    )


def _make_scan_result(
    *,
    target: str = "skills/bad/SKILL.md",
    findings: list[Finding] | None = None,
    scan_id: str = "test-scan-001",
) -> ScanResult:
    """Create a ScanResult with sensible defaults for testing."""
    return ScanResult(
        scan_id=scan_id,
        target=target,
        findings=findings or [],
        layers_executed=["rule_engine"],
        skill_sha256="abc123" * 8,
    )


@pytest.fixture
def clean_result() -> ScanResult:
    """A scan result with no findings (CLEAN verdict)."""
    return _make_scan_result()


@pytest.fixture
def malicious_result() -> ScanResult:
    """A scan result with a high-severity finding (MALICIOUS verdict)."""
    return _make_scan_result(
        findings=[
            _make_finding(severity=Severity.CRITICAL, confidence=1.0),
        ],
    )


@pytest.fixture
def suspicious_result() -> ScanResult:
    """A scan result with medium findings (SUSPICIOUS verdict)."""
    return _make_scan_result(
        findings=[
            _make_finding(
                rule_id="MALWAR-SUSP-001",
                severity=Severity.MEDIUM,
                confidence=0.85,
            ),
        ],
    )


@pytest.fixture
def multi_finding_result() -> ScanResult:
    """A scan result with multiple findings of varying severity."""
    return _make_scan_result(
        findings=[
            _make_finding(
                rule_id="MALWAR-CRIT-001",
                title="Critical obfuscation",
                severity=Severity.CRITICAL,
                confidence=1.0,
                line_start=5,
            ),
            _make_finding(
                rule_id="MALWAR-MED-001",
                title="Suspicious URL",
                severity=Severity.MEDIUM,
                confidence=0.7,
                line_start=20,
                line_end=22,
                category=ThreatCategory.MALICIOUS_URL,
            ),
            _make_finding(
                rule_id="MALWAR-LOW-001",
                title="Minor concern",
                severity=Severity.LOW,
                confidence=0.5,
                line_start=30,
                line_end=None,
            ),
        ],
    )


# ===========================================================================
# Exit Codes
# ===========================================================================


class TestCIExitCode:
    """Test CIExitCode enum values."""

    def test_clean_is_zero(self):
        assert CIExitCode.CLEAN == 0

    def test_malicious_is_one(self):
        assert CIExitCode.MALICIOUS == 1

    def test_scan_error_is_two(self):
        assert CIExitCode.SCAN_ERROR == 2

    def test_suspicious_is_three(self):
        assert CIExitCode.SUSPICIOUS == 3

    def test_exit_codes_are_int(self):
        for code in CIExitCode:
            assert isinstance(code, int)


class TestVerdictToExitCode:
    """Test verdict string to exit code conversion."""

    def test_clean_verdict(self):
        assert verdict_to_exit_code("CLEAN") == CIExitCode.CLEAN

    def test_malicious_verdict(self):
        assert verdict_to_exit_code("MALICIOUS") == CIExitCode.MALICIOUS

    def test_suspicious_verdict(self):
        assert verdict_to_exit_code("SUSPICIOUS") == CIExitCode.SUSPICIOUS

    def test_caution_verdict(self):
        assert verdict_to_exit_code("CAUTION") == CIExitCode.SUSPICIOUS

    def test_case_insensitive(self):
        assert verdict_to_exit_code("clean") == CIExitCode.CLEAN
        assert verdict_to_exit_code("Malicious") == CIExitCode.MALICIOUS

    def test_whitespace_stripped(self):
        assert verdict_to_exit_code("  CLEAN  ") == CIExitCode.CLEAN

    def test_unknown_verdict_raises(self):
        with pytest.raises(ValueError, match="Unknown verdict"):
            verdict_to_exit_code("UNKNOWN")

    def test_empty_verdict_raises(self):
        with pytest.raises(ValueError, match="Unknown verdict"):
            verdict_to_exit_code("")


# ===========================================================================
# GitLab Code Quality Formatter
# ===========================================================================


class TestFormatGitlabCodeQuality:
    """Test GitLab Code Quality JSON output."""

    def test_empty_results(self):
        output = format_gitlab_code_quality([])
        parsed = json.loads(output)
        assert parsed == []

    def test_clean_result_produces_empty_array(self, clean_result: ScanResult):
        output = format_gitlab_code_quality([clean_result])
        parsed = json.loads(output)
        assert parsed == []

    def test_valid_json_array(self, malicious_result: ScanResult):
        output = format_gitlab_code_quality([malicious_result])
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) > 0

    def test_issue_structure(self, malicious_result: ScanResult):
        output = format_gitlab_code_quality([malicious_result])
        parsed = json.loads(output)
        issue = parsed[0]

        assert issue["type"] == "issue"
        assert "check_name" in issue
        assert "description" in issue
        assert "severity" in issue
        assert "fingerprint" in issue
        assert "location" in issue
        assert "path" in issue["location"]
        assert "lines" in issue["location"]
        assert "begin" in issue["location"]["lines"]

    def test_severity_mapping(self, multi_finding_result: ScanResult):
        output = format_gitlab_code_quality([multi_finding_result])
        parsed = json.loads(output)

        severities = {issue["check_name"]: issue["severity"] for issue in parsed}
        assert severities["MALWAR-CRIT-001"] == "blocker"
        assert severities["MALWAR-MED-001"] == "major"
        assert severities["MALWAR-LOW-001"] == "minor"

    def test_fingerprints_are_unique(self, multi_finding_result: ScanResult):
        output = format_gitlab_code_quality([multi_finding_result])
        parsed = json.loads(output)
        fingerprints = [issue["fingerprint"] for issue in parsed]
        assert len(fingerprints) == len(set(fingerprints))

    def test_categories_include_security(self, malicious_result: ScanResult):
        output = format_gitlab_code_quality([malicious_result])
        parsed = json.loads(output)
        for issue in parsed:
            assert "Security" in issue["categories"]

    def test_line_end_included_when_present(self, multi_finding_result: ScanResult):
        output = format_gitlab_code_quality([multi_finding_result])
        parsed = json.loads(output)
        # The first finding has line_end, check it is present
        crit_issue = next(i for i in parsed if i["check_name"] == "MALWAR-CRIT-001")
        assert "end" in crit_issue["location"]["lines"]

    def test_multiple_results_combined(self, malicious_result: ScanResult, suspicious_result: ScanResult):
        output = format_gitlab_code_quality([malicious_result, suspicious_result])
        parsed = json.loads(output)
        assert len(parsed) == 2

    def test_content_body_present(self, malicious_result: ScanResult):
        output = format_gitlab_code_quality([malicious_result])
        parsed = json.loads(output)
        issue = parsed[0]
        assert "content" in issue
        assert "body" in issue["content"]
        assert len(issue["content"]["body"]) > 0


# ===========================================================================
# Azure DevOps Annotations Formatter
# ===========================================================================


class TestFormatAzureAnnotations:
    """Test Azure DevOps ##vso logging command output."""

    def test_empty_results(self):
        output = format_azure_annotations([])
        assert output == ""

    def test_clean_result_produces_no_output(self, clean_result: ScanResult):
        output = format_azure_annotations([clean_result])
        assert output == ""

    def test_vso_command_format(self, malicious_result: ScanResult):
        output = format_azure_annotations([malicious_result])
        lines = output.strip().split("\n")
        # At least one finding line + summary
        assert len(lines) >= 2
        assert lines[0].startswith("##vso[task.logissue")

    def test_contains_error_type_for_critical(self, malicious_result: ScanResult):
        output = format_azure_annotations([malicious_result])
        assert "type=error" in output

    def test_contains_source_path(self, malicious_result: ScanResult):
        output = format_azure_annotations([malicious_result])
        assert "sourcepath=skills/bad/SKILL.md" in output

    def test_contains_line_number(self, malicious_result: ScanResult):
        output = format_azure_annotations([malicious_result])
        assert "linenumber=10" in output

    def test_contains_rule_code(self, malicious_result: ScanResult):
        output = format_azure_annotations([malicious_result])
        assert "code=MALWAR-TEST-001" in output

    def test_summary_line_present(self, malicious_result: ScanResult):
        output = format_azure_annotations([malicious_result])
        lines = output.strip().split("\n")
        summary = lines[-1]
        assert "Malwar scan complete" in summary
        assert "finding(s)" in summary

    def test_multiple_findings_produce_multiple_lines(self, multi_finding_result: ScanResult):
        output = format_azure_annotations([multi_finding_result])
        lines = output.strip().split("\n")
        # 3 findings + 1 summary
        assert len(lines) == 4

    def test_warning_type_for_medium_severity(self, suspicious_result: ScanResult):
        output = format_azure_annotations([suspicious_result])
        # First line should be warning for medium severity
        first_line = output.strip().split("\n")[0]
        assert "type=warning" in first_line

    def test_column_number_defaults_to_one(self, malicious_result: ScanResult):
        output = format_azure_annotations([malicious_result])
        assert "columnnumber=1" in output

    def test_multiple_results_combined(self, malicious_result: ScanResult, suspicious_result: ScanResult):
        output = format_azure_annotations([malicious_result, suspicious_result])
        lines = output.strip().split("\n")
        # 1 finding from malicious + 1 from suspicious + 1 summary = 3
        assert len(lines) == 3

    def test_worst_verdict_in_summary(self, malicious_result: ScanResult, suspicious_result: ScanResult):
        output = format_azure_annotations([malicious_result, suspicious_result])
        assert "MALICIOUS" in output


# ===========================================================================
# Pipeline Template YAML Validation
# ===========================================================================


class TestGitlabTemplateYaml:
    """Test that the GitLab CI template is valid YAML."""

    def test_file_exists(self):
        path = TEMPLATES_DIR / "gitlab" / ".gitlab-ci.yml"
        assert path.exists(), f"GitLab CI template not found at {path}"

    def test_valid_yaml(self):
        path = TEMPLATES_DIR / "gitlab" / ".gitlab-ci.yml"
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        assert isinstance(data, dict)

    def test_has_stages(self):
        path = TEMPLATES_DIR / "gitlab" / ".gitlab-ci.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "stages" in data
        assert "test" in data["stages"]

    def test_has_malwar_scan_job(self):
        path = TEMPLATES_DIR / "gitlab" / ".gitlab-ci.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "malwar-scan" in data

    def test_scan_job_has_image(self):
        path = TEMPLATES_DIR / "gitlab" / ".gitlab-ci.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        job = data["malwar-scan"]
        assert "image" in job
        assert "python" in job["image"]

    def test_scan_job_has_artifacts(self):
        path = TEMPLATES_DIR / "gitlab" / ".gitlab-ci.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        job = data["malwar-scan"]
        assert "artifacts" in job
        assert "reports" in job["artifacts"]
        assert "codequality" in job["artifacts"]["reports"]

    def test_scan_job_has_script(self):
        path = TEMPLATES_DIR / "gitlab" / ".gitlab-ci.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        job = data["malwar-scan"]
        assert "script" in job

    def test_variables_defined(self):
        path = TEMPLATES_DIR / "gitlab" / ".gitlab-ci.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "variables" in data
        assert "MALWAR_SCAN_PATH" in data["variables"]
        assert "MALWAR_FAIL_ON" in data["variables"]

    def test_has_copyright_header(self):
        path = TEMPLATES_DIR / "gitlab" / ".gitlab-ci.yml"
        content = path.read_text(encoding="utf-8")
        assert "Copyright (c) 2026 Veritas Aequitas Holdings LLC" in content


class TestAzureTemplateYaml:
    """Test that the Azure DevOps pipeline template is valid YAML."""

    def test_file_exists(self):
        path = TEMPLATES_DIR / "azure" / "azure-pipelines.yml"
        assert path.exists(), f"Azure pipeline template not found at {path}"

    def test_valid_yaml(self):
        path = TEMPLATES_DIR / "azure" / "azure-pipelines.yml"
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        assert isinstance(data, dict)

    def test_has_parameters(self):
        path = TEMPLATES_DIR / "azure" / "azure-pipelines.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "parameters" in data
        param_names = [p["name"] for p in data["parameters"]]
        assert "scanPath" in param_names
        assert "failOn" in param_names

    def test_has_steps(self):
        path = TEMPLATES_DIR / "azure" / "azure-pipelines.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "steps" in data
        assert len(data["steps"]) > 0

    def test_has_python_setup_step(self):
        path = TEMPLATES_DIR / "azure" / "azure-pipelines.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        steps = data["steps"]
        python_steps = [s for s in steps if s.get("task", "").startswith("UsePythonVersion")]
        assert len(python_steps) > 0

    def test_has_pool(self):
        path = TEMPLATES_DIR / "azure" / "azure-pipelines.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "pool" in data
        assert "vmImage" in data["pool"]

    def test_has_trigger(self):
        path = TEMPLATES_DIR / "azure" / "azure-pipelines.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "trigger" in data

    def test_has_copyright_header(self):
        path = TEMPLATES_DIR / "azure" / "azure-pipelines.yml"
        content = path.read_text(encoding="utf-8")
        assert "Copyright (c) 2026 Veritas Aequitas Holdings LLC" in content

    def test_fail_on_parameter_values(self):
        path = TEMPLATES_DIR / "azure" / "azure-pipelines.yml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        fail_on_param = next(p for p in data["parameters"] if p["name"] == "failOn")
        assert "MALICIOUS" in fail_on_param["values"]
        assert "SUSPICIOUS" in fail_on_param["values"]
        assert "CAUTION" in fail_on_param["values"]


# ===========================================================================
# Integration: CI module __init__ re-exports
# ===========================================================================


class TestCIModuleImports:
    """Test that the CI module properly exports its public API."""

    def test_import_exit_code(self):
        from malwar.ci import CIExitCode
        assert CIExitCode.CLEAN == 0

    def test_import_verdict_to_exit_code(self):
        from malwar.ci import verdict_to_exit_code
        assert verdict_to_exit_code("CLEAN") == 0

    def test_import_gitlab_formatter(self):
        from malwar.ci import format_gitlab_code_quality
        assert callable(format_gitlab_code_quality)

    def test_import_azure_formatter(self):
        from malwar.ci import format_azure_annotations
        assert callable(format_azure_annotations)
