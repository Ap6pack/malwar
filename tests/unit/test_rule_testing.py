# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for the rule testing framework."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

from malwar.testing.framework import (
    CaseStatus,
    ExpectedVerdict,
    RuleTestCase,
    RuleTestManifest,
    RuleTestReport,
    RuleTestRunner,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "skills"
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def benign_manifest(tmp_path: Path) -> Path:
    """Create a minimal manifest pointing at a single benign fixture."""
    data = {
        "version": "1",
        "description": "Test manifest - benign only",
        "base_dir": str(PROJECT_ROOT),
        "test_cases": [
            {
                "fixture": "tests/fixtures/skills/benign/hello_world.md",
                "expected_verdict": "CLEAN",
                "description": "Should be clean",
            },
        ],
    }
    manifest_path = tmp_path / "manifest.yml"
    manifest_path.write_text(yaml.dump(data), encoding="utf-8")
    return manifest_path


@pytest.fixture
def malicious_manifest(tmp_path: Path) -> Path:
    """Create a minimal manifest with a malicious fixture."""
    data = {
        "version": "1",
        "description": "Test manifest - malicious",
        "base_dir": str(PROJECT_ROOT),
        "test_cases": [
            {
                "fixture": "tests/fixtures/skills/malicious/env_harvesting.md",
                "expected_verdict": "MALICIOUS",
                "expected_rules": ["MALWAR-ENV-001"],
                "description": "Should detect env harvesting",
            },
        ],
    }
    manifest_path = tmp_path / "manifest.yml"
    manifest_path.write_text(yaml.dump(data), encoding="utf-8")
    return manifest_path


@pytest.fixture
def mixed_manifest(tmp_path: Path) -> Path:
    """Create a manifest with both benign and malicious fixtures."""
    data = {
        "version": "1",
        "description": "Test manifest - mixed",
        "base_dir": str(PROJECT_ROOT),
        "test_cases": [
            {
                "fixture": "tests/fixtures/skills/benign/hello_world.md",
                "expected_verdict": "CLEAN",
            },
            {
                "fixture": "tests/fixtures/skills/malicious/base64_reverse_shell.md",
                "expected_verdict": "MALICIOUS",
                "expected_rules": ["MALWAR-OBF-001", "MALWAR-OBF-003"],
            },
        ],
    }
    manifest_path = tmp_path / "manifest.yml"
    manifest_path.write_text(yaml.dump(data), encoding="utf-8")
    return manifest_path


@pytest.fixture
def failing_manifest(tmp_path: Path) -> Path:
    """Create a manifest where the expected verdict is intentionally wrong."""
    data = {
        "version": "1",
        "description": "Test manifest - should fail",
        "base_dir": str(PROJECT_ROOT),
        "test_cases": [
            {
                "fixture": "tests/fixtures/skills/malicious/env_harvesting.md",
                "expected_verdict": "CLEAN",
                "description": "Intentionally wrong - should fail",
            },
        ],
    }
    manifest_path = tmp_path / "manifest.yml"
    manifest_path.write_text(yaml.dump(data), encoding="utf-8")
    return manifest_path


@pytest.fixture
def regression_manifest(tmp_path: Path) -> Path:
    """Manifest where a malicious file is expected MALICIOUS but has a missing rule."""
    data = {
        "version": "1",
        "description": "Test manifest - regression detection",
        "base_dir": str(PROJECT_ROOT),
        "test_cases": [
            {
                "fixture": "tests/fixtures/skills/malicious/base64_reverse_shell.md",
                "expected_verdict": "MALICIOUS",
                "expected_rules": [
                    "MALWAR-OBF-001",
                    "MALWAR-OBF-003",
                    "NONEXISTENT-RULE-999",
                ],
                "description": "Has a non-existent expected rule to simulate regression",
            },
        ],
    }
    manifest_path = tmp_path / "manifest.yml"
    manifest_path.write_text(yaml.dump(data), encoding="utf-8")
    return manifest_path


@pytest.fixture
def not_expected_manifest(tmp_path: Path) -> Path:
    """Manifest that tests not_expected_rules functionality."""
    data = {
        "version": "1",
        "description": "Test manifest - not_expected_rules",
        "base_dir": str(PROJECT_ROOT),
        "test_cases": [
            {
                "fixture": "tests/fixtures/skills/malicious/env_harvesting.md",
                "expected_verdict": "MALICIOUS",
                "expected_rules": ["MALWAR-ENV-001"],
                "not_expected_rules": ["MALWAR-ENV-001"],
                "description": "Contradictory: expected and forbidden overlap",
            },
        ],
    }
    manifest_path = tmp_path / "manifest.yml"
    manifest_path.write_text(yaml.dump(data), encoding="utf-8")
    return manifest_path


@pytest.fixture
def error_manifest(tmp_path: Path) -> Path:
    """Manifest pointing to a non-existent fixture file."""
    data = {
        "version": "1",
        "description": "Test manifest - missing fixture",
        "base_dir": str(PROJECT_ROOT),
        "test_cases": [
            {
                "fixture": "tests/fixtures/skills/nonexistent_file.md",
                "expected_verdict": "CLEAN",
                "description": "File does not exist",
            },
        ],
    }
    manifest_path = tmp_path / "manifest.yml"
    manifest_path.write_text(yaml.dump(data), encoding="utf-8")
    return manifest_path


# ---------------------------------------------------------------------------
# Test: Manifest loading and validation
# ---------------------------------------------------------------------------


class TestManifestLoading:
    """Tests for RuleTestManifest loading and validation."""

    def test_load_from_yaml(self, benign_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(benign_manifest)
        assert manifest.version == "1"
        assert len(manifest.test_cases) == 1
        assert manifest.test_cases[0].expected_verdict == ExpectedVerdict.CLEAN

    def test_load_malicious_manifest(self, malicious_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(malicious_manifest)
        tc = manifest.test_cases[0]
        assert tc.expected_verdict == ExpectedVerdict.MALICIOUS
        assert "MALWAR-ENV-001" in tc.expected_rules

    def test_load_mixed_manifest(self, mixed_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(mixed_manifest)
        assert len(manifest.test_cases) == 2
        assert manifest.test_cases[0].expected_verdict == ExpectedVerdict.CLEAN
        assert manifest.test_cases[1].expected_verdict == ExpectedVerdict.MALICIOUS

    def test_base_dir_resolved(self, benign_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(benign_manifest)
        assert Path(manifest.base_dir).is_absolute()

    def test_default_fields(self) -> None:
        tc = RuleTestCase(
            fixture="test.md",
            expected_verdict=ExpectedVerdict.CLEAN,
        )
        assert tc.expected_rules == []
        assert tc.not_expected_rules == []
        assert tc.description == ""

    def test_invalid_verdict_rejected(self) -> None:
        with pytest.raises(ValueError):
            RuleTestCase(
                fixture="test.md",
                expected_verdict="INVALID",  # type: ignore[arg-type]
            )

    def test_real_manifest_loads(self) -> None:
        """Ensure the project's actual rule_tests.yml loads correctly."""
        manifest_path = PROJECT_ROOT / "tests" / "rule_tests.yml"
        if manifest_path.exists():
            manifest = RuleTestManifest.from_yaml(manifest_path)
            assert len(manifest.test_cases) > 0


# ---------------------------------------------------------------------------
# Test: Runner with known fixtures
# ---------------------------------------------------------------------------


class TestRunner:
    """Tests for RuleTestRunner execution."""

    async def test_benign_passes(self, benign_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(benign_manifest)
        report = await RuleTestRunner.run(manifest)
        assert report.total == 1
        assert report.passed == 1
        assert report.failed == 0
        assert report.all_passed

    async def test_malicious_detected(self, malicious_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(malicious_manifest)
        report = await RuleTestRunner.run(manifest)
        assert report.total == 1
        assert report.passed == 1
        assert report.failed == 0

        result = report.results[0]
        assert result.actual_verdict in {"MALICIOUS", "SUSPICIOUS"}
        assert "MALWAR-ENV-001" in result.actual_rules

    async def test_mixed_all_pass(self, mixed_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(mixed_manifest)
        report = await RuleTestRunner.run(manifest)
        assert report.total == 2
        assert report.passed == 2
        assert report.all_passed

    async def test_error_on_missing_fixture(self, error_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(error_manifest)
        report = await RuleTestRunner.run(manifest)
        assert report.total == 1
        assert report.errors == 1
        assert report.results[0].status == CaseStatus.ERROR
        assert report.results[0].error_message != ""


# ---------------------------------------------------------------------------
# Test: Pass/fail detection
# ---------------------------------------------------------------------------


class TestPassFailDetection:
    """Tests that the runner correctly identifies pass/fail states."""

    async def test_wrong_verdict_fails(self, failing_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(failing_manifest)
        report = await RuleTestRunner.run(manifest)
        assert report.failed == 1
        assert not report.all_passed

    async def test_forbidden_rule_fires(self, not_expected_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(not_expected_manifest)
        report = await RuleTestRunner.run(manifest)
        assert report.failed == 1
        result = report.results[0]
        assert "MALWAR-ENV-001" in result.forbidden_rules_fired


# ---------------------------------------------------------------------------
# Test: Regression detection
# ---------------------------------------------------------------------------


class TestRegressionDetection:
    """Tests for regression detection logic."""

    async def test_missing_rule_is_regression(self, regression_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(regression_manifest)
        report = await RuleTestRunner.run(manifest)
        assert report.failed == 1
        result = report.results[0]
        assert "NONEXISTENT-RULE-999" in result.missed_rules
        # Verdict is still correct (MALICIOUS), but the test fails due to missing rules

    async def test_clean_misclassified_as_malicious_not_regression(
        self, failing_manifest: Path
    ) -> None:
        """When we expect CLEAN but get MALICIOUS, that's a failure but not a regression
        (regressions are only for malicious files that stop being detected)."""
        manifest = RuleTestManifest.from_yaml(failing_manifest)
        report = await RuleTestRunner.run(manifest)
        result = report.results[0]
        # expected_verdict is CLEAN, so is_regression should be False
        assert result.is_regression is False


# ---------------------------------------------------------------------------
# Test: Report generation — text
# ---------------------------------------------------------------------------


class TestReportText:
    """Tests for RuleTestReport.to_text() output."""

    async def test_text_output_contains_summary(self, mixed_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(mixed_manifest)
        report = await RuleTestRunner.run(manifest)
        text = report.to_text()
        assert "Rule Test Report" in text
        assert "Total: 2" in text
        assert "Passed: 2" in text

    async def test_text_output_shows_failures(self, failing_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(failing_manifest)
        report = await RuleTestRunner.run(manifest)
        text = report.to_text()
        assert "[FAIL]" in text
        assert "Failed: 1" in text

    def test_text_output_empty_report(self) -> None:
        report = RuleTestReport()
        text = report.to_text()
        assert "Total: 0" in text


# ---------------------------------------------------------------------------
# Test: Report generation — JSON
# ---------------------------------------------------------------------------


class TestReportJson:
    """Tests for RuleTestReport.to_json() output."""

    async def test_json_valid(self, mixed_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(mixed_manifest)
        report = await RuleTestRunner.run(manifest)
        data = json.loads(report.to_json())
        assert "summary" in data
        assert "results" in data
        assert data["summary"]["total"] == 2
        assert data["summary"]["all_passed"] is True

    async def test_json_failure_details(self, failing_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(failing_manifest)
        report = await RuleTestRunner.run(manifest)
        data = json.loads(report.to_json())
        assert data["summary"]["failed"] == 1
        result = data["results"][0]
        assert result["status"] == "failed"
        assert result["expected_verdict"] == "CLEAN"
        assert result["actual_verdict"] != "CLEAN"

    def test_json_empty_report(self) -> None:
        report = RuleTestReport()
        data = json.loads(report.to_json())
        assert data["summary"]["total"] == 0
        assert data["summary"]["all_passed"] is True


# ---------------------------------------------------------------------------
# Test: Report generation — JUnit XML
# ---------------------------------------------------------------------------


class TestReportJunit:
    """Tests for RuleTestReport.to_junit_xml() output."""

    async def test_junit_valid_xml(self, mixed_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(mixed_manifest)
        report = await RuleTestRunner.run(manifest)
        xml_str = report.to_junit_xml()
        root = ET.fromstring(xml_str)  # noqa: S314
        assert root.tag == "testsuite"
        assert root.get("tests") == "2"
        assert root.get("failures") == "0"

    async def test_junit_failure_element(self, failing_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(failing_manifest)
        report = await RuleTestRunner.run(manifest)
        xml_str = report.to_junit_xml()
        root = ET.fromstring(xml_str)  # noqa: S314
        assert root.get("failures") == "1"
        failure_elems = root.findall(".//failure")
        assert len(failure_elems) == 1

    async def test_junit_error_element(self, error_manifest: Path) -> None:
        manifest = RuleTestManifest.from_yaml(error_manifest)
        report = await RuleTestRunner.run(manifest)
        xml_str = report.to_junit_xml()
        root = ET.fromstring(xml_str)  # noqa: S314
        assert root.get("errors") == "1"
        error_elems = root.findall(".//error")
        assert len(error_elems) == 1

    def test_junit_empty_report(self) -> None:
        report = RuleTestReport()
        xml_str = report.to_junit_xml()
        root = ET.fromstring(xml_str)  # noqa: S314
        assert root.get("tests") == "0"


# ---------------------------------------------------------------------------
# Test: Full manifest run
# ---------------------------------------------------------------------------


class TestFullManifest:
    """Integration test running the real rule_tests.yml manifest."""

    async def test_real_manifest_all_pass(self) -> None:
        """Run the actual project manifest and verify all test cases pass."""
        manifest_path = PROJECT_ROOT / "tests" / "rule_tests.yml"
        if not manifest_path.exists():
            pytest.skip("rule_tests.yml not found")

        manifest = RuleTestManifest.from_yaml(manifest_path)
        report = await RuleTestRunner.run(manifest)

        # Print report for debugging if failures occur
        if not report.all_passed:
            for r in report.results:
                if r.status != CaseStatus.PASSED:
                    print(  # noqa: T201
                        f"\nFAILED: {r.fixture}"
                        f"\n  Expected: {r.expected_verdict}"
                        f"\n  Actual:   {r.actual_verdict}"
                        f"\n  Missed:   {r.missed_rules}"
                        f"\n  Unexpected: {r.unexpected_rules}"
                        f"\n  Forbidden: {r.forbidden_rules_fired}"
                    )

        assert report.all_passed, (
            f"{report.failed} test(s) failed, {report.errors} error(s). "
            f"Run `malwar test-rules` for details."
        )
