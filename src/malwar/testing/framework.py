# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Rule testing framework — manifest, runner, and report."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from malwar.sdk import scan

# ---------------------------------------------------------------------------
# Manifest models (loaded from YAML)
# ---------------------------------------------------------------------------


class ExpectedVerdict(StrEnum):
    """Expected verdict for a test fixture."""

    CLEAN = "CLEAN"
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"


class RuleTestCase(BaseModel):
    """A single test case within the manifest."""

    fixture: str = Field(description="Relative path to the fixture file from project root")
    expected_verdict: ExpectedVerdict = Field(description="Expected scan verdict")
    expected_rules: list[str] = Field(
        default_factory=list,
        description="Rule IDs that should fire on this fixture",
    )
    not_expected_rules: list[str] = Field(
        default_factory=list,
        description="Rule IDs that should NOT fire on this fixture",
    )
    description: str = ""


class RuleTestManifest(BaseModel):
    """Top-level manifest loaded from a YAML file."""

    version: str = "1"
    description: str = ""
    base_dir: str = Field(
        default=".",
        description="Base directory for resolving fixture paths",
    )
    test_cases: list[RuleTestCase] = Field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> RuleTestManifest:
        """Load a manifest from a YAML file."""
        path = Path(path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        manifest = cls.model_validate(raw)
        # Resolve base_dir relative to the YAML file's parent
        resolved_base = (path.parent / manifest.base_dir).resolve()
        manifest.base_dir = str(resolved_base)
        return manifest


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


class CaseStatus(StrEnum):
    """Outcome of a single test case."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


@dataclass
class TestCaseResult:
    """Result of running a single test case."""

    fixture: str
    expected_verdict: str
    actual_verdict: str
    expected_rules: list[str]
    actual_rules: list[str]
    status: CaseStatus
    unexpected_rules: list[str] = field(default_factory=list)
    missed_rules: list[str] = field(default_factory=list)
    forbidden_rules_fired: list[str] = field(default_factory=list)
    error_message: str = ""
    is_regression: bool = False


@dataclass
class RuleTestReport:
    """Aggregate report of all test case results."""

    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    regressions: int = 0
    results: list[TestCaseResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0 and self.errors == 0

    def to_text(self) -> str:
        """Formatted console output."""
        lines: list[str] = []
        lines.append("=" * 72)
        lines.append("Rule Test Report")
        lines.append("=" * 72)
        lines.append("")

        for r in self.results:
            icon = "PASS" if r.status == CaseStatus.PASSED else "FAIL"
            if r.status == CaseStatus.ERROR:
                icon = "ERR "
            regression_flag = " [REGRESSION]" if r.is_regression else ""
            lines.append(f"  [{icon}] {r.fixture}{regression_flag}")
            lines.append(f"         Expected: {r.expected_verdict}  Actual: {r.actual_verdict}")

            if r.missed_rules:
                lines.append(f"         Missed rules:     {', '.join(r.missed_rules)}")
            if r.unexpected_rules:
                lines.append(f"         Unexpected rules: {', '.join(r.unexpected_rules)}")
            if r.forbidden_rules_fired:
                lines.append(
                    f"         Forbidden rules:  {', '.join(r.forbidden_rules_fired)}"
                )
            if r.error_message:
                lines.append(f"         Error: {r.error_message}")
            lines.append("")

        lines.append("-" * 72)
        lines.append(
            f"Total: {self.total}  Passed: {self.passed}  "
            f"Failed: {self.failed}  Errors: {self.errors}  "
            f"Regressions: {self.regressions}"
        )
        lines.append("=" * 72)
        return "\n".join(lines)

    def to_json(self) -> str:
        """JSON export."""
        data = {
            "summary": {
                "total": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "errors": self.errors,
                "regressions": self.regressions,
                "all_passed": self.all_passed,
            },
            "results": [
                {
                    "fixture": r.fixture,
                    "expected_verdict": r.expected_verdict,
                    "actual_verdict": r.actual_verdict,
                    "expected_rules": r.expected_rules,
                    "actual_rules": r.actual_rules,
                    "status": r.status.value,
                    "unexpected_rules": r.unexpected_rules,
                    "missed_rules": r.missed_rules,
                    "forbidden_rules_fired": r.forbidden_rules_fired,
                    "error_message": r.error_message,
                    "is_regression": r.is_regression,
                }
                for r in self.results
            ],
        }
        return json.dumps(data, indent=2)

    def to_junit_xml(self) -> str:
        """JUnit XML for CI integration."""
        testsuite = ET.Element("testsuite")
        testsuite.set("name", "rule-tests")
        testsuite.set("tests", str(self.total))
        testsuite.set("failures", str(self.failed))
        testsuite.set("errors", str(self.errors))

        for r in self.results:
            testcase = ET.SubElement(testsuite, "testcase")
            testcase.set("name", r.fixture)
            testcase.set("classname", "rule-tests")

            if r.status == CaseStatus.FAILED:
                failure = ET.SubElement(testcase, "failure")
                parts: list[str] = []
                parts.append(
                    f"Expected verdict: {r.expected_verdict}, "
                    f"Actual verdict: {r.actual_verdict}"
                )
                if r.missed_rules:
                    parts.append(f"Missed rules: {', '.join(r.missed_rules)}")
                if r.unexpected_rules:
                    parts.append(f"Unexpected rules: {', '.join(r.unexpected_rules)}")
                if r.forbidden_rules_fired:
                    parts.append(
                        f"Forbidden rules fired: {', '.join(r.forbidden_rules_fired)}"
                    )
                failure.set("message", "; ".join(parts))
                failure.text = "\n".join(parts)

            elif r.status == CaseStatus.ERROR:
                error = ET.SubElement(testcase, "error")
                error.set("message", r.error_message)
                error.text = r.error_message

        return ET.tostring(testsuite, encoding="unicode", xml_declaration=True)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _verdict_matches(expected: ExpectedVerdict, actual: str) -> bool:
    """Check if the actual verdict satisfies the expected verdict.

    CLEAN must match exactly.  MALICIOUS accepts MALICIOUS or SUSPICIOUS.
    SUSPICIOUS accepts SUSPICIOUS, MALICIOUS, or CAUTION.
    """
    if expected == ExpectedVerdict.CLEAN:
        return actual == "CLEAN"
    if expected == ExpectedVerdict.MALICIOUS:
        return actual in {"MALICIOUS", "SUSPICIOUS"}
    if expected == ExpectedVerdict.SUSPICIOUS:
        return actual in {"SUSPICIOUS", "MALICIOUS", "CAUTION"}
    return False


class RuleTestRunner:
    """Runs test cases from a manifest and produces a report."""

    @staticmethod
    async def run(manifest: RuleTestManifest) -> RuleTestReport:
        """Execute all test cases and return a report."""
        report = RuleTestReport()
        base_dir = Path(manifest.base_dir)

        for tc in manifest.test_cases:
            report.total += 1
            fixture_path = base_dir / tc.fixture

            try:
                content = fixture_path.read_text(encoding="utf-8")
            except OSError as exc:
                result = TestCaseResult(
                    fixture=tc.fixture,
                    expected_verdict=tc.expected_verdict.value,
                    actual_verdict="ERROR",
                    expected_rules=tc.expected_rules,
                    actual_rules=[],
                    status=CaseStatus.ERROR,
                    error_message=str(exc),
                )
                report.errors += 1
                report.results.append(result)
                continue

            try:
                scan_result = await scan(
                    content,
                    file_name=fixture_path.name,
                    use_llm=False,
                    use_urls=False,
                )
            except Exception as exc:
                result = TestCaseResult(
                    fixture=tc.fixture,
                    expected_verdict=tc.expected_verdict.value,
                    actual_verdict="ERROR",
                    expected_rules=tc.expected_rules,
                    actual_rules=[],
                    status=CaseStatus.ERROR,
                    error_message=f"Scan failed: {exc}",
                )
                report.errors += 1
                report.results.append(result)
                continue

            actual_rule_ids = list({f.rule_id for f in scan_result.findings})
            actual_rule_set = set(actual_rule_ids)
            expected_rule_set = set(tc.expected_rules)
            not_expected_set = set(tc.not_expected_rules)

            verdict_ok = _verdict_matches(tc.expected_verdict, scan_result.verdict)
            missed_rules = sorted(expected_rule_set - actual_rule_set)
            unexpected_rules = sorted(actual_rule_set - expected_rule_set) if expected_rule_set else []
            forbidden_rules_fired = sorted(not_expected_set & actual_rule_set)

            passed = verdict_ok and not missed_rules and not forbidden_rules_fired

            is_regression = not verdict_ok and tc.expected_verdict != ExpectedVerdict.CLEAN

            status = CaseStatus.PASSED if passed else CaseStatus.FAILED

            result = TestCaseResult(
                fixture=tc.fixture,
                expected_verdict=tc.expected_verdict.value,
                actual_verdict=scan_result.verdict,
                expected_rules=tc.expected_rules,
                actual_rules=sorted(actual_rule_ids),
                status=status,
                unexpected_rules=unexpected_rules,
                missed_rules=missed_rules,
                forbidden_rules_fired=forbidden_rules_fired,
                is_regression=is_regression,
            )

            if passed:
                report.passed += 1
            else:
                report.failed += 1
                if is_regression:
                    report.regressions += 1

            report.results.append(result)

        return report
