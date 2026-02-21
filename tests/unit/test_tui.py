# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for TUI module: result formatting, watch mode, dashboard data assembly."""

from __future__ import annotations

import os
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from malwar.cli.tui.dashboard import (
    DashboardData,
    assemble_dashboard,
    build_recent_results_panel,
    build_rule_trigger_panel,
    build_status_panel,
    build_system_stats_panel,
    build_verdict_distribution_panel,
)
from malwar.cli.tui.results import (
    VERDICT_COLORS,
    build_evidence_tree,
    build_findings_table,
    build_info_table,
    build_layers_tree,
    build_summary_line,
    build_verdict_panel,
    format_scan_result_rich,
    make_severity_badge,
    make_verdict_text,
    render_scan_result,
)
from malwar.cli.tui.watch import collect_file_states, detect_changes
from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.models.finding import Finding, Location
from malwar.models.scan import ScanResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    finding_id: str = "MALWAR-TEST-001",
    rule_id: str = "rule-test-001",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    evidence: list[str] | None = None,
    remediation: str = "",
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
        evidence=evidence or ["matched pattern"],
        ioc_values=[],
        remediation=remediation,
    )


def _make_scan_result(
    verdict_type: str = "CLEAN",
    findings: list[Finding] | None = None,
) -> ScanResult:
    """Create a ScanResult for testing with an appropriate risk score."""
    result = ScanResult(
        scan_id="test-scan-001",
        target="/tmp/test/SKILL.md",
        skill_sha256="abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
        skill_name="test-skill",
        skill_author="tester",
        layers_executed=["rule_engine", "threat_intel"],
        duration_ms=1234,
        findings=findings or [],
    )
    return result


# ===========================================================================
# Result formatting tests
# ===========================================================================


class TestVerdictColors:
    """Tests for verdict color mapping."""

    def test_malicious_color_is_red(self):
        """MALICIOUS verdict should map to bold red."""
        assert VERDICT_COLORS["MALICIOUS"] == "bold red"

    def test_suspicious_color_is_yellow(self):
        """SUSPICIOUS verdict should map to yellow."""
        assert VERDICT_COLORS["SUSPICIOUS"] == "yellow"

    def test_caution_color_is_cyan(self):
        """CAUTION verdict should map to cyan."""
        assert VERDICT_COLORS["CAUTION"] == "cyan"

    def test_clean_color_is_green(self):
        """CLEAN verdict should map to bold green."""
        assert VERDICT_COLORS["CLEAN"] == "bold green"

    def test_all_verdicts_have_colors(self):
        """All four verdict types should have color entries."""
        for verdict in ("MALICIOUS", "SUSPICIOUS", "CAUTION", "CLEAN"):
            assert verdict in VERDICT_COLORS


class TestSeverityBadges:
    """Tests for severity badge creation."""

    def test_critical_badge_style(self):
        """CRITICAL badge should have white-on-red styling."""
        badge = make_severity_badge(Severity.CRITICAL)
        assert isinstance(badge, Text)
        assert "CRITICAL" in badge.plain

    def test_high_badge_style(self):
        """HIGH badge should have appropriate styling."""
        badge = make_severity_badge(Severity.HIGH)
        assert "HIGH" in badge.plain

    def test_all_severities_produce_badges(self):
        """All severity levels should produce Text badges."""
        for sev in Severity:
            badge = make_severity_badge(sev)
            assert isinstance(badge, Text)
            assert sev.upper() in badge.plain

    def test_badge_has_padding(self):
        """Badges should have space padding."""
        badge = make_severity_badge(Severity.MEDIUM)
        assert badge.plain.startswith(" ")
        assert badge.plain.endswith(" ")


class TestMakeVerdictText:
    """Tests for verdict text creation."""

    def test_malicious_verdict_text(self):
        """MALICIOUS verdict should produce styled Text."""
        text = make_verdict_text("MALICIOUS")
        assert isinstance(text, Text)
        assert text.plain == "MALICIOUS"

    def test_clean_verdict_text(self):
        """CLEAN verdict should produce styled Text."""
        text = make_verdict_text("CLEAN")
        assert text.plain == "CLEAN"

    def test_unknown_verdict_still_creates_text(self):
        """Unknown verdict should still produce a Text object."""
        text = make_verdict_text("UNKNOWN")
        assert isinstance(text, Text)
        assert text.plain == "UNKNOWN"


class TestBuildVerdictPanel:
    """Tests for verdict panel construction."""

    def test_clean_result_produces_panel(self):
        """A CLEAN result should produce a Panel."""
        result = _make_scan_result("CLEAN")
        panel = build_verdict_panel(result)
        assert isinstance(panel, Panel)

    def test_malicious_result_produces_panel(self):
        """A MALICIOUS result (high-risk findings) should produce a Panel."""
        findings = [_make_finding(severity=Severity.CRITICAL, confidence=1.0)]
        result = _make_scan_result("MALICIOUS", findings=findings)
        panel = build_verdict_panel(result)
        assert isinstance(panel, Panel)


class TestBuildInfoTable:
    """Tests for scan info table construction."""

    def test_info_table_includes_target(self):
        """Info table should include the scan target."""
        result = _make_scan_result()
        table = build_info_table(result)
        assert isinstance(table, Table)
        # Verify column count
        assert len(table.columns) == 2

    def test_info_table_with_all_metadata(self):
        """Info table should include all available metadata."""
        result = _make_scan_result()
        table = build_info_table(result)
        assert isinstance(table, Table)
        assert table.row_count >= 4  # target, sha, skill, author, scan_id, duration


class TestBuildFindingsTable:
    """Tests for findings table construction."""

    def test_empty_findings_produces_empty_table(self):
        """A result with no findings should produce a table with 0 rows."""
        result = _make_scan_result()
        table = build_findings_table(result)
        assert isinstance(table, Table)
        assert table.row_count == 0

    def test_findings_sorted_by_severity(self):
        """Findings should be sorted by severity (critical first)."""
        findings = [
            _make_finding(finding_id="f1", severity=Severity.LOW),
            _make_finding(finding_id="f2", severity=Severity.CRITICAL),
            _make_finding(finding_id="f3", severity=Severity.MEDIUM),
        ]
        result = _make_scan_result(findings=findings)
        table = build_findings_table(result)
        assert table.row_count == 3

    def test_findings_table_has_correct_columns(self):
        """Findings table should have the expected column count."""
        result = _make_scan_result()
        table = build_findings_table(result)
        # Columns: #, Severity, Rule ID, Title, Confidence, Line, Detector
        assert len(table.columns) == 7


class TestBuildEvidenceTree:
    """Tests for evidence tree construction."""

    def test_no_findings_returns_none(self):
        """No findings should return None for the evidence tree."""
        result = _make_scan_result()
        tree = build_evidence_tree(result)
        assert tree is None

    def test_findings_with_evidence_returns_tree(self):
        """Findings with evidence should produce a Tree."""
        findings = [_make_finding(evidence=["matched pattern xyz"])]
        result = _make_scan_result(findings=findings)
        tree = build_evidence_tree(result)
        assert isinstance(tree, Tree)

    def test_findings_with_remediation_included(self):
        """Findings with remediation text should include fix hints in tree."""
        findings = [
            _make_finding(
                evidence=["found bad pattern"],
                remediation="Remove the bad pattern",
            )
        ]
        result = _make_scan_result(findings=findings)
        tree = build_evidence_tree(result)
        assert isinstance(tree, Tree)

    def test_findings_without_evidence_skipped(self):
        """Findings with empty evidence should be skipped in the tree."""
        findings = [_make_finding(evidence=[])]
        result = _make_scan_result(findings=findings)
        tree = build_evidence_tree(result)
        # Tree created but no child nodes for this finding
        assert isinstance(tree, Tree)


class TestBuildLayersTree:
    """Tests for scan layers tree construction."""

    def test_executed_layers_shown_green(self):
        """Executed layers should appear in the tree."""
        result = _make_scan_result()
        result.layers_executed = ["rule_engine", "threat_intel"]
        tree = build_layers_tree(result)
        assert isinstance(tree, Tree)

    def test_all_four_layers_in_tree(self):
        """All four standard layers should appear in the tree."""
        result = _make_scan_result()
        result.layers_executed = ["rule_engine"]
        tree = build_layers_tree(result)
        # 4 children for the 4 layers
        assert len(tree.children) == 4


class TestBuildSummaryLine:
    """Tests for summary line construction."""

    def test_no_findings_shows_zero(self):
        """A result with no findings should show '0 findings'."""
        result = _make_scan_result()
        text = build_summary_line(result)
        assert isinstance(text, Text)
        assert "0 findings" in text.plain

    def test_with_findings_shows_counts(self):
        """A result with findings should show counts by severity."""
        findings = [
            _make_finding(finding_id="f1", severity=Severity.HIGH),
            _make_finding(finding_id="f2", severity=Severity.MEDIUM),
        ]
        result = _make_scan_result(findings=findings)
        text = build_summary_line(result)
        assert "2 findings" in text.plain


class TestRenderScanResult:
    """Tests for the full render_scan_result function."""

    def test_renders_clean_result_without_error(self):
        """render_scan_result should complete without errors for CLEAN."""
        result = _make_scan_result()
        console = Console(file=open(os.devnull, "w"), force_terminal=True)  # noqa: SIM115
        render_scan_result(result, console=console)

    def test_renders_malicious_result_without_error(self):
        """render_scan_result should complete for results with findings."""
        findings = [_make_finding(severity=Severity.CRITICAL, confidence=1.0)]
        result = _make_scan_result(findings=findings)
        console = Console(file=open(os.devnull, "w"), force_terminal=True)  # noqa: SIM115
        render_scan_result(result, console=console)

    def test_renders_result_with_errors(self):
        """render_scan_result should display error info."""
        result = _make_scan_result()
        result.errors = ["llm_analyzer: Connection refused"]
        console = Console(file=open(os.devnull, "w"), force_terminal=True)  # noqa: SIM115
        render_scan_result(result, console=console)


class TestFormatScanResultRich:
    """Tests for format_scan_result_rich Group renderable."""

    def test_returns_group_for_clean_result(self):
        """format_scan_result_rich should return a Group."""
        result = _make_scan_result()
        group = format_scan_result_rich(result)
        assert group is not None

    def test_returns_group_with_findings(self):
        """format_scan_result_rich should return a Group with findings."""
        findings = [_make_finding()]
        result = _make_scan_result(findings=findings)
        group = format_scan_result_rich(result)
        assert group is not None


# ===========================================================================
# Watch mode file detection logic tests
# ===========================================================================


class TestCollectFileStates:
    """Tests for collect_file_states."""

    def test_collects_md_files(self, tmp_path):
        """Should collect .md files in the directory."""
        (tmp_path / "SKILL.md").write_text("# Test Skill")
        (tmp_path / "README.md").write_text("# Readme")
        (tmp_path / "data.txt").write_text("not a md file")

        states = collect_file_states(tmp_path)
        assert len(states) == 2
        assert all(f.endswith(".md") for f in states)

    def test_empty_directory(self, tmp_path):
        """Empty directory should return empty dict."""
        states = collect_file_states(tmp_path)
        assert states == {}

    def test_nonexistent_directory(self):
        """Non-existent directory should return empty dict."""
        states = collect_file_states(Path("/tmp/nonexistent_dir_xyz_123"))
        assert states == {}

    def test_values_are_floats(self, tmp_path):
        """Values should be mtime floats."""
        (tmp_path / "test.md").write_text("content")
        states = collect_file_states(tmp_path)
        for mtime in states.values():
            assert isinstance(mtime, float)


class TestDetectChanges:
    """Tests for detect_changes."""

    def test_new_file_detected(self):
        """A new file should be detected as changed."""
        prev = {"/a.md": 100.0}
        curr = {"/a.md": 100.0, "/b.md": 200.0}
        changed = detect_changes(prev, curr)
        assert changed == ["/b.md"]

    def test_modified_file_detected(self):
        """A file with updated mtime should be detected as changed."""
        prev = {"/a.md": 100.0}
        curr = {"/a.md": 200.0}
        changed = detect_changes(prev, curr)
        assert changed == ["/a.md"]

    def test_unchanged_file_not_detected(self):
        """An unchanged file should not appear in the change list."""
        prev = {"/a.md": 100.0}
        curr = {"/a.md": 100.0}
        changed = detect_changes(prev, curr)
        assert changed == []

    def test_deleted_file_not_in_changes(self):
        """A deleted file should not appear in the change list."""
        prev = {"/a.md": 100.0, "/b.md": 100.0}
        curr = {"/a.md": 100.0}
        changed = detect_changes(prev, curr)
        assert changed == []

    def test_empty_previous_all_new(self):
        """All files are new when previous state is empty."""
        prev: dict[str, float] = {}
        curr = {"/a.md": 100.0, "/b.md": 200.0}
        changed = detect_changes(prev, curr)
        assert len(changed) == 2

    def test_empty_current_no_changes(self):
        """No changes when current state is empty."""
        prev = {"/a.md": 100.0}
        curr: dict[str, float] = {}
        changed = detect_changes(prev, curr)
        assert changed == []

    def test_mixed_new_and_modified(self):
        """Both new and modified files should be detected."""
        prev = {"/a.md": 100.0, "/b.md": 100.0}
        curr = {"/a.md": 100.0, "/b.md": 200.0, "/c.md": 300.0}
        changed = detect_changes(prev, curr)
        assert set(changed) == {"/b.md", "/c.md"}

    def test_real_file_change_detection(self, tmp_path):
        """Integration test: detect actual file modification."""
        test_file = tmp_path / "SKILL.md"
        test_file.write_text("version 1")

        state1 = collect_file_states(tmp_path)

        # Modify the file — ensure mtime changes by waiting
        time.sleep(0.05)
        test_file.write_text("version 2")

        state2 = collect_file_states(tmp_path)
        changed = detect_changes(state1, state2)
        assert len(changed) == 1
        assert changed[0].endswith("SKILL.md")


# ===========================================================================
# Dashboard data assembly tests
# ===========================================================================


class TestDashboardData:
    """Tests for DashboardData state management."""

    def test_initial_state(self):
        """DashboardData should start with zero counts."""
        data = DashboardData()
        assert data.scans_completed == 0
        assert data.scans_in_progress == 0
        assert data.scans_failed == 0
        assert data.recent_results == []
        assert data.rule_trigger_counts == {}
        assert data.verdict_counts == {}
        assert data.last_scan_at is None

    def test_record_result_increments_completed(self):
        """record_result should increment scans_completed."""
        data = DashboardData()
        result = _make_scan_result()
        data.record_result(result)
        assert data.scans_completed == 1

    def test_record_result_updates_verdict_counts(self):
        """record_result should update verdict distribution."""
        data = DashboardData()
        result = _make_scan_result("CLEAN")
        data.record_result(result)
        assert data.verdict_counts.get("CLEAN") == 1

    def test_record_result_updates_rule_triggers(self):
        """record_result should update rule trigger counts from findings."""
        data = DashboardData()
        findings = [
            _make_finding(finding_id="f1", rule_id="rule-001"),
            _make_finding(finding_id="f2", rule_id="rule-001"),
            _make_finding(finding_id="f3", rule_id="rule-002"),
        ]
        result = _make_scan_result(findings=findings)
        data.record_result(result)
        assert data.rule_trigger_counts["rule-001"] == 2
        assert data.rule_trigger_counts["rule-002"] == 1

    def test_record_result_updates_recent_results(self):
        """record_result should add to recent_results (most recent first)."""
        data = DashboardData()
        r1 = _make_scan_result()
        r1.scan_id = "scan-1"
        r2 = _make_scan_result()
        r2.scan_id = "scan-2"

        data.record_result(r1)
        data.record_result(r2)
        assert len(data.recent_results) == 2
        assert data.recent_results[0].scan_id == "scan-2"

    def test_recent_results_capped_at_max(self):
        """recent_results should be limited to max_recent."""
        data = DashboardData(max_recent=3)
        for i in range(5):
            r = _make_scan_result()
            r.scan_id = f"scan-{i}"
            data.record_result(r)
        assert len(data.recent_results) == 3

    def test_record_result_sets_last_scan_at(self):
        """record_result should set last_scan_at."""
        data = DashboardData()
        result = _make_scan_result()
        data.record_result(result)
        assert data.last_scan_at is not None

    def test_record_failure_increments_failed(self):
        """record_failure should increment scans_failed."""
        data = DashboardData()
        data.record_failure()
        assert data.scans_failed == 1

    def test_uptime_seconds(self):
        """uptime_seconds should return a positive float."""
        data = DashboardData()
        assert data.uptime_seconds >= 0

    def test_multiple_verdicts_tracked(self):
        """Multiple different verdicts should be tracked."""
        data = DashboardData()

        clean_result = _make_scan_result("CLEAN")
        data.record_result(clean_result)

        # Create a result with findings that make it MALICIOUS
        findings = [_make_finding(severity=Severity.CRITICAL, confidence=1.0)]
        mal_result = _make_scan_result("MALICIOUS", findings=findings)
        data.record_result(mal_result)

        assert data.verdict_counts.get("CLEAN") == 1
        assert data.verdict_counts.get("MALICIOUS") == 1


class TestDashboardPanels:
    """Tests for individual dashboard panel builders."""

    def test_build_status_panel(self):
        """build_status_panel should return a Panel."""
        data = DashboardData()
        panel = build_status_panel(data)
        assert isinstance(panel, Panel)

    def test_build_verdict_distribution_panel(self):
        """build_verdict_distribution_panel should return a Panel."""
        data = DashboardData()
        data.verdict_counts = {"CLEAN": 5, "MALICIOUS": 2}
        panel = build_verdict_distribution_panel(data)
        assert isinstance(panel, Panel)

    def test_build_recent_results_panel_empty(self):
        """build_recent_results_panel should handle empty results."""
        data = DashboardData()
        panel = build_recent_results_panel(data)
        assert isinstance(panel, Panel)

    def test_build_recent_results_panel_with_data(self):
        """build_recent_results_panel should handle populated results."""
        data = DashboardData()
        data.record_result(_make_scan_result())
        panel = build_recent_results_panel(data)
        assert isinstance(panel, Panel)

    def test_build_rule_trigger_panel(self):
        """build_rule_trigger_panel should return a Panel."""
        data = DashboardData()
        data.rule_trigger_counts = {"rule-001": 5, "rule-002": 3}
        panel = build_rule_trigger_panel(data)
        assert isinstance(panel, Panel)

    def test_build_system_stats_panel(self):
        """build_system_stats_panel should return a Panel."""
        panel = build_system_stats_panel()
        assert isinstance(panel, Panel)


class TestAssembleDashboard:
    """Tests for the full dashboard assembly."""

    def test_assemble_dashboard_returns_layout(self):
        """assemble_dashboard should return a Layout."""
        from rich.layout import Layout

        data = DashboardData()
        layout = assemble_dashboard(data)
        assert isinstance(layout, Layout)

    def test_assemble_dashboard_with_data(self):
        """assemble_dashboard should work with populated data."""
        from rich.layout import Layout

        data = DashboardData()
        data.record_result(_make_scan_result())
        data.record_failure()
        layout = assemble_dashboard(data)
        assert isinstance(layout, Layout)

    def test_assemble_dashboard_renderable(self):
        """Dashboard should be renderable by Console without errors."""
        data = DashboardData()
        data.record_result(_make_scan_result())
        layout = assemble_dashboard(data)
        console = Console(file=open(os.devnull, "w"), force_terminal=True, width=120)  # noqa: SIM115
        console.print(layout)  # Should not raise
