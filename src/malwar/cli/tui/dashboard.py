# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Live dashboard panel showing scan status, recent results, and system stats."""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from datetime import UTC, datetime

from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from malwar.cli.tui.results import VERDICT_COLORS
from malwar.models.scan import ScanResult


@dataclass
class DashboardData:
    """Aggregated data used to render the dashboard."""

    # Scan status
    scans_completed: int = 0
    scans_in_progress: int = 0
    scans_failed: int = 0

    # Recent results (most recent first)
    recent_results: list[ScanResult] = field(default_factory=list)
    max_recent: int = 10

    # Rule trigger counts: rule_id -> count
    rule_trigger_counts: dict[str, int] = field(default_factory=dict)

    # Verdict distribution
    verdict_counts: dict[str, int] = field(default_factory=dict)

    # Timing
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_scan_at: datetime | None = None

    def record_result(self, result: ScanResult) -> None:
        """Record a completed scan result into dashboard stats."""
        self.scans_completed += 1
        self.last_scan_at = datetime.now(UTC)

        # Update verdict counts
        verdict = result.verdict
        self.verdict_counts[verdict] = self.verdict_counts.get(verdict, 0) + 1

        # Update rule trigger counts
        for finding in result.findings:
            self.rule_trigger_counts[finding.rule_id] = (
                self.rule_trigger_counts.get(finding.rule_id, 0) + 1
            )

        # Add to recent results
        self.recent_results.insert(0, result)
        if len(self.recent_results) > self.max_recent:
            self.recent_results = self.recent_results[: self.max_recent]

    def record_failure(self) -> None:
        """Record a failed scan."""
        self.scans_failed += 1

    @property
    def uptime_seconds(self) -> float:
        """Return seconds since dashboard started."""
        return (datetime.now(UTC) - self.started_at).total_seconds()


def build_status_panel(data: DashboardData) -> Panel:
    """Build a panel showing scan status summary."""
    uptime = int(data.uptime_seconds)
    hours, remainder = divmod(uptime, 3600)
    minutes, seconds = divmod(remainder, 60)

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("key", style="dim", no_wrap=True)
    table.add_column("value", style="bold")

    table.add_row("Scans Completed:", str(data.scans_completed))
    table.add_row("In Progress:", str(data.scans_in_progress))
    table.add_row("Failed:", str(data.scans_failed))
    table.add_row("Uptime:", f"{hours}h {minutes}m {seconds}s")
    if data.last_scan_at:
        table.add_row("Last Scan:", data.last_scan_at.strftime("%H:%M:%S"))

    return Panel(table, title="Scan Status", border_style="blue")


def build_verdict_distribution_panel(data: DashboardData) -> Panel:
    """Build a panel showing verdict distribution counts."""
    table = Table(show_header=True, box=None, padding=(0, 2))
    table.add_column("Verdict", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Bar", width=20)

    total = max(sum(data.verdict_counts.values()), 1)

    for verdict in ["MALICIOUS", "SUSPICIOUS", "CAUTION", "CLEAN"]:
        count = data.verdict_counts.get(verdict, 0)
        color = VERDICT_COLORS.get(verdict, "white")
        bar_len = int((count / total) * 20) if count > 0 else 0
        bar = Text("=" * bar_len, style=color)
        table.add_row(Text(verdict, style=color), str(count), bar)

    return Panel(table, title="Verdict Distribution", border_style="blue")


def build_recent_results_panel(data: DashboardData) -> Panel:
    """Build a panel showing recent scan results."""
    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("Time", style="dim", width=8)
    table.add_column("Target", max_width=30, no_wrap=True)
    table.add_column("Verdict", width=12)
    table.add_column("Score", justify="right", width=5)
    table.add_column("Findings", justify="right", width=8)

    for result in data.recent_results[:8]:
        verdict_style = VERDICT_COLORS.get(result.verdict, "white")
        time_str = result.started_at.strftime("%H:%M:%S")
        target_short = result.target
        if len(target_short) > 28:
            target_short = "..." + target_short[-25:]
        table.add_row(
            time_str,
            target_short,
            Text(result.verdict, style=verdict_style),
            str(result.risk_score),
            str(len(result.findings)),
        )

    if not data.recent_results:
        table.add_row("--", "No scans yet", "--", "--", "--")

    return Panel(table, title="Recent Results", border_style="blue")


def build_rule_trigger_panel(data: DashboardData) -> Panel:
    """Build a panel showing top triggered rules."""
    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Triggers", justify="right", width=8)

    sorted_rules = sorted(data.rule_trigger_counts.items(), key=lambda x: x[1], reverse=True)

    for rule_id, count in sorted_rules[:10]:
        table.add_row(rule_id, str(count))

    if not sorted_rules:
        table.add_row("--", "--")

    return Panel(table, title="Top Rule Triggers", border_style="blue")


def build_system_stats_panel() -> Panel:
    """Build a panel showing system information."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("key", style="dim", no_wrap=True)
    table.add_column("value")

    table.add_row("Platform:", platform.system())
    table.add_row("Python:", platform.python_version())
    table.add_row("PID:", str(os.getpid()))

    try:
        load = os.getloadavg()
        table.add_row("Load Avg:", f"{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}")
    except (OSError, AttributeError):
        table.add_row("Load Avg:", "N/A")

    return Panel(table, title="System", border_style="dim")


def assemble_dashboard(data: DashboardData) -> Layout:
    """Assemble the full dashboard layout from individual panels."""
    layout = Layout()

    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )

    # Header
    layout["header"].update(
        Panel(
            Text("malwar Interactive Dashboard", style="bold blue", justify="center"),
            style="blue",
        )
    )

    # Body — top row: status + verdicts, bottom row: results + rules + system
    layout["body"].split_column(
        Layout(name="top_row", size=12),
        Layout(name="bottom_row"),
    )

    layout["top_row"].split_row(
        Layout(build_status_panel(data), name="status"),
        Layout(build_verdict_distribution_panel(data), name="verdicts"),
    )

    layout["bottom_row"].split_row(
        Layout(build_recent_results_panel(data), name="recent", ratio=3),
        Layout(name="right_col", ratio=2),
    )

    layout["right_col"].split_column(
        Layout(build_rule_trigger_panel(data), name="rules"),
        Layout(build_system_stats_panel(), name="system", size=9),
    )

    # Footer
    footer_text = Text(
        "Press Ctrl+C to exit  |  malwar interactive mode",
        style="dim",
        justify="center",
    )
    layout["footer"].update(Panel(footer_text, style="dim"))

    return layout
