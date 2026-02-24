# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Rich console output formatter for scan results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from malwar import __version__
from malwar.core.constants import Severity
from malwar.models.scan import ScanResult

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

VERDICT_COLORS = {
    "MALICIOUS": "bold red",
    "SUSPICIOUS": "yellow",
    "CAUTION": "cyan",
    "CLEAN": "bold green",
}


def format_scan_result(result: ScanResult) -> None:
    """Print a scan result to the console with Rich formatting."""
    console.print()
    console.print(f"[bold]malwar v{__version__}[/bold] - Agentic Skills Malware Scanner")
    console.print()

    # Target info
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("key", style="dim")
    info_table.add_column("value")
    info_table.add_row("Target:", result.target)
    info_table.add_row("SHA256:", result.skill_sha256[:16] + "..." if result.skill_sha256 else "N/A")
    if result.skill_name:
        info_table.add_row("Skill:", result.skill_name)
    if result.skill_author:
        info_table.add_row("Author:", result.skill_author)
    console.print(info_table)
    console.print()

    # Verdict banner
    verdict_color = VERDICT_COLORS.get(result.verdict, "white")
    console.print(
        Panel(
            f"[{verdict_color}]VERDICT: {result.verdict}[/{verdict_color}]"
            f"  (risk score: {result.risk_score}/100)",
            style=verdict_color,
        )
    )
    console.print()

    # Findings
    if result.findings:
        for finding in sorted(
            result.findings,
            key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity),
        ):
            sev_color = SEVERITY_COLORS.get(finding.severity, "white")
            sev_label = Text(finding.severity.upper().ljust(9), style=sev_color)

            console.print(sev_label, end="")
            console.print(f"  [bold]{finding.rule_id}[/bold]  {finding.title}")

            if finding.location and finding.location.snippet:
                snippet = finding.location.snippet[:120]
                line_info = f"Line {finding.location.line_start}"
                console.print(f"          {line_info}: {snippet}", style="dim")

            if finding.evidence:
                for ev in finding.evidence[:2]:
                    console.print(f"          {ev}", style="dim italic")

            console.print(f"          Confidence: {finding.confidence:.2f}", style="dim")
            console.print()
    else:
        console.print("  No threats detected.", style="bold green")
        console.print()

    # Summary line
    counts = result.finding_count_by_severity
    parts = []
    for sev in ["critical", "high", "medium", "low"]:
        if sev in counts:
            parts.append(f"{counts[sev]} {sev}")
    summary = ", ".join(parts) if parts else "0 findings"
    console.print(f"  Summary: {len(result.findings)} findings ({summary})")
    console.print(f"  Layers:  {', '.join(result.layers_executed)}")
    if result.duration_ms is not None:
        console.print(f"  Duration: {result.duration_ms / 1000:.1f}s")
    if result.errors:
        console.print(f"  Errors: {len(result.errors)}", style="red")
    console.print()
