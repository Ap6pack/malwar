# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Rich-formatted scan result display with color-coded verdicts and severity badges."""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from malwar.core.constants import Severity
from malwar.models.scan import ScanResult

VERDICT_COLORS: dict[str, str] = {
    "MALICIOUS": "bold red",
    "SUSPICIOUS": "yellow",
    "CAUTION": "cyan",
    "CLEAN": "bold green",
}

SEVERITY_COLORS: dict[str, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_BADGE_STYLES: dict[str, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold white on dark_red",
    Severity.MEDIUM: "bold black on yellow",
    Severity.LOW: "bold black on cyan",
    Severity.INFO: "bold white on bright_black",
}


def make_severity_badge(severity: str) -> Text:
    """Create a Rich Text badge for a severity level."""
    label = f" {severity.upper()} "
    style = SEVERITY_BADGE_STYLES.get(severity, "dim")
    return Text(label, style=style)


def make_verdict_text(verdict: str) -> Text:
    """Create styled verdict text."""
    style = VERDICT_COLORS.get(verdict, "white")
    return Text(verdict, style=style)


def build_verdict_panel(result: ScanResult) -> Panel:
    """Build a Rich Panel showing the scan verdict prominently."""
    verdict_color = VERDICT_COLORS.get(result.verdict, "white")
    content = Text.assemble(
        ("VERDICT: ", "bold"),
        (result.verdict, verdict_color),
        ("  ", ""),
        (f"Risk Score: {result.risk_score}/100", "dim"),
    )
    return Panel(content, style=verdict_color, title="Scan Verdict", title_align="left")


def build_info_table(result: ScanResult) -> Table:
    """Build a table showing scan metadata."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("key", style="dim", no_wrap=True)
    table.add_column("value")
    table.add_row("Target:", result.target)
    if result.skill_sha256:
        table.add_row("SHA256:", result.skill_sha256[:16] + "...")
    if result.skill_name:
        table.add_row("Skill:", result.skill_name)
    if result.skill_author:
        table.add_row("Author:", result.skill_author)
    if result.scan_id:
        table.add_row("Scan ID:", result.scan_id)
    if result.duration_ms is not None:
        table.add_row("Duration:", f"{result.duration_ms / 1000:.1f}s")
    return table


def build_findings_table(result: ScanResult) -> Table:
    """Build a Rich Table of all findings with severity badges."""
    table = Table(
        title="Findings",
        title_style="bold",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Severity", width=12, justify="center")
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="bold")
    table.add_column("Confidence", justify="right", width=10)
    table.add_column("Line", justify="right", width=6)
    table.add_column("Detector", style="dim")

    sorted_findings = sorted(
        result.findings,
        key=lambda f: [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
        ].index(f.severity)
        if f.severity in list(Severity)
        else 99,
    )

    for i, finding in enumerate(sorted_findings, 1):
        badge = make_severity_badge(finding.severity)
        line_str = str(finding.location.line_start) if finding.location else "-"
        table.add_row(
            str(i),
            badge,
            finding.rule_id,
            finding.title,
            f"{finding.confidence:.0%}",
            line_str,
            finding.detector_layer,
        )

    return table


def build_evidence_tree(result: ScanResult) -> Tree | None:
    """Build a tree view of evidence per finding, for collapsible display."""
    if not result.findings:
        return None

    tree = Tree("[bold]Evidence Details[/bold]")

    for finding in result.findings:
        if not finding.evidence:
            continue
        badge = make_severity_badge(finding.severity)
        node_label = Text.assemble(badge, " ", (finding.rule_id, "cyan"), " ", finding.title)
        node = tree.add(node_label)

        for ev in finding.evidence:
            node.add(Text(ev, style="dim italic"))

        if finding.location and finding.location.snippet:
            node.add(
                Text(
                    f"Snippet (L{finding.location.line_start}): {finding.location.snippet[:120]}",
                    style="dim",
                )
            )

        if finding.remediation:
            node.add(Text(f"Fix: {finding.remediation}", style="green"))

    return tree


def build_layers_tree(result: ScanResult) -> Tree:
    """Build a tree view showing which scan layers were executed."""
    tree = Tree("[bold]Scan Layers[/bold]")
    all_layers = ["rule_engine", "url_crawler", "llm_analyzer", "threat_intel"]

    for layer in all_layers:
        if layer in result.layers_executed:
            tree.add(Text(f"{layer}", style="green"))
        else:
            tree.add(Text(f"{layer} (skipped)", style="dim strikethrough"))

    return tree


def build_summary_line(result: ScanResult) -> Text:
    """Build a one-line summary of finding counts."""
    counts = result.finding_count_by_severity
    parts: list[tuple[str, str]] = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if sev in counts:
            color = SEVERITY_COLORS.get(sev, "white")
            parts.append((f"{counts[sev]} {sev}", color))

    text = Text.assemble(
        (f"{len(result.findings)} findings", "bold"),
        (" (", "dim"),
    )
    for i, (label, style) in enumerate(parts):
        if i > 0:
            text.append(", ", style="dim")
        text.append(label, style=style)
    if not parts:
        text.append("0 issues", style="green")
    text.append(")", style="dim")
    return text


def render_scan_result(result: ScanResult, console: Console | None = None) -> None:
    """Render a complete scan result with Rich formatting.

    This is the main entry point for displaying scan results in the TUI.
    """
    if console is None:
        console = Console()

    console.print()
    console.print("[bold]malwar[/bold] - Agentic Skills Malware Scanner", style="bold blue")
    console.print()

    # Scan info
    console.print(build_info_table(result))
    console.print()

    # Verdict panel
    console.print(build_verdict_panel(result))
    console.print()

    # Findings table
    if result.findings:
        console.print(build_findings_table(result))
        console.print()

        # Evidence (collapsible sections)
        evidence_tree = build_evidence_tree(result)
        if evidence_tree:
            console.print(evidence_tree)
            console.print()
    else:
        console.print("[bold green]No threats detected.[/bold green]")
        console.print()

    # Layers tree
    console.print(build_layers_tree(result))
    console.print()

    # Summary line
    console.print(build_summary_line(result))

    if result.errors:
        console.print(f"[red]Errors: {len(result.errors)}[/red]")
        for err in result.errors:
            console.print(f"  [dim red]{err}[/dim red]")
    console.print()


def format_scan_result_rich(result: ScanResult) -> Group:
    """Return a Group renderable for embedding in Live displays / dashboards."""
    renderables = [
        build_info_table(result),
        build_verdict_panel(result),
    ]

    if result.findings:
        renderables.append(build_findings_table(result))
        evidence = build_evidence_tree(result)
        if evidence:
            renderables.append(evidence)
    else:
        renderables.append(Text("No threats detected.", style="bold green"))

    renderables.append(build_layers_tree(result))
    renderables.append(build_summary_line(result))

    return Group(*renderables)  # type: ignore[arg-type]
