# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI command for diff scanning — compare two versions of a skill."""

from __future__ import annotations

import asyncio
import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from malwar.scanner.diff import DiffResult

app = typer.Typer(help="Compare two versions of a SKILL.md file.")


class DiffFormat(StrEnum):
    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


def _format_text(result: DiffResult) -> str:
    """Render a human-readable diff report."""
    lines: list[str] = []

    lines.append("malwar diff report")
    lines.append("=" * 60)
    lines.append("")

    # Verdict change
    if result.verdict_changed:
        lines.append(
            f"Verdict: {result.old_verdict} -> {result.new_verdict}"
        )
    else:
        lines.append(f"Verdict: {result.new_verdict} (unchanged)")

    # Risk delta
    if result.risk_delta > 0:
        lines.append(f"Risk delta: +{result.risk_delta}")
    elif result.risk_delta < 0:
        lines.append(f"Risk delta: {result.risk_delta}")
    else:
        lines.append("Risk delta: 0 (no change)")

    lines.append(
        f"Old risk: {result.old_scan.risk_score}  |  "
        f"New risk: {result.new_scan.risk_score}"
    )
    lines.append("")

    # New findings (highlighted)
    if result.new_findings:
        lines.append(f"[+] NEW FINDINGS ({len(result.new_findings)}):")
        lines.append("-" * 40)
        for f in result.new_findings:
            lines.append(
                f"  + {f.rule_id}  [{f.severity}]  {f.title}"
            )
            if f.evidence:
                for ev in f.evidence[:2]:
                    lines.append(f"    evidence: {ev}")
        lines.append("")

    # Removed findings
    if result.removed_findings:
        lines.append(f"[-] REMOVED FINDINGS ({len(result.removed_findings)}):")
        lines.append("-" * 40)
        for f in result.removed_findings:
            lines.append(
                f"  - {f.rule_id}  [{f.severity}]  {f.title}"
            )
        lines.append("")

    # Unchanged findings
    if result.unchanged_findings:
        lines.append(
            f"[=] UNCHANGED FINDINGS ({len(result.unchanged_findings)}):"
        )
        lines.append("-" * 40)
        for f in result.unchanged_findings:
            lines.append(
                f"  = {f.rule_id}  [{f.severity}]  {f.title}"
            )
        lines.append("")

    # Summary
    lines.append("Summary:")
    lines.append(f"  New:       {len(result.new_findings)}")
    lines.append(f"  Removed:   {len(result.removed_findings)}")
    lines.append(f"  Unchanged: {len(result.unchanged_findings)}")

    return "\n".join(lines)


def _format_json(result: DiffResult) -> str:
    """Render a JSON diff report."""

    def _finding_to_dict(f):
        return {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": str(f.severity),
            "confidence": f.confidence,
            "category": str(f.category),
            "detector_layer": str(f.detector_layer),
            "evidence": f.evidence,
        }

    data = {
        "verdict_changed": result.verdict_changed,
        "old_verdict": result.old_verdict,
        "new_verdict": result.new_verdict,
        "risk_delta": result.risk_delta,
        "old_risk_score": result.old_scan.risk_score,
        "new_risk_score": result.new_scan.risk_score,
        "new_findings": [_finding_to_dict(f) for f in result.new_findings],
        "removed_findings": [
            _finding_to_dict(f) for f in result.removed_findings
        ],
        "unchanged_findings": [
            _finding_to_dict(f) for f in result.unchanged_findings
        ],
        "old_scan_id": result.old_scan.scan_id,
        "new_scan_id": result.new_scan.scan_id,
    }
    return json.dumps(data, indent=2)


def _format_sarif(result: DiffResult) -> str:
    """Render a SARIF report containing only the *new* findings."""
    from malwar.cli.formatters.sarif import scan_result_to_sarif

    # Build a synthetic ScanResult containing only new findings
    from malwar.models.scan import ScanResult

    synthetic = ScanResult(
        scan_id=result.new_scan.scan_id,
        target=result.new_scan.target,
        status=result.new_scan.status,
        findings=result.new_findings,
        skill_sha256=result.new_scan.skill_sha256,
        layers_executed=result.new_scan.layers_executed,
    )
    sarif = scan_result_to_sarif(synthetic)
    sarif["properties"] = {
        "diff": True,
        "verdict_changed": result.verdict_changed,
        "old_verdict": result.old_verdict,
        "new_verdict": result.new_verdict,
        "risk_delta": result.risk_delta,
    }
    return json.dumps(sarif, indent=2)


@app.command(name="diff")
def diff_command(
    old_file: Annotated[
        Path, typer.Argument(help="Path to the old (baseline) SKILL.md")
    ],
    new_file: Annotated[
        Path, typer.Argument(help="Path to the new (updated) SKILL.md")
    ],
    fmt: Annotated[
        DiffFormat,
        typer.Option("--format", "-f", help="Output format"),
    ] = DiffFormat.TEXT,
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Skip LLM analysis layer")
    ] = False,
    no_urls: Annotated[
        bool, typer.Option("--no-urls", help="Skip URL crawling layer")
    ] = False,
    layers: Annotated[
        str | None,
        typer.Option("--layers", help="Comma-separated layers to run"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
) -> None:
    """Compare two versions of a SKILL.md and flag newly introduced threats."""
    if not old_file.is_file():
        typer.echo(f"Old file not found: {old_file}", err=True)
        raise typer.Exit(1)
    if not new_file.is_file():
        typer.echo(f"New file not found: {new_file}", err=True)
        raise typer.Exit(1)

    exit_code = asyncio.run(
        _async_diff(old_file, new_file, fmt, no_llm, no_urls, layers, output)
    )
    raise typer.Exit(exit_code)


async def _async_diff(
    old_file: Path,
    new_file: Path,
    fmt: DiffFormat,
    no_llm: bool,
    no_urls: bool,
    layers_str: str | None,
    output: Path | None,
) -> int:
    """Run the diff scan and return the exit code."""
    from malwar.scanner.diff import diff_scan

    old_content = old_file.read_text(encoding="utf-8")
    new_content = new_file.read_text(encoding="utf-8")

    layer_list: list[str] | None = None
    if layers_str:
        layer_list = [layer.strip() for layer in layers_str.split(",")]

    result = await diff_scan(
        old_content,
        new_content,
        file_name=new_file.name,
        use_llm=not no_llm,
        use_urls=not no_urls,
        layers=layer_list,
    )

    if fmt == DiffFormat.TEXT:
        text = _format_text(result)
    elif fmt == DiffFormat.JSON:
        text = _format_json(result)
    elif fmt == DiffFormat.SARIF:
        text = _format_sarif(result)
    else:
        text = _format_text(result)

    if output:
        output.write_text(text)
        typer.echo(f"Output written to {output}")
    else:
        sys.stdout.write(text + "\n")

    # Exit code 1 if new findings were introduced, 0 otherwise
    return 1 if result.new_findings else 0
