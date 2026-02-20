# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Malwar SKILL.md scanner for GitHub Actions.

Finds files matching a glob pattern, scans each with the malwar SDK,
and reports results in the requested format. Sets GitHub Action outputs
and exits with code 1 if any file meets or exceeds the fail-on threshold.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from glob import glob
from pathlib import Path
from typing import Any

from malwar import __version__, scan
from malwar.cli.formatters.sarif import scan_result_to_sarif
from malwar.models.scan import ScanResult

logger = logging.getLogger("malwar.action")

# Verdict severity ordering (lowest to highest)
VERDICT_ORDER: dict[str, int] = {
    "CLEAN": 0,
    "CAUTION": 1,
    "SUSPICIOUS": 2,
    "MALICIOUS": 3,
}

SARIF_OUTPUT_FILE = "malwar-results.sarif"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Scan SKILL.md files for threats using Malwar.",
    )
    parser.add_argument(
        "--path",
        default="**/SKILL.md",
        help="Glob pattern for files to scan (default: **/SKILL.md)",
    )
    parser.add_argument(
        "--fail-on",
        default="SUSPICIOUS",
        choices=["CAUTION", "SUSPICIOUS", "MALICIOUS"],
        help="Verdict threshold that triggers failure (default: SUSPICIOUS)",
    )
    parser.add_argument(
        "--format",
        default="text",
        choices=["text", "json", "sarif"],
        dest="output_format",
        help="Output format (default: text)",
    )
    return parser.parse_args(argv)


def find_files(pattern: str) -> list[Path]:
    """Find all files matching the glob pattern."""
    matches = sorted(glob(pattern, recursive=True))
    return [Path(m) for m in matches if Path(m).is_file()]


def verdict_meets_threshold(verdict: str, threshold: str) -> bool:
    """Return True if the verdict meets or exceeds the threshold."""
    return VERDICT_ORDER.get(verdict, 0) >= VERDICT_ORDER.get(threshold, 0)


def worst_verdict(verdicts: list[str]) -> str:
    """Return the most severe verdict from a list."""
    if not verdicts:
        return "CLEAN"
    return max(verdicts, key=lambda v: VERDICT_ORDER.get(v, 0))


async def scan_files(files: list[Path]) -> list[tuple[Path, ScanResult]]:
    """Scan all files and return (path, result) pairs."""
    results: list[tuple[Path, ScanResult]] = []
    for file_path in files:
        content = file_path.read_text(encoding="utf-8")
        result = await scan(
            content,
            file_name=str(file_path),
            use_llm=False,
            use_urls=False,
        )
        results.append((file_path, result))
    return results


def format_text(results: list[tuple[Path, ScanResult]]) -> str:
    """Format scan results as human-readable text."""
    if not results:
        return "No SKILL.md files found to scan."

    lines: list[str] = []
    lines.append(f"Malwar Scan Results (v{__version__})")
    lines.append("=" * 50)

    for file_path, result in results:
        lines.append("")
        lines.append(f"File: {file_path}")
        lines.append(f"  Verdict:    {result.verdict}")
        lines.append(f"  Risk Score: {result.risk_score}/100")
        lines.append(f"  Findings:   {len(result.findings)}")

        for finding in result.findings:
            lines.append(f"    - [{finding.severity.upper()}] {finding.title}")
            if finding.location:
                lines.append(f"      Line {finding.location.line_start}: {finding.description}")
            else:
                lines.append(f"      {finding.description}")

    lines.append("")
    lines.append("-" * 50)
    all_verdicts = [r.verdict for _, r in results]
    lines.append(f"Overall: {worst_verdict(all_verdicts)}")

    return "\n".join(lines)


def format_json(results: list[tuple[Path, ScanResult]]) -> str:
    """Format scan results as JSON."""
    output: list[dict[str, Any]] = []
    for file_path, result in results:
        output.append({
            "file": str(file_path),
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "finding_count": len(result.findings),
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "description": f.description,
                }
                for f in result.findings
            ],
        })
    return json.dumps(output, indent=2)


def format_sarif(results: list[tuple[Path, ScanResult]]) -> str:
    """Format scan results as SARIF 2.1.0 and write to file."""
    if not results:
        sarif: dict[str, Any] = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "malwar",
                        "version": __version__,
                        "rules": [],
                    }
                },
                "results": [],
            }],
        }
    elif len(results) == 1:
        _, result = results[0]
        sarif = scan_result_to_sarif(result)
    else:
        # Merge multiple results into a single SARIF run
        all_rules: list[dict[str, Any]] = []
        all_results: list[dict[str, Any]] = []
        seen_rules: set[str] = set()

        for _, result in results:
            single = scan_result_to_sarif(result)
            run = single["runs"][0]
            for rule in run["tool"]["driver"]["rules"]:
                if rule["id"] not in seen_rules:
                    seen_rules.add(rule["id"])
                    all_rules.append(rule)
            all_results.extend(run["results"])

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "malwar",
                        "version": __version__,
                        "rules": all_rules,
                    }
                },
                "results": all_results,
            }],
        }

    sarif_str = json.dumps(sarif, indent=2)

    # Write SARIF file to disk
    Path(SARIF_OUTPUT_FILE).write_text(sarif_str, encoding="utf-8")

    return sarif_str


def set_github_output(name: str, value: str) -> None:
    """Write a key=value pair to $GITHUB_OUTPUT."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the scan script."""
    args = parse_args(argv)

    # Discover files
    files = find_files(args.path)
    sys.stdout.write(f"Found {len(files)} file(s) matching '{args.path}'\n")

    if not files:
        set_github_output("verdict", "CLEAN")
        set_github_output("risk_score", "0")
        set_github_output("finding_count", "0")
        sys.stdout.write("No files to scan. Exiting clean.\n")
        return 0

    # Run scans
    results = asyncio.run(scan_files(files))

    # Compute aggregates
    verdicts = [r.verdict for _, r in results]
    overall = worst_verdict(verdicts)
    max_score = max((r.risk_score for _, r in results), default=0)
    total_findings = sum(len(r.findings) for _, r in results)

    # Format output
    formatters = {
        "text": format_text,
        "json": format_json,
        "sarif": format_sarif,
    }
    formatter = formatters[args.output_format]
    output = formatter(results)
    sys.stdout.write(output + "\n")

    # Set GitHub Action outputs
    set_github_output("verdict", overall)
    set_github_output("risk_score", str(max_score))
    set_github_output("finding_count", str(total_findings))
    if args.output_format == "sarif":
        set_github_output("sarif_path", SARIF_OUTPUT_FILE)

    # Determine exit code
    should_fail = verdict_meets_threshold(overall, args.fail_on)
    if should_fail:
        sys.stdout.write(f"\nFailed: verdict '{overall}' meets or exceeds threshold '{args.fail_on}'\n")
        return 1

    sys.stdout.write(f"\nPassed: verdict '{overall}' is below threshold '{args.fail_on}'\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
