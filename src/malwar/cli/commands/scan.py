# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Scan command — the primary CLI entry point."""

from __future__ import annotations

import asyncio
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer()


class OutputFormat(StrEnum):
    CONSOLE = "console"
    SARIF = "sarif"
    JSON = "json"


def _run_scan(
    target: str,
    fmt: OutputFormat,
    output: Path | None,
    no_llm: bool,
    no_urls: bool,
    layers_str: str | None,
) -> None:
    """Synchronous wrapper for the async scan."""
    asyncio.run(_async_scan(target, fmt, output, no_llm, no_urls, layers_str))


async def _async_scan(
    target: str,
    fmt: OutputFormat,
    output: Path | None,
    no_llm: bool,
    no_urls: bool,
    layers_str: str | None,
) -> None:
    from malwar.core.config import get_settings
    from malwar.scanner.pipeline import ScanPipeline
    from malwar.detectors.rule_engine.detector import RuleEngineDetector
    from malwar.detectors.url_crawler.detector import UrlCrawlerDetector
    from malwar.detectors.llm_analyzer.detector import LlmAnalyzerDetector
    from malwar.detectors.threat_intel.detector import ThreatIntelDetector

    settings = get_settings()

    # Build layer list
    if layers_str:
        layers = [l.strip() for l in layers_str.split(",")]
    else:
        layers = list(settings.scan_default_layers)
        if no_llm and "llm_analyzer" in layers:
            layers.remove("llm_analyzer")
        if no_urls and "url_crawler" in layers:
            layers.remove("url_crawler")

    # Create pipeline with all detectors
    pipeline = ScanPipeline(settings=settings)
    pipeline.register_detector(RuleEngineDetector())
    pipeline.register_detector(UrlCrawlerDetector(settings=settings))
    pipeline.register_detector(LlmAnalyzerDetector(settings=settings))
    pipeline.register_detector(ThreatIntelDetector())

    target_path = Path(target)

    if target_path.is_dir():
        # Scan all .md files in directory
        from malwar.cli.formatters.console import console

        md_files = sorted(target_path.glob("*.md"))
        if not md_files:
            console.print(f"No .md files found in {target}", style="red")
            raise typer.Exit(1)

        results = []
        for md_file in md_files:
            result = await pipeline.scan_file(str(md_file), layers=layers)
            results.append(result)
            if fmt == OutputFormat.CONSOLE:
                from malwar.cli.formatters.console import format_scan_result

                format_scan_result(result)

        if fmt == OutputFormat.SARIF:
            # Combine all results into one SARIF report
            combined = results[0] if results else None
            if combined and len(results) > 1:
                for r in results[1:]:
                    combined.findings.extend(r.findings)
            if combined:
                _output_formatted(combined, fmt, output)
        elif fmt == OutputFormat.JSON:
            import json

            data = [r.model_dump(mode="json") for r in results]
            text = json.dumps(data, indent=2)
            _write_output(text, output)

    elif target_path.is_file():
        result = await pipeline.scan_file(str(target_path), layers=layers)
        _output_formatted(result, fmt, output)

    else:
        # Treat as URL or raw content
        from malwar.cli.formatters.console import console

        console.print(f"Target not found: {target}", style="red")
        raise typer.Exit(1)


def _output_formatted(
    result: "ScanResult",  # type: ignore[name-defined]
    fmt: OutputFormat,
    output: Path | None,
) -> None:
    if fmt == OutputFormat.CONSOLE:
        from malwar.cli.formatters.console import format_scan_result

        format_scan_result(result)
    elif fmt == OutputFormat.SARIF:
        from malwar.cli.formatters.sarif import format_sarif

        text = format_sarif(result)
        _write_output(text, output)
    elif fmt == OutputFormat.JSON:
        from malwar.cli.formatters.json_fmt import format_json

        text = format_json(result)
        _write_output(text, output)


def _write_output(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text)
        from malwar.cli.formatters.console import console

        console.print(f"Output written to {output}", style="green")
    else:
        sys.stdout.write(text + "\n")


@app.callback(invoke_without_command=True)
def scan(
    target: Annotated[
        str, typer.Argument(help="SKILL.md file, directory, or URL to scan")
    ],
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format"),
    ] = OutputFormat.CONSOLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
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
) -> None:
    """Scan a SKILL.md file, directory, or URL for malware."""
    _run_scan(target, fmt, output, no_llm, no_urls, layers)
