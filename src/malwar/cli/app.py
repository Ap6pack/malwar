# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Typer CLI application root."""

from __future__ import annotations

import asyncio
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from malwar.cli.commands import db

app = typer.Typer(
    name="malwar",
    help="Malware detection engine for agentic skills (SKILL.md)",
    no_args_is_help=True,
)

app.add_typer(db.app, name="db", help="Database management")


class OutputFormat(StrEnum):
    CONSOLE = "console"
    SARIF = "sarif"
    JSON = "json"


@app.command()
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
    asyncio.run(_async_scan(target, fmt, output, no_llm, no_urls, layers))


async def _async_scan(
    target: str,
    fmt: OutputFormat,
    output: Path | None,
    no_llm: bool,
    no_urls: bool,
    layers_str: str | None,
) -> None:
    from malwar.core.config import get_settings
    from malwar.detectors.llm_analyzer.detector import LlmAnalyzerDetector
    from malwar.detectors.rule_engine.detector import RuleEngineDetector
    from malwar.detectors.threat_intel.detector import ThreatIntelDetector
    from malwar.detectors.url_crawler.detector import UrlCrawlerDetector
    from malwar.scanner.pipeline import ScanPipeline

    settings = get_settings()

    if layers_str:
        scan_layers = [layer.strip() for layer in layers_str.split(",")]
    else:
        scan_layers = list(settings.scan_default_layers)
        if no_llm and "llm_analyzer" in scan_layers:
            scan_layers.remove("llm_analyzer")
        if no_urls and "url_crawler" in scan_layers:
            scan_layers.remove("url_crawler")

    pipeline = ScanPipeline(settings=settings)
    pipeline.register_detector(RuleEngineDetector())
    pipeline.register_detector(UrlCrawlerDetector())
    pipeline.register_detector(LlmAnalyzerDetector(settings=settings))
    pipeline.register_detector(ThreatIntelDetector())

    target_path = Path(target)

    if target_path.is_dir():
        md_files = sorted(target_path.glob("*.md"))
        if not md_files:
            typer.echo(f"No .md files found in {target}", err=True)
            raise typer.Exit(1)

        results = []
        for md_file in md_files:
            result = await pipeline.scan_file(str(md_file), layers=scan_layers)
            results.append(result)
            if fmt == OutputFormat.CONSOLE:
                from malwar.cli.formatters.console import format_scan_result
                format_scan_result(result)

        if fmt == OutputFormat.SARIF:
            import json

            from malwar.cli.formatters.sarif import format_sarif

            all_sarif = [
                json.loads(format_sarif(r)) for r in results
            ]
            _write_output(json.dumps(all_sarif, indent=2), output)
        elif fmt == OutputFormat.JSON:
            import json
            data = [r.model_dump(mode="json") for r in results]
            _write_output(json.dumps(data, indent=2), output)

    elif target_path.is_file():
        result = await pipeline.scan_file(str(target_path), layers=scan_layers)
        _output_result(result, fmt, output)

    else:
        typer.echo(f"Target not found: {target}", err=True)
        raise typer.Exit(1)


def _output_result(result, fmt: OutputFormat, output: Path | None) -> None:
    if fmt == OutputFormat.CONSOLE:
        from malwar.cli.formatters.console import format_scan_result
        format_scan_result(result)
    elif fmt == OutputFormat.SARIF:
        from malwar.cli.formatters.sarif import format_sarif
        _write_output(format_sarif(result), output)
    elif fmt == OutputFormat.JSON:
        from malwar.cli.formatters.json_fmt import format_json
        _write_output(format_json(result), output)


def _write_output(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text)
        typer.echo(f"Output written to {output}")
    else:
        sys.stdout.write(text + "\n")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    workers: int = typer.Option(1, "--workers", "-w", help="Worker count"),
) -> None:
    """Start the malwar API server."""
    import uvicorn

    uvicorn.run(
        "malwar.api.app:create_app",
        host=host,
        port=port,
        workers=workers,
        factory=True,
    )


@app.command()
def version() -> None:
    """Show version information."""
    from malwar import __version__

    typer.echo(f"malwar v{__version__}")
