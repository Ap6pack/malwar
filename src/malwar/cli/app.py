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
def signature_list() -> None:
    """List threat signatures from the database."""
    asyncio.run(_async_signature_list())


async def _async_signature_list() -> None:
    from rich.console import Console
    from rich.table import Table

    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db
    from malwar.storage.repositories.signatures import SignatureRepository

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        repo = SignatureRepository(db)
        rows = await repo.get_all()

        console = Console()
        table = Table(title="Threat Signatures")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="bold")
        table.add_column("Severity", style="red")
        table.add_column("Pattern Type")
        table.add_column("IOC Type")
        table.add_column("Source")
        table.add_column("Enabled")

        for row in rows:
            table.add_row(
                row["id"],
                row["name"],
                row["severity"],
                row["pattern_type"],
                row.get("ioc_type") or "-",
                row.get("source", "manual"),
                "yes" if row.get("enabled") else "no",
            )

        console.print(table)
    finally:
        await close_db()


@app.command()
def signature_add(
    pattern_type: Annotated[
        str, typer.Argument(help="Pattern type: regex | exact | fuzzy | ioc")
    ],
    pattern_value: Annotated[str, typer.Argument(help="Pattern value to match")],
    name: Annotated[
        str, typer.Option("--name", "-n", help="Signature name")
    ] = "",
    severity: Annotated[
        str, typer.Option("--severity", "-s", help="Severity: critical|high|medium|low|info")
    ] = "medium",
    category: Annotated[
        str, typer.Option("--category", "-c", help="Threat category")
    ] = "known_malware",
    ioc_type: Annotated[
        str | None,
        typer.Option("--ioc-type", help="IOC type: ip|domain|url|hash|email"),
    ] = None,
    campaign_id: Annotated[
        str | None,
        typer.Option("--campaign-id", help="Linked campaign ID"),
    ] = None,
    source: Annotated[
        str, typer.Option("--source", help="Signature source")
    ] = "manual",
    description: Annotated[
        str, typer.Option("--description", "-d", help="Signature description")
    ] = "",
) -> None:
    """Add a new threat signature to the database."""
    asyncio.run(
        _async_signature_add(
            pattern_type, pattern_value, name, severity, category,
            ioc_type, campaign_id, source, description,
        )
    )


async def _async_signature_add(
    pattern_type: str,
    pattern_value: str,
    name: str,
    severity: str,
    category: str,
    ioc_type: str | None,
    campaign_id: str | None,
    source: str,
    description: str,
) -> None:
    import uuid

    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db
    from malwar.storage.repositories.signatures import SignatureRepository

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        repo = SignatureRepository(db)

        sig_id = f"sig-{uuid.uuid4().hex[:12]}"
        sig_name = name or f"{pattern_type}-{pattern_value[:30]}"
        sig_desc = description or f"Signature for {pattern_type} pattern: {pattern_value}"

        await repo.create({
            "id": sig_id,
            "name": sig_name,
            "description": sig_desc,
            "severity": severity,
            "category": category,
            "pattern_type": pattern_type,
            "pattern_value": pattern_value,
            "ioc_type": ioc_type,
            "campaign_id": campaign_id,
            "source": source,
            "enabled": True,
        })

        typer.echo(f"Created signature {sig_id}: {sig_name}")
    finally:
        await close_db()


@app.command()
def version() -> None:
    """Show version information."""
    from malwar import __version__

    typer.echo(f"malwar v{__version__}")
