# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Typer CLI application root."""

from __future__ import annotations

import asyncio
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from malwar.cli.commands import analytics as analytics_cmd
from malwar.cli.commands import audit as audit_cmd
from malwar.cli.commands import cache as cache_cmd
from malwar.cli.commands import crawl as crawl_cmd
from malwar.cli.commands import db, export, ingest, keys, ml, notify, plugin, schedule, test_rules
from malwar.cli.commands.diff import diff_command

app = typer.Typer(
    name="malwar",
    help="Malware detection engine for agentic skills (SKILL.md)",
    no_args_is_help=True,
)

app.add_typer(db.app, name="db", help="Database management")
app.add_typer(export.app, name="export", help="Export threat intelligence (STIX/TAXII)")
app.add_typer(ingest.app, name="ingest", help="Import threat intelligence from external sources")

app.command(name="diff")(diff_command)
app.add_typer(test_rules.app, name="test-rules", help="Run rule test suite")
app.add_typer(schedule.app, name="schedule", help="Manage scheduled scans")
app.add_typer(keys.app, name="keys", help="Manage API keys (RBAC)")
app.add_typer(notify.app, name="notify", help="Manage and test notification channels")
app.add_typer(audit_cmd.app, name="audit", help="Query audit log events")
app.add_typer(plugin.app, name="plugin", help="Manage detector plugins")
app.add_typer(cache_cmd.app, name="cache", help="Manage scan result cache")
app.add_typer(ml.app, name="ml", help="ML risk scoring model management")
app.add_typer(analytics_cmd.app, name="analytics", help="Dashboard analytics summary")
app.add_typer(crawl_cmd.app, name="crawl", help="Crawl and scan skills from ClawHub registry")


class OutputFormat(StrEnum):
    CONSOLE = "console"
    SARIF = "sarif"
    JSON = "json"
    GITLAB_CODEQUALITY = "gitlab-codequality"
    AZURE_ANNOTATIONS = "azure-annotations"


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
    ci_mode: Annotated[
        bool,
        typer.Option("--ci-mode", help="Enable CI mode with standardized exit codes"),
    ] = False,
    watch: Annotated[
        bool,
        typer.Option("--watch", help="Watch directory for changes and auto-scan"),
    ] = False,
    poll_interval: Annotated[
        float,
        typer.Option("--poll-interval", help="Watch mode poll interval in seconds"),
    ] = 2.0,
) -> None:
    """Scan a SKILL.md file, directory, or URL for malware."""
    if watch:
        from malwar.cli.tui.watch import run_watch_mode

        scan_layers: list[str] | None = None
        if layers:
            scan_layers = [layer.strip() for layer in layers.split(",")]
        run_watch_mode(target, layers=scan_layers, poll_interval=poll_interval)
        return

    exit_code = asyncio.run(
        _async_scan(target, fmt, output, no_llm, no_urls, layers, ci_mode=ci_mode)
    )
    if ci_mode and exit_code is not None:
        raise typer.Exit(exit_code)


async def _async_scan(
    target: str,
    fmt: OutputFormat,
    output: Path | None,
    no_llm: bool,
    no_urls: bool,
    layers_str: str | None,
    *,
    ci_mode: bool = False,
) -> int | None:
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
        elif fmt == OutputFormat.GITLAB_CODEQUALITY:
            from malwar.ci.parser import format_gitlab_code_quality
            _write_output(format_gitlab_code_quality(results), output)
        elif fmt == OutputFormat.AZURE_ANNOTATIONS:
            from malwar.ci.parser import format_azure_annotations
            _write_output(format_azure_annotations(results), output)

        if ci_mode:
            from malwar.ci.exit_codes import verdict_to_exit_code
            verdicts = [r.verdict for r in results]
            if verdicts:
                worst = max(
                    verdicts,
                    key=lambda v: ["CLEAN", "CAUTION", "SUSPICIOUS", "MALICIOUS"].index(v),
                )
                return int(verdict_to_exit_code(worst))
            return 0

    elif target_path.is_file():
        result = await pipeline.scan_file(str(target_path), layers=scan_layers)
        _output_result(result, fmt, output)

        if ci_mode:
            from malwar.ci.exit_codes import verdict_to_exit_code
            return int(verdict_to_exit_code(result.verdict))

    else:
        typer.echo(f"Target not found: {target}", err=True)
        if ci_mode:
            from malwar.ci.exit_codes import CIExitCode
            return int(CIExitCode.SCAN_ERROR)
        raise typer.Exit(1)

    return None


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
    elif fmt == OutputFormat.GITLAB_CODEQUALITY:
        from malwar.ci.parser import format_gitlab_code_quality
        _write_output(format_gitlab_code_quality([result]), output)
    elif fmt == OutputFormat.AZURE_ANNOTATIONS:
        from malwar.ci.parser import format_azure_annotations
        _write_output(format_azure_annotations([result]), output)


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
    no_scheduler: Annotated[
        bool, typer.Option("--no-scheduler", help="Disable the background scheduled scanner")
    ] = False,
) -> None:
    """Start the malwar API server."""
    import uvicorn

    if no_scheduler:
        # Pass flag via environment; the app factory reads it
        import os
        os.environ["MALWAR_NO_SCHEDULER"] = "1"

    uvicorn.run(
        "malwar.api.app:_create_app_from_env",
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


@app.command(name="report-show")
def report_show(
    scan_id: Annotated[
        str, typer.Argument(help="Scan ID to show report for")
    ],
) -> None:
    """Show a detailed report for a scan."""
    asyncio.run(_async_report_show(scan_id))


async def _async_report_show(scan_id: str) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db
    from malwar.storage.repositories.findings import FindingRepository
    from malwar.storage.repositories.scans import ScanRepository

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        scan_repo = ScanRepository(db)
        finding_repo = FindingRepository(db)

        result = await scan_repo.get(scan_id)
        if result is None:
            typer.echo(f"Scan {scan_id} not found.", err=True)
            raise typer.Exit(1)

        finding_rows = await finding_repo.get_by_scan(scan_id)

        console = Console()

        # Verdict color mapping
        verdict_colors = {
            "MALICIOUS": "bold red",
            "SUSPICIOUS": "yellow",
            "CAUTION": "cyan",
            "CLEAN": "bold green",
        }
        verdict_color = verdict_colors.get(result.verdict, "white")

        # Header panel
        header_lines = [
            f"Scan ID:    {result.scan_id}",
            f"Verdict:    [{verdict_color}]{result.verdict}[/{verdict_color}]",
            f"Risk Score: {result.risk_score}/100",
            f"Severity:   {result.overall_severity}",
            f"Timestamp:  {result.started_at.isoformat()}",
        ]
        if result.skill_name:
            header_lines.insert(1, f"Skill:      {result.skill_name}")
        if result.duration_ms is not None:
            header_lines.append(f"Duration:   {result.duration_ms / 1000:.1f}s")

        console.print(Panel("\n".join(header_lines), title="Scan Report"))

        # Severity breakdown
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for f in finding_rows:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = f.get("category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        summary_table = Table(title="Summary")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_counts:
                summary_table.add_row(sev, str(severity_counts[sev]))
        console.print(summary_table)

        cat_table = Table(title="Categories")
        cat_table.add_column("Category", style="bold")
        cat_table.add_column("Count", justify="right")
        for cat, count in sorted(category_counts.items()):
            cat_table.add_row(cat, str(count))
        console.print(cat_table)

        # Findings table
        if finding_rows:
            findings_table = Table(title="Findings")
            findings_table.add_column("Rule ID", style="cyan", no_wrap=True)
            findings_table.add_column("Title", style="bold")
            findings_table.add_column("Severity", style="red")
            findings_table.add_column("Confidence", justify="right")
            findings_table.add_column("Line", justify="right")
            findings_table.add_column("Detector")

            for f in finding_rows:
                findings_table.add_row(
                    f["rule_id"],
                    f["title"],
                    f["severity"],
                    f"{f['confidence']:.2f}",
                    str(f.get("line_start") or "-"),
                    f["detector_layer"],
                )
            console.print(findings_table)
        else:
            console.print("[bold green]No findings.[/bold green]")
    finally:
        await close_db()


@app.command(name="db-seed")
def db_seed() -> None:
    """Run seed data independently (campaigns, signatures, publishers)."""
    asyncio.run(_async_db_seed())


async def _async_db_seed() -> None:
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db
    from malwar.storage.migrations import seed_data

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        await seed_data(db)
        await db.commit()
        typer.echo("Seed data inserted successfully.")
    finally:
        await close_db()


@app.command()
def tui(
    directory: Annotated[
        str | None,
        typer.Argument(help="Optional directory to start in"),
    ] = None,
) -> None:
    """Launch the interactive TUI mode with Rich dashboard."""
    from malwar.cli.tui.app import run_tui

    run_tui(directory=directory)


@app.command()
def version() -> None:
    """Show version information."""
    from malwar import __version__

    typer.echo(f"malwar v{__version__}")
