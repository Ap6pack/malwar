# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI commands for crawling and scanning skills from ClawHub."""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(help="Crawl and scan skills from ClawHub registry.")
console = Console()


class CrawlFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"


def _format_and_output(result, fmt: CrawlFormat, output: Path | None) -> None:
    """Format a scan result and write to output or stdout."""
    if fmt == CrawlFormat.CONSOLE:
        from malwar.cli.formatters.console import format_scan_result

        format_scan_result(result)
    elif fmt == CrawlFormat.JSON:
        from malwar.cli.formatters.json_fmt import format_json

        text = format_json(result)
        _write(text, output)
    elif fmt == CrawlFormat.SARIF:
        from malwar.cli.formatters.sarif import format_sarif

        text = format_sarif(result)
        _write(text, output)


def _write(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text)
        typer.echo(f"Output written to {output}")
    else:
        sys.stdout.write(text + "\n")


@app.command(name="scan")
def crawl_scan(
    slug: Annotated[str, typer.Argument(help="Skill slug on ClawHub")],
    version: Annotated[
        str | None,
        typer.Option("--version", "-v", help="Specific skill version"),
    ] = None,
    fmt: Annotated[
        CrawlFormat,
        typer.Option("--format", "-f", help="Output format"),
    ] = CrawlFormat.CONSOLE,
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
    """Fetch a skill from ClawHub and scan its SKILL.md for threats."""
    exit_code = asyncio.run(
        _async_crawl_scan(slug, version, fmt, output, no_llm, no_urls, layers)
    )
    raise typer.Exit(exit_code)


async def _async_crawl_scan(
    slug: str,
    version: str | None,
    fmt: CrawlFormat,
    output: Path | None,
    no_llm: bool,
    no_urls: bool,
    layers_str: str | None,
) -> int:
    from malwar.crawl.client import ClawHubClient, ClawHubError
    from malwar.sdk import scan

    client = ClawHubClient()

    try:
        console.print(f"Fetching SKILL.md for [bold]{slug}[/bold]...", style="dim")
        content = await client.get_skill_file(slug, version=version)
    except ClawHubError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1

    layer_list: list[str] | None = None
    if layers_str:
        layer_list = [layer.strip() for layer in layers_str.split(",")]

    result = await scan(
        content,
        file_name=f"clawhub:{slug}/SKILL.md",
        use_llm=not no_llm,
        use_urls=not no_urls,
        layers=layer_list,
    )

    _format_and_output(result, fmt, output)

    return 1 if result.risk_score >= 40 else 0


@app.command(name="search")
def crawl_search(
    query: Annotated[str, typer.Argument(help="Search query")],
    limit: Annotated[
        int, typer.Option("--limit", "-n", help="Maximum results")
    ] = 20,
) -> None:
    """Search for skills on ClawHub."""
    asyncio.run(_async_search(query, limit))


async def _async_search(query: str, limit: int) -> None:
    from malwar.crawl.client import ClawHubClient, ClawHubError

    client = ClawHubClient()

    try:
        results = await client.search(query, limit=limit)
    except ClawHubError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from None

    if not results:
        console.print(f"No skills found for [bold]{query}[/bold]")
        return

    table = Table(title=f"Search results for '{query}'")
    table.add_column("Slug", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("Summary")
    table.add_column("Version", justify="right")
    table.add_column("Score", justify="right", style="dim")

    for r in results:
        table.add_row(
            r.slug,
            r.display_name,
            r.summary[:60] + ("..." if len(r.summary) > 60 else ""),
            r.version,
            f"{r.score:.1f}",
        )

    console.print(table)
    console.print(
        "\n  Scan a skill: [bold]malwar crawl scan <slug>[/bold]",
        style="dim",
    )


@app.command(name="list")
def crawl_list(
    limit: Annotated[
        int, typer.Option("--limit", "-n", help="Number of skills to list")
    ] = 20,
    cursor: Annotated[
        str | None,
        typer.Option("--cursor", help="Pagination cursor from previous request"),
    ] = None,
) -> None:
    """List skills from the ClawHub registry."""
    asyncio.run(_async_list(limit, cursor))


async def _async_list(limit: int, cursor: str | None) -> None:
    from malwar.crawl.client import ClawHubClient, ClawHubError

    client = ClawHubClient()

    try:
        skills, next_cursor = await client.list_skills(limit=limit, cursor=cursor)
    except ClawHubError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from None

    if not skills:
        console.print("No skills found.")
        return

    table = Table(title="ClawHub Skills")
    table.add_column("Slug", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("Summary")
    table.add_column("Version", justify="right")
    table.add_column("Downloads", justify="right", style="dim")

    for s in skills:
        version = s.latest_version.version if s.latest_version else "-"
        table.add_row(
            s.slug,
            s.display_name,
            s.summary[:60] + ("..." if len(s.summary) > 60 else ""),
            version,
            str(s.stats.downloads),
        )

    console.print(table)

    if next_cursor:
        console.print(
            f"\n  Next page: [bold]malwar crawl list --cursor {next_cursor[:20]}...[/bold]",
            style="dim",
        )


@app.command(name="info")
def crawl_info(
    slug: Annotated[str, typer.Argument(help="Skill slug on ClawHub")],
) -> None:
    """Show details and moderation status for a ClawHub skill."""
    asyncio.run(_async_info(slug))


async def _async_info(slug: str) -> None:
    from malwar.crawl.client import ClawHubClient, ClawHubError

    client = ClawHubClient()

    try:
        detail = await client.get_skill(slug)
    except ClawHubError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from None

    # Header panel
    lines = [
        f"Slug:    {detail.slug}",
        f"Name:    {detail.display_name}",
        f"Summary: {detail.summary}",
    ]
    if detail.owner:
        lines.append(f"Author:  {detail.owner.username}")
    if detail.latest_version:
        lines.append(f"Version: {detail.latest_version.version}")
    if detail.stats:
        lines.append(
            f"Stats:   {detail.stats.downloads} downloads, "
            f"{detail.stats.stars} stars, "
            f"{detail.stats.versions} versions"
        )
    if detail.created_at:
        created = datetime.fromtimestamp(detail.created_at / 1000, tz=UTC)
        lines.append(f"Created: {created.strftime('%Y-%m-%d')}")
    if detail.tags:
        lines.append(f"Tags:    {', '.join(f'{k}={v}' for k, v in detail.tags.items())}")

    console.print(Panel("\n".join(lines), title=f"Skill: {detail.slug}"))

    # Moderation status
    if detail.moderation:
        mod = detail.moderation
        mod_lines = []
        if mod.is_malware_blocked:
            mod_lines.append("[bold red]BLOCKED: Malware detected by VirusTotal[/bold red]")
        if mod.is_suspicious:
            mod_lines.append("[yellow]SUSPICIOUS: Flagged for review[/yellow]")
        if mod.is_pending_scan:
            mod_lines.append("[cyan]PENDING: Awaiting security scan[/cyan]")
        if mod.is_hidden_by_mod:
            mod_lines.append("[red]HIDDEN: Hidden by moderator[/red]")
        if mod.is_removed:
            mod_lines.append("[red]REMOVED: Removed from registry[/red]")
        if mod.reason:
            mod_lines.append(f"Reason: {mod.reason}")

        if mod_lines:
            console.print(Panel(
                "\n".join(mod_lines),
                title="Moderation Status",
                style="yellow",
            ))
        else:
            console.print("[bold green]Moderation: No flags[/bold green]")
    else:
        console.print("[dim]Moderation: No data available[/dim]")

    console.print(
        f"\n  Scan this skill: [bold]malwar crawl scan {detail.slug}[/bold]",
        style="dim",
    )


@app.command(name="url")
def crawl_url(
    url: Annotated[str, typer.Argument(help="URL to a SKILL.md file")],
    fmt: Annotated[
        CrawlFormat,
        typer.Option("--format", "-f", help="Output format"),
    ] = CrawlFormat.CONSOLE,
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
    """Fetch a SKILL.md from any URL and scan it for threats."""
    exit_code = asyncio.run(
        _async_crawl_url(url, fmt, output, no_llm, no_urls, layers)
    )
    raise typer.Exit(exit_code)


async def _async_crawl_url(
    url: str,
    fmt: CrawlFormat,
    output: Path | None,
    no_llm: bool,
    no_urls: bool,
    layers_str: str | None,
) -> int:
    from malwar.crawl.client import ClawHubError, fetch_url
    from malwar.sdk import scan

    try:
        console.print(f"Fetching [bold]{url}[/bold]...", style="dim")
        content = await fetch_url(url)
    except ClawHubError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1
    except Exception as exc:
        console.print(f"[red]Error fetching URL:[/red] {exc}")
        return 1

    # Derive a file name from the URL
    file_name = url.rsplit("/", 1)[-1] or "SKILL.md"

    layer_list: list[str] | None = None
    if layers_str:
        layer_list = [layer.strip() for layer in layers_str.split(",")]

    result = await scan(
        content,
        file_name=file_name,
        use_llm=not no_llm,
        use_urls=not no_urls,
        layers=layer_list,
    )

    _format_and_output(result, fmt, output)

    return 1 if result.risk_score >= 40 else 0
