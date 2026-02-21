# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Main TUI application using Rich Live display with panels, tables, and progress bars."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt

from malwar.cli.tui.dashboard import DashboardData, assemble_dashboard
from malwar.cli.tui.results import render_scan_result
from malwar.cli.tui.scanner import run_interactive_browser


def run_tui(directory: str | None = None) -> None:
    """Launch the main TUI interactive mode.

    Displays a live dashboard and accepts commands:
      scan [dir]  - open interactive scanner on a directory
      browse [dir] - browse and select files to scan
      quit / exit - exit the TUI
    """
    console = Console()
    data = DashboardData()

    console.print()
    console.print(
        Panel(
            "[bold blue]malwar Interactive TUI[/bold blue]\n"
            "Commands: [bold]scan[/bold] <dir>, [bold]browse[/bold] <dir>, "
            "[bold]dashboard[/bold], [bold]quit[/bold]",
            border_style="blue",
        )
    )
    console.print()

    while True:
        try:
            command = Prompt.ask(
                "[bold blue]malwar>[/bold blue]",
                default="dashboard",
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        parts = command.strip().split(maxsplit=1)
        cmd = parts[0].lower() if parts else ""
        arg = parts[1] if len(parts) > 1 else directory

        if cmd in ("quit", "exit", "q"):
            console.print("[dim]Goodbye.[/dim]")
            break

        elif cmd == "dashboard":
            _show_live_dashboard(console, data)

        elif cmd in ("scan", "browse"):
            target_dir = arg or "."
            run_interactive_browser(directory=target_dir, console=console)

        elif cmd == "help":
            console.print(
                Panel(
                    "[bold]Available commands:[/bold]\n\n"
                    "  [cyan]scan[/cyan] <dir>      Scan .md files in a directory\n"
                    "  [cyan]browse[/cyan] <dir>    Browse and select files to scan\n"
                    "  [cyan]dashboard[/cyan]       Show live dashboard (Ctrl+C to return)\n"
                    "  [cyan]help[/cyan]            Show this help\n"
                    "  [cyan]quit[/cyan]            Exit the TUI\n",
                    title="Help",
                    border_style="blue",
                )
            )

        else:
            console.print(f"[yellow]Unknown command: {cmd}. Type 'help' for commands.[/yellow]")


def _show_live_dashboard(console: Console, data: DashboardData) -> None:
    """Display the live dashboard until Ctrl+C is pressed."""
    console.print("[dim]Showing live dashboard. Press Ctrl+C to return to prompt.[/dim]")

    try:
        with Live(assemble_dashboard(data), console=console, refresh_per_second=1) as live:
            while True:
                live.update(assemble_dashboard(data))
                time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Returned to command prompt.[/dim]")


def run_scan_with_progress(
    target: str,
    layers: list[str] | None = None,
    console: Console | None = None,
) -> None:
    """Run a scan on a target with Rich progress display.

    This is used by the enhanced `malwar scan` command.
    """
    if console is None:
        console = Console()

    asyncio.run(_async_scan_with_progress(target, layers, console))


async def _async_scan_with_progress(
    target: str,
    layers: list[str] | None,
    console: Console,
) -> None:
    """Async implementation of scan with progress."""
    from malwar.core.config import get_settings
    from malwar.detectors.rule_engine.detector import RuleEngineDetector
    from malwar.detectors.threat_intel.detector import ThreatIntelDetector
    from malwar.detectors.url_crawler.detector import UrlCrawlerDetector
    from malwar.scanner.pipeline import ScanPipeline

    settings = get_settings()
    scan_layers = layers or list(settings.scan_default_layers)

    pipeline = ScanPipeline(settings=settings)
    pipeline.register_detector(RuleEngineDetector())
    pipeline.register_detector(UrlCrawlerDetector())
    pipeline.register_detector(ThreatIntelDetector())

    if "llm_analyzer" in scan_layers:
        try:
            from malwar.detectors.llm_analyzer.detector import LlmAnalyzerDetector

            pipeline.register_detector(LlmAnalyzerDetector(settings=settings))
        except Exception:
            scan_layers = [ly for ly in scan_layers if ly != "llm_analyzer"]

    target_path = Path(target)

    if target_path.is_dir():
        md_files = sorted(target_path.glob("*.md"))
        if not md_files:
            console.print(f"[red]No .md files found in {target}[/red]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(md_files))

            for md_file in md_files:
                progress.update(task, description=f"Scanning {md_file.name}...")
                try:
                    result = await pipeline.scan_file(str(md_file), layers=scan_layers)
                    progress.advance(task)
                    console.print()
                    render_scan_result(result, console=console)
                except Exception as exc:
                    progress.advance(task)
                    console.print(f"\n[red]Error: {exc}[/red]")

    elif target_path.is_file():
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {target_path.name}...", total=1)
            result = await pipeline.scan_file(str(target_path), layers=scan_layers)
            progress.advance(task)

        render_scan_result(result, console=console)

    else:
        console.print(f"[red]Target not found: {target}[/red]")
