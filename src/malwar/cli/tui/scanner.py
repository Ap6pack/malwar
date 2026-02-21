# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Interactive file browser/scanner with real-time result display."""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from malwar.cli.tui.results import render_scan_result


def list_skill_files(directory: str | Path) -> list[Path]:
    """List all .md files in a directory, sorted by name."""
    dirpath = Path(directory)
    if not dirpath.is_dir():
        return []
    return sorted(dirpath.glob("*.md"))


def build_file_browser_table(files: list[Path], selected: set[int] | None = None) -> Table:
    """Build a Rich table showing available skill files for scanning."""
    if selected is None:
        selected = set()

    table = Table(title="Skill Files", show_lines=False)
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Selected", width=3, justify="center")
    table.add_column("File", style="bold")
    table.add_column("Size", justify="right", width=10)
    table.add_column("Modified", style="dim", width=20)

    for i, filepath in enumerate(files):
        sel_mark = "[green]x[/green]" if i in selected else " "
        size = filepath.stat().st_size
        size_str = _human_size(size)
        mtime = filepath.stat().st_mtime
        from datetime import UTC, datetime

        mod_str = datetime.fromtimestamp(mtime, tz=UTC).strftime("%Y-%m-%d %H:%M")
        table.add_row(str(i + 1), sel_mark, filepath.name, size_str, mod_str)

    return table


def _human_size(nbytes: int) -> str:
    """Convert bytes to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024:
            return f"{nbytes:.0f} {unit}"
        nbytes /= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} TB"


async def interactive_scan_files(
    files: list[Path],
    layers: list[str] | None = None,
    console: Console | None = None,
) -> None:
    """Scan a list of files interactively with progress display and result rendering."""
    if console is None:
        console = Console()

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

    # Try to register LLM detector if not skipped
    if "llm_analyzer" in scan_layers:
        try:
            from malwar.detectors.llm_analyzer.detector import LlmAnalyzerDetector

            pipeline.register_detector(LlmAnalyzerDetector(settings=settings))
        except Exception:
            console.print("[yellow]LLM analyzer not available, skipping.[/yellow]")
            scan_layers = [ly for ly in scan_layers if ly != "llm_analyzer"]

    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        overall = progress.add_task("Scanning files...", total=len(files))

        for filepath in files:
            progress.update(overall, description=f"Scanning {filepath.name}...")
            try:
                result = await pipeline.scan_file(str(filepath), layers=scan_layers)
                progress.advance(overall)
                console.print()
                render_scan_result(result, console=console)
            except Exception as exc:
                progress.advance(overall)
                console.print(f"\n[red]Error scanning {filepath}: {exc}[/red]")

    console.print("[bold green]Scan complete.[/bold green]")


def run_interactive_browser(directory: str | None = None, console: Console | None = None) -> None:
    """Run the interactive file browser and scanner.

    Presents a file listing, lets the user select files, configure layers,
    and view results in real-time.
    """
    if console is None:
        console = Console()

    target_dir = Path(directory) if directory else Path.cwd()

    console.print()
    console.print(
        Panel(
            "[bold blue]malwar Interactive Scanner[/bold blue]\n"
            f"Directory: {target_dir}",
            border_style="blue",
        )
    )

    files = list_skill_files(target_dir)
    if not files:
        console.print(f"[yellow]No .md files found in {target_dir}[/yellow]")
        return

    console.print(build_file_browser_table(files))
    console.print()

    # File selection
    selection_input = Prompt.ask(
        "Select files (comma-separated numbers, 'all', or 'q' to quit)",
        default="all",
    )

    if selection_input.strip().lower() == "q":
        console.print("[dim]Cancelled.[/dim]")
        return

    selected_files: list[Path]
    if selection_input.strip().lower() == "all":
        selected_files = files
    else:
        indices: list[int] = []
        for part in selection_input.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(files):
                    indices.append(idx)
        selected_files = [files[i] for i in indices]

    if not selected_files:
        console.print("[yellow]No files selected.[/yellow]")
        return

    console.print(f"\n[bold]Selected {len(selected_files)} file(s) for scanning.[/bold]")

    # Layer configuration
    default_layers = "rule_engine,url_crawler,llm_analyzer,threat_intel"
    layers_input = Prompt.ask("Layers (comma-separated)", default=default_layers)
    layers = [ly.strip() for ly in layers_input.split(",") if ly.strip()]

    # Confirm and scan
    if Confirm.ask("Start scan?", default=True):
        asyncio.run(interactive_scan_files(selected_files, layers=layers, console=console))
    else:
        console.print("[dim]Cancelled.[/dim]")
