# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Watch mode — polls a directory for SKILL.md changes and auto-scans."""

from __future__ import annotations

import asyncio
import contextlib
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from malwar.cli.tui.dashboard import DashboardData
from malwar.cli.tui.results import render_scan_result


def collect_file_states(directory: Path) -> dict[str, float]:
    """Collect mtime for all .md files in directory.

    Returns a mapping of absolute file path to modification time.
    """
    states: dict[str, float] = {}
    if not directory.is_dir():
        return states
    for filepath in directory.iterdir():
        if filepath.is_file() and filepath.suffix == ".md":
            with contextlib.suppress(OSError):
                states[str(filepath.resolve())] = filepath.stat().st_mtime
    return states


def detect_changes(
    previous: dict[str, float],
    current: dict[str, float],
) -> list[str]:
    """Detect new or modified files between two state snapshots.

    Returns a list of file paths that are new or have a newer mtime.
    """
    changed: list[str] = []

    for fpath, mtime in current.items():
        prev_mtime = previous.get(fpath)
        if prev_mtime is None or mtime > prev_mtime:
            changed.append(fpath)

    return changed


def run_watch_mode(
    directory: str,
    layers: list[str] | None = None,
    poll_interval: float = 2.0,
    console: Console | None = None,
) -> None:
    """Watch a directory for .md file changes and auto-scan.

    Uses polling (no external watchdog dependency).
    """
    if console is None:
        console = Console()

    dir_path = Path(directory).resolve()
    if not dir_path.is_dir():
        console.print(f"[red]Directory not found: {directory}[/red]")
        return

    console.print(
        Panel(
            f"[bold blue]Watch Mode[/bold blue]\n"
            f"Watching: {dir_path}\n"
            f"Poll interval: {poll_interval}s\n"
            f"Press Ctrl+C to stop.",
            border_style="blue",
        )
    )

    # Initial state capture
    file_states = collect_file_states(dir_path)
    console.print(f"[dim]Tracking {len(file_states)} .md file(s)...[/dim]")

    dashboard_data = DashboardData()

    try:
        while True:
            time.sleep(poll_interval)

            current_states = collect_file_states(dir_path)
            changed = detect_changes(file_states, current_states)

            if changed:
                console.print(
                    f"\n[bold yellow]Detected {len(changed)} changed file(s):[/bold yellow]"
                )
                for fpath in changed:
                    console.print(f"  [cyan]{fpath}[/cyan]")

                # Run scan on changed files
                dashboard_data.scans_in_progress += len(changed)
                asyncio.run(
                    _async_watch_scan(changed, layers, console, dashboard_data)
                )
                dashboard_data.scans_in_progress = 0

            # Update state
            file_states = current_states

    except KeyboardInterrupt:
        console.print("\n[dim]Watch mode stopped.[/dim]")


async def _async_watch_scan(
    file_paths: list[str],
    layers: list[str] | None,
    console: Console,
    dashboard_data: DashboardData,
) -> None:
    """Scan changed files asynchronously."""
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

    for fpath in file_paths:
        try:
            result = await pipeline.scan_file(fpath, layers=scan_layers)
            render_scan_result(result, console=console)
            dashboard_data.record_result(result)
        except Exception as exc:
            console.print(f"[red]Error scanning {fpath}: {exc}[/red]")
            dashboard_data.record_failure()
