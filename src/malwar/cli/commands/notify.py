# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI commands for notification channel management and testing."""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer

app = typer.Typer(
    name="notify",
    help="Manage and test notification channels",
    no_args_is_help=True,
)


@app.command()
def test(
    channel: Annotated[
        str | None,
        typer.Option("--channel", "-c", help="Channel to test (slack, teams, pagerduty, email, webhook). Omit for all."),
    ] = None,
) -> None:
    """Send a test notification to verify channel configuration."""
    asyncio.run(_async_test(channel))


async def _async_test(channel: str | None) -> None:
    from rich.console import Console
    from rich.table import Table

    from malwar.core.config import get_settings
    from malwar.notifications.events import EventType, NotificationEvent
    from malwar.notifications.factory import build_router

    console = Console()
    settings = get_settings()
    router = build_router(settings)

    if not router.channels:
        console.print("[yellow]No notification channels configured.[/yellow]")
        console.print("Set MALWAR_SLACK_WEBHOOK_URL, MALWAR_TEAMS_WEBHOOK_URL, etc.")
        raise typer.Exit(1)

    test_event = NotificationEvent(
        event_type=EventType.SCAN_COMPLETE,
        scan_id="test-notification-000",
        target="test/SKILL.md",
        verdict="CLEAN",
        risk_score=0,
        finding_count=0,
        findings_summary=[],
        skill_name="test-skill",
    )

    table = Table(title="Notification Test Results")
    table.add_column("Channel", style="cyan")
    table.add_column("Configured", style="bold")
    table.add_column("Result", style="bold")

    any_tested = False

    for ch in router.channels:
        if channel and ch.name != channel:
            continue

        any_tested = True
        configured = ch.is_configured()

        if not configured:
            table.add_row(ch.name, "[red]No[/red]", "[red]Skipped[/red]")
            continue

        try:
            success = await ch.send(test_event)
            if success:
                table.add_row(ch.name, "[green]Yes[/green]", "[green]OK[/green]")
            else:
                table.add_row(ch.name, "[green]Yes[/green]", "[red]Failed[/red]")
        except Exception as exc:
            table.add_row(ch.name, "[green]Yes[/green]", f"[red]Error: {exc}[/red]")

    if not any_tested:
        if channel:
            console.print(f"[yellow]Channel '{channel}' not found in configured channels.[/yellow]")
        else:
            console.print("[yellow]No channels to test.[/yellow]")
        raise typer.Exit(1)

    console.print(table)


@app.command(name="channels")
def list_channels() -> None:
    """List configured notification channels."""
    asyncio.run(_async_list_channels())


async def _async_list_channels() -> None:
    from rich.console import Console
    from rich.table import Table

    from malwar.core.config import get_settings
    from malwar.notifications.factory import build_router

    console = Console()
    settings = get_settings()
    router = build_router(settings)

    if not router.channels:
        console.print("[yellow]No notification channels configured.[/yellow]")
        return

    table = Table(title="Notification Channels")
    table.add_column("Channel", style="cyan")
    table.add_column("Configured", style="bold")

    for status in router.get_channel_status():
        configured = "[green]Yes[/green]" if status["configured"] else "[red]No[/red]"
        table.add_row(str(status["name"]), configured)

    console.print(table)
