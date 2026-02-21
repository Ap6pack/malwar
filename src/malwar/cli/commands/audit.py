# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI commands for querying the audit log."""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer

app = typer.Typer()


@app.command(name="list")
def audit_list(
    event_type: Annotated[
        str | None,
        typer.Option("--type", "-t", help="Filter by event type"),
    ] = None,
    actor: Annotated[
        str | None,
        typer.Option("--actor", "-a", help="Filter by actor"),
    ] = None,
    start_date: Annotated[
        str | None,
        typer.Option("--start", help="Start date (ISO format)"),
    ] = None,
    end_date: Annotated[
        str | None,
        typer.Option("--end", help="End date (ISO format)"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Maximum number of events to show"),
    ] = 50,
) -> None:
    """List audit events with optional filters."""
    asyncio.run(
        _async_audit_list(event_type, actor, start_date, end_date, limit)
    )


async def _async_audit_list(
    event_type: str | None,
    actor: str | None,
    start_date: str | None,
    end_date: str | None,
    limit: int,
) -> None:
    from rich.console import Console
    from rich.table import Table

    from malwar.audit.store import AuditStore
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        store = AuditStore(db)
        events = await store.list_events(
            event_type=event_type,
            actor=actor,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )

        console = Console()

        if not events:
            console.print("[dim]No audit events found.[/dim]")
            return

        table = Table(title="Audit Events")
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Event Type", style="cyan")
        table.add_column("Actor", style="yellow")
        table.add_column("Resource", style="green")
        table.add_column("Action", style="bold")
        table.add_column("Event ID", style="dim", no_wrap=True)

        for event in events:
            resource = event.get("resource_type", "")
            resource_id = event.get("resource_id", "")
            resource_display = f"{resource}/{resource_id}" if resource else resource_id

            table.add_row(
                event.get("timestamp", ""),
                event.get("event_type", ""),
                event.get("actor", ""),
                resource_display,
                event.get("action", ""),
                event.get("event_id", "")[:12] + "...",
            )

        console.print(table)
        console.print(f"\n[dim]Showing {len(events)} event(s)[/dim]")
    finally:
        await close_db()
