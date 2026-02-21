# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI commands for scheduled scanning management."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Annotated

import typer

app = typer.Typer(help="Manage scheduled scans")


@app.command()
def create(
    target: Annotated[str, typer.Argument(help="SKILL.md file path to scan")],
    cron: Annotated[str, typer.Option("--cron", help="Cron expression (5-field)")],
    name: Annotated[str, typer.Option("--name", "-n", help="Job name")] = "",
    layers: Annotated[
        str | None,
        typer.Option("--layers", help="Comma-separated layers to run"),
    ] = None,
    disabled: Annotated[
        bool, typer.Option("--disabled", help="Create job in disabled state")
    ] = False,
) -> None:
    """Create a new scheduled scan job."""
    asyncio.run(_async_create(target, cron, name, layers, disabled))


async def _async_create(
    target: str,
    cron_expr: str,
    name: str,
    layers_str: str | None,
    disabled: bool,
) -> None:
    from malwar.core.config import get_settings
    from malwar.scheduler.cron import CronParseError, next_run_from_cron
    from malwar.scheduler.jobs import ScanJob
    from malwar.scheduler.store import JobStore
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        # Validate cron
        try:
            next_run = next_run_from_cron(cron_expr, datetime.now(UTC))
        except CronParseError as exc:
            typer.echo(f"Invalid cron expression: {exc}", err=True)
            raise typer.Exit(1) from exc

        scan_layers = (
            [part.strip() for part in layers_str.split(",") if part.strip()]
            if layers_str
            else list(settings.scan_default_layers)
        )

        job_name = name or f"scan-{target}"
        job = ScanJob(
            job_id=f"sched-{uuid.uuid4().hex[:12]}",
            name=job_name,
            target_path=target,
            schedule=cron_expr,
            layers=scan_layers,
            enabled=not disabled,
            next_run=next_run,
            created_at=datetime.now(UTC),
        )

        store = JobStore(db)
        await store.create_job(job)

        typer.echo(f"Created scheduled job {job.job_id}: {job.name}")
        typer.echo(f"  Schedule: {cron_expr}")
        typer.echo(f"  Next run: {next_run.isoformat()}")
        typer.echo(f"  Enabled:  {job.enabled}")
    finally:
        await close_db()


@app.command(name="list")
def list_jobs() -> None:
    """List all scheduled scan jobs."""
    asyncio.run(_async_list_jobs())


async def _async_list_jobs() -> None:
    from rich.console import Console
    from rich.table import Table

    from malwar.core.config import get_settings
    from malwar.scheduler.store import JobStore
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        store = JobStore(db)
        jobs = await store.list_jobs()

        console = Console()
        table = Table(title="Scheduled Scan Jobs")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="bold")
        table.add_column("Target")
        table.add_column("Schedule")
        table.add_column("Enabled")
        table.add_column("Last Run")
        table.add_column("Next Run")

        for job in jobs:
            table.add_row(
                job.job_id,
                job.name,
                job.target_path,
                job.schedule,
                "yes" if job.enabled else "no",
                job.last_run.isoformat() if job.last_run else "-",
                job.next_run.isoformat() if job.next_run else "-",
            )

        console.print(table)
    finally:
        await close_db()


@app.command()
def run(
    job_id: Annotated[str, typer.Argument(help="Job ID to run immediately")],
) -> None:
    """Trigger an immediate run of a scheduled job."""
    asyncio.run(_async_run(job_id))


async def _async_run(job_id: str) -> None:
    from malwar.core.config import get_settings
    from malwar.scheduler.engine import SchedulerEngine
    from malwar.scheduler.store import JobStore
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        store = JobStore(db)
        job = await store.get_job(job_id)

        if job is None:
            typer.echo(f"Job {job_id} not found.", err=True)
            raise typer.Exit(1)

        typer.echo(f"Running job {job.job_id}: {job.name} ...")

        engine = SchedulerEngine(store)
        run_result = await engine.execute_job(job)

        typer.echo(f"  Run ID:     {run_result.run_id}")
        typer.echo(f"  Status:     {run_result.status}")
        typer.echo(f"  Verdict:    {run_result.verdict or '-'}")
        typer.echo(f"  Risk Score: {run_result.risk_score or 0}")
        if run_result.error:
            typer.echo(f"  Error:      {run_result.error}")
    finally:
        await close_db()
