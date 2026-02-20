# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Database management commands."""

from __future__ import annotations

import asyncio

import typer

app = typer.Typer()


@app.command()
def init() -> None:
    """Initialize the SQLite database with schema and seed data."""
    asyncio.run(_init_db())


async def _init_db() -> None:
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    typer.echo(f"Initializing database at {settings.db_path}...")
    await init_db(settings.db_path)
    await close_db()
    typer.echo("Database initialized with schema and seed data.")


@app.command()
def migrate() -> None:
    """Apply pending database migrations.

    Shows the current schema version and any pending migrations,
    then applies them in order.
    """
    asyncio.run(_migrate_db())


async def _migrate_db() -> None:
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db
    from malwar.storage.migrations import (
        get_current_version,
        get_pending_migrations,
        run_migrations,
    )

    settings = get_settings()
    # Initialize without auto-migrate so we can show status first
    db = await init_db(settings.db_path, auto_migrate=False)

    try:
        current = await get_current_version(db)
        pending = await get_pending_migrations(db)

        typer.echo(f"Database: {settings.db_path}")
        typer.echo(f"Current schema version: {current}")

        if not pending:
            typer.echo("No pending migrations.")
            return

        typer.echo(f"Pending migrations: {len(pending)}")
        for m in pending:
            typer.echo(f"  {m.version:03d}: {m.name}")

        typer.echo()
        applied = await run_migrations(db)

        for m in applied:
            typer.echo(f"Applied migration {m.version:03d}: {m.name}")

        new_version = await get_current_version(db)
        typer.echo(f"\nSchema version is now: {new_version}")
    finally:
        await close_db()


@app.command()
def stats() -> None:
    """Show database statistics."""
    asyncio.run(_show_stats())


async def _show_stats() -> None:
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, get_db, init_db

    settings = get_settings()
    await init_db(settings.db_path)
    db = await get_db()

    tables = ["scans", "findings", "signatures", "campaigns", "publishers", "url_analysis"]
    typer.echo(f"Database: {settings.db_path}")
    typer.echo()
    for table in tables:
        cursor = await db.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
        row = await cursor.fetchone()
        count = row[0] if row else 0
        typer.echo(f"  {table}: {count} rows")

    await close_db()
