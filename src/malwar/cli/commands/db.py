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
