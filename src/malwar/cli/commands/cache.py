# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Cache management CLI commands."""

from __future__ import annotations

import asyncio

import typer

app = typer.Typer()


@app.command()
def clear() -> None:
    """Flush the scan result cache."""
    asyncio.run(_async_clear())


async def _async_clear() -> None:
    from malwar.cache.manager import get_cache_manager

    mgr = get_cache_manager()
    count = await mgr.clear()
    typer.echo(f"Cache cleared: {count} entries removed.")


@app.command()
def stats() -> None:
    """Show cache hit/miss counts and size."""
    asyncio.run(_async_stats())


async def _async_stats() -> None:
    from rich.console import Console
    from rich.table import Table

    from malwar.cache.manager import get_cache_manager

    mgr = get_cache_manager()
    st = mgr.stats
    current_size = await mgr.size()

    console = Console()
    table = Table(title="Cache Statistics")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Hits", str(st.hits))
    table.add_row("Misses", str(st.misses))
    table.add_row("Total Requests", str(st.total))
    table.add_row("Hit Rate", f"{st.hit_rate:.2%}")
    table.add_row("Entries", str(current_size))

    console.print(table)
