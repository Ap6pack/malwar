# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Typer CLI application root."""

from __future__ import annotations

import typer

from malwar.cli.commands import scan, db

app = typer.Typer(
    name="malwar",
    help="Malware detection engine for agentic skills (SKILL.md)",
    no_args_is_help=True,
)

app.add_typer(scan.app, name="scan", help="Scan skills for threats")
app.add_typer(db.app, name="db", help="Database management")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    workers: int = typer.Option(1, "--workers", "-w", help="Worker count"),
) -> None:
    """Start the malwar API server."""
    import uvicorn

    uvicorn.run(
        "malwar.api.app:create_app",
        host=host,
        port=port,
        workers=workers,
        factory=True,
    )


@app.command()
def version() -> None:
    """Show version information."""
    from malwar import __version__

    typer.echo(f"malwar v{__version__}")
