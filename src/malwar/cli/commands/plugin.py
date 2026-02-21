# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI commands for managing detector plugins."""

from __future__ import annotations

from typing import Annotated

import typer

app = typer.Typer()


@app.command(name="list")
def plugin_list() -> None:
    """List installed detector plugins with status."""
    from rich.console import Console
    from rich.table import Table

    from malwar.core.config import get_settings
    from malwar.plugins.manager import PluginManager

    settings = get_settings()
    mgr = PluginManager()
    enabled_names = settings.enabled_plugins or None
    mgr.discover(
        plugins_dir=settings.plugins_dir,
        module_paths=settings.plugin_module_paths or None,
        enabled_names=enabled_names,
    )

    plugins = mgr.list_plugins()
    console = Console()

    if not plugins:
        console.print("[dim]No plugins installed.[/dim]")
        return

    table = Table(title="Detector Plugins")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Version")
    table.add_column("Author")
    table.add_column("Layer")
    table.add_column("Status")
    table.add_column("Description")

    for p in plugins:
        status = "[green]enabled[/green]" if p.enabled else "[red]disabled[/red]"
        table.add_row(p.name, p.version, p.author, p.layer_name, status, p.description)

    console.print(table)


@app.command()
def enable(
    name: Annotated[str, typer.Argument(help="Plugin name to enable")],
) -> None:
    """Enable a detector plugin."""
    from malwar.core.config import get_settings
    from malwar.plugins.manager import PluginManager

    settings = get_settings()
    mgr = PluginManager()
    mgr.discover(
        plugins_dir=settings.plugins_dir,
        module_paths=settings.plugin_module_paths or None,
    )

    if mgr.enable(name):
        typer.echo(f"Plugin '{name}' enabled.")
    else:
        typer.echo(f"Plugin '{name}' not found.", err=True)
        raise typer.Exit(1)


@app.command()
def disable(
    name: Annotated[str, typer.Argument(help="Plugin name to disable")],
) -> None:
    """Disable a detector plugin."""
    from malwar.core.config import get_settings
    from malwar.plugins.manager import PluginManager

    settings = get_settings()
    mgr = PluginManager()
    mgr.discover(
        plugins_dir=settings.plugins_dir,
        module_paths=settings.plugin_module_paths or None,
    )

    if mgr.disable(name):
        typer.echo(f"Plugin '{name}' disabled.")
    else:
        typer.echo(f"Plugin '{name}' not found.", err=True)
        raise typer.Exit(1)
