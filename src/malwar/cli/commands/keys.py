# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI commands for API key management (RBAC)."""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer

app = typer.Typer()


@app.command(name="create")
def keys_create(
    role: Annotated[
        str,
        typer.Option("--role", "-r", help="Role: admin | analyst | scanner | readonly"),
    ] = "scanner",
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="Human-readable label for the key"),
    ] = "",
) -> None:
    """Create a new API key with a given role."""
    asyncio.run(_async_keys_create(role, name))


async def _async_keys_create(role: str, name: str) -> None:
    from malwar.api.keys import APIKeyManager
    from malwar.api.rbac import Role
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        # Validate role
        try:
            r = Role(role.lower())
        except ValueError:
            typer.echo(f"Invalid role: {role}. Must be one of: admin, analyst, scanner, readonly", err=True)
            raise typer.Exit(1) from None

        label = name or f"{r.value}-key"
        km = APIKeyManager(db)
        record, raw_key = await km.create_key(label, r)

        typer.echo(f"Key ID:   {record['id']}")
        typer.echo(f"Name:     {record['name']}")
        typer.echo(f"Role:     {record['role']}")
        typer.echo(f"API Key:  {raw_key}")
        typer.echo("")
        typer.echo("Store this key securely. It cannot be retrieved again.")
    finally:
        await close_db()


@app.command(name="list")
def keys_list() -> None:
    """List all API keys (without revealing key values)."""
    asyncio.run(_async_keys_list())


async def _async_keys_list() -> None:
    from rich.console import Console
    from rich.table import Table

    from malwar.api.keys import APIKeyManager
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        km = APIKeyManager(db)
        rows = await km.list_keys()

        console = Console()
        table = Table(title="API Keys")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="bold")
        table.add_column("Role")
        table.add_column("Active")
        table.add_column("Created At")
        table.add_column("Last Used")

        for row in rows:
            table.add_row(
                row["id"],
                row["name"],
                row["role"],
                "yes" if row.get("is_active") else "no",
                row.get("created_at") or "-",
                row.get("last_used") or "-",
            )

        console.print(table)
    finally:
        await close_db()


@app.command(name="revoke")
def keys_revoke(
    key_id: Annotated[str, typer.Argument(help="ID of the key to revoke")],
) -> None:
    """Revoke (deactivate) an API key."""
    asyncio.run(_async_keys_revoke(key_id))


async def _async_keys_revoke(key_id: str) -> None:
    from malwar.api.keys import APIKeyManager
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        km = APIKeyManager(db)
        revoked = await km.revoke_key(key_id)
        if revoked:
            typer.echo(f"Key {key_id} revoked.")
        else:
            typer.echo(f"Key {key_id} not found.", err=True)
            raise typer.Exit(1)
    finally:
        await close_db()
