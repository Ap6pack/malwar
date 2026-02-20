# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI commands for ingesting threat intelligence from external sources."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer()


def _print_result(result: object) -> None:
    """Print an ImportResult summary to the console."""
    typer.echo("Import complete:")
    typer.echo(f"  Campaigns added:    {result.campaigns_added}")
    typer.echo(f"  Campaigns updated:  {result.campaigns_updated}")
    typer.echo(f"  Signatures added:   {result.signatures_added}")
    typer.echo(f"  Signatures skipped: {result.signatures_skipped}")
    if result.errors:
        typer.echo(f"  Errors: {len(result.errors)}")
        for err in result.errors:
            typer.echo(f"    - {err}", err=True)


@app.command(name="json")
def ingest_json(
    file: Annotated[
        Path,
        typer.Argument(help="Path to JSON file matching the import schema"),
    ],
) -> None:
    """Import campaigns from a JSON file."""
    if not file.exists():
        typer.echo(f"File not found: {file}", err=True)
        raise typer.Exit(1)
    asyncio.run(_async_ingest_json(file))


async def _async_ingest_json(file: Path) -> None:
    from malwar.core.config import get_settings
    from malwar.ingestion.importer import CampaignImporter
    from malwar.ingestion.sources import JsonFileSource
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)
    try:
        source = JsonFileSource(file)
        importer = CampaignImporter(db)
        result = await importer.import_from(source)
        _print_result(result)
    finally:
        await close_db()


@app.command(name="csv")
def ingest_csv(
    file: Annotated[
        Path,
        typer.Argument(help="Path to CSV file (campaign,ioc_type,ioc_value,severity)"),
    ],
) -> None:
    """Import campaigns from a CSV file."""
    if not file.exists():
        typer.echo(f"File not found: {file}", err=True)
        raise typer.Exit(1)
    asyncio.run(_async_ingest_csv(file))


async def _async_ingest_csv(file: Path) -> None:
    from malwar.core.config import get_settings
    from malwar.ingestion.importer import CampaignImporter
    from malwar.ingestion.sources import CsvFileSource
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)
    try:
        source = CsvFileSource(file)
        importer = CampaignImporter(db)
        result = await importer.import_from(source)
        _print_result(result)
    finally:
        await close_db()


@app.command(name="stix")
def ingest_stix(
    file: Annotated[
        Path,
        typer.Argument(help="Path to a STIX 2.1 JSON bundle file"),
    ],
) -> None:
    """Import campaigns from a STIX 2.1 bundle."""
    if not file.exists():
        typer.echo(f"File not found: {file}", err=True)
        raise typer.Exit(1)
    asyncio.run(_async_ingest_stix(file))


async def _async_ingest_stix(file: Path) -> None:
    from malwar.core.config import get_settings
    from malwar.ingestion.importer import CampaignImporter
    from malwar.ingestion.sources import StixBundleSource
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)
    try:
        source = StixBundleSource(file)
        importer = CampaignImporter(db)
        result = await importer.import_from(source)
        _print_result(result)
    finally:
        await close_db()


@app.command(name="url")
def ingest_url(
    url: Annotated[
        str,
        typer.Argument(help="URL to fetch threat intelligence from (JSON or CSV)"),
    ],
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Feed format: json (default) or csv"),
    ] = "json",
) -> None:
    """Fetch and import threat intelligence from an HTTP URL."""
    asyncio.run(_async_ingest_url(url, fmt))


async def _async_ingest_url(url: str, fmt: str) -> None:
    from malwar.core.config import get_settings
    from malwar.ingestion.importer import CampaignImporter
    from malwar.ingestion.sources import HttpFeedSource
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)
    try:
        source = HttpFeedSource(url, format=fmt)
        importer = CampaignImporter(db)
        result = await importer.import_from(source)
        _print_result(result)
    finally:
        await close_db()
