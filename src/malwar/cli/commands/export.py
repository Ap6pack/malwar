# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI commands for exporting threat intelligence in STIX/TAXII formats."""

from __future__ import annotations

import asyncio
import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer()


class ExportFormat(StrEnum):
    STIX = "stix"
    TAXII = "taxii"


@app.command(name="stix")
def export_stix(
    campaign: Annotated[
        str | None,
        typer.Option("--campaign", "-c", help="Export only a specific campaign (by name)"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write output to file instead of stdout"),
    ] = None,
    fmt: Annotated[
        ExportFormat,
        typer.Option("--format", "-f", help="Output format: stix (default) or taxii"),
    ] = ExportFormat.STIX,
) -> None:
    """Export threat intelligence as a STIX 2.1 bundle."""
    asyncio.run(_async_export_stix(campaign, output, fmt))


async def _async_export_stix(
    campaign_name: str | None,
    output: Path | None,
    fmt: ExportFormat,
) -> None:
    from malwar.core.config import get_settings
    from malwar.export.stix import build_stix_bundle
    from malwar.export.taxii import format_taxii_objects
    from malwar.storage.database import close_db, init_db
    from malwar.storage.repositories.campaigns import CampaignRepository
    from malwar.storage.repositories.scans import ScanRepository
    from malwar.storage.repositories.signatures import SignatureRepository

    settings = get_settings()
    db = await init_db(settings.db_path)

    try:
        campaign_repo = CampaignRepository(db)
        signature_repo = SignatureRepository(db)
        scan_repo = ScanRepository(db)

        # Fetch campaigns
        if campaign_name:
            # Look up campaign by name
            cursor = await db.execute(
                "SELECT * FROM campaigns WHERE name = ?", (campaign_name,)
            )
            row = await cursor.fetchone()
            if row is None:
                typer.echo(f"Campaign not found: {campaign_name}", err=True)
                raise typer.Exit(1)
            campaigns = [dict(row)]
            # Get signatures linked to this campaign only
            signatures = await signature_repo.get_by_campaign(campaigns[0]["id"])
        else:
            campaigns = await campaign_repo.list_active()
            signatures = await signature_repo.get_all()

        # Fetch recent scans
        scans = await scan_repo.list_recent(limit=100)

        bundle = build_stix_bundle(
            campaigns=campaigns,
            signatures=signatures,
            scans=scans,
        )

        result = format_taxii_objects(bundle) if fmt == ExportFormat.TAXII else bundle

        text = json.dumps(result, indent=2)

        if output:
            output.write_text(text)
            typer.echo(f"STIX bundle written to {output}")
        else:
            sys.stdout.write(text + "\n")
    finally:
        await close_db()
