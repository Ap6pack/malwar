# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""API endpoint for ingesting threat intelligence data."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from malwar.api.auth import require_api_key

router = APIRouter()


class IngestRequest(BaseModel):
    """Request body for the ingest endpoint."""

    source_type: str = Field(
        ...,
        description="Source format: json, csv, or stix",
        pattern=r"^(json|csv|stix)$",
    )
    data: str = Field(
        ...,
        min_length=1,
        description="The content to import (JSON string, CSV text, or STIX bundle JSON)",
    )


@router.post("/ingest")
async def ingest_data(
    body: IngestRequest,
    _api_key: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Import threat intelligence from a JSON, CSV, or STIX payload.

    Requires API key authentication.  Returns an ``ImportResult`` with
    counts of added, updated, and skipped records.
    """
    from malwar.ingestion.importer import CampaignImporter
    from malwar.ingestion.sources import (
        CsvStringSource,
        JsonStringSource,
        StixStringSource,
        ThreatSource,
    )
    from malwar.storage.database import get_db

    source: ThreatSource
    if body.source_type == "json":
        source = JsonStringSource(body.data)
    elif body.source_type == "csv":
        source = CsvStringSource(body.data)
    elif body.source_type == "stix":
        source = StixStringSource(body.data)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported source_type: {body.source_type}",
        )

    db = await get_db()
    importer = CampaignImporter(db)
    result = await importer.import_from(source)

    if result.errors and not result.campaigns_added and not result.campaigns_updated:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Import failed",
                "errors": result.errors,
            },
        )

    return result.to_dict()
