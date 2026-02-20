# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""API endpoints for STIX/TAXII threat intelligence export."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from malwar.api.auth import require_api_key

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _fetch_campaign_by_name(db, name: str) -> dict | None:
    """Look up a campaign by name."""
    cursor = await db.execute(
        "SELECT * FROM campaigns WHERE name = ?", (name,)
    )
    row = await cursor.fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# STIX endpoints
# ---------------------------------------------------------------------------

@router.get("/export/stix")
async def export_stix_bundle(
    campaign: str | None = None,
    _api_key: str = Depends(require_api_key),
) -> dict:
    """Export Malwar threat intelligence as a STIX 2.1 bundle.

    Optionally filter by campaign name using the ``campaign`` query parameter.
    """
    from malwar.export.stix import build_stix_bundle
    from malwar.storage.database import get_db
    from malwar.storage.repositories.campaigns import CampaignRepository
    from malwar.storage.repositories.scans import ScanRepository
    from malwar.storage.repositories.signatures import SignatureRepository

    db = await get_db()
    campaign_repo = CampaignRepository(db)
    signature_repo = SignatureRepository(db)
    scan_repo = ScanRepository(db)

    if campaign:
        row = await _fetch_campaign_by_name(db, campaign)
        if row is None:
            raise HTTPException(
                status_code=404,
                detail=f"Campaign not found: {campaign}",
            )
        campaigns = [row]
        signatures = await signature_repo.get_by_campaign(row["id"])
    else:
        campaigns = await campaign_repo.list_active()
        signatures = await signature_repo.get_all()

    scans = await scan_repo.list_recent(limit=100)

    bundle = build_stix_bundle(
        campaigns=campaigns,
        signatures=signatures,
        scans=scans,
    )
    return bundle


# ---------------------------------------------------------------------------
# TAXII endpoints
# ---------------------------------------------------------------------------

@router.get("/export/taxii/discovery")
async def taxii_discovery(
    _api_key: str = Depends(require_api_key),
) -> dict:
    """TAXII 2.1 discovery endpoint."""
    from malwar.export.taxii import format_taxii_discovery

    return format_taxii_discovery()


@router.get("/export/taxii/collections")
async def taxii_collections(
    _api_key: str = Depends(require_api_key),
) -> dict:
    """TAXII 2.1 collections listing."""
    from malwar.export.taxii import format_taxii_collections

    return format_taxii_collections()


@router.get("/export/taxii/collections/{collection_id}/objects")
async def taxii_collection_objects(
    collection_id: str,
    _api_key: str = Depends(require_api_key),
) -> dict:
    """TAXII 2.1 collection objects endpoint.

    Returns STIX objects wrapped in a TAXII envelope for the
    requested collection.
    """
    from malwar.export.stix import build_stix_bundle
    from malwar.export.taxii import format_taxii_objects
    from malwar.storage.database import get_db
    from malwar.storage.repositories.campaigns import CampaignRepository
    from malwar.storage.repositories.scans import ScanRepository
    from malwar.storage.repositories.signatures import SignatureRepository

    expected_collection = "malwar-threat-intel-001"
    if collection_id != expected_collection:
        raise HTTPException(
            status_code=404,
            detail=f"Collection not found: {collection_id}",
        )

    db = await get_db()
    campaign_repo = CampaignRepository(db)
    signature_repo = SignatureRepository(db)
    scan_repo = ScanRepository(db)

    campaigns = await campaign_repo.list_active()
    signatures = await signature_repo.get_all()
    scans = await scan_repo.list_recent(limit=100)

    bundle = build_stix_bundle(
        campaigns=campaigns,
        signatures=signatures,
        scans=scans,
    )

    return format_taxii_objects(bundle)
