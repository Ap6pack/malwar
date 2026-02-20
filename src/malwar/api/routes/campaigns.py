# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Campaign API endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from malwar.api.auth import require_api_key

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class CampaignResponse(BaseModel):
    id: str
    name: str
    description: str
    first_seen: str
    last_seen: str
    attributed_to: str | None = None
    iocs: list[str]
    total_skills_affected: int
    status: str


class CampaignDetailResponse(CampaignResponse):
    signature_count: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_response(row: dict) -> CampaignResponse:
    iocs_raw = row.get("iocs", "[]")
    iocs = json.loads(iocs_raw) if isinstance(iocs_raw, str) else iocs_raw
    return CampaignResponse(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        attributed_to=row.get("attributed_to"),
        iocs=iocs,
        total_skills_affected=row.get("total_skills_affected", 0),
        status=row["status"],
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/campaigns", response_model=list[CampaignResponse])
async def list_campaigns(
    _api_key: str = Depends(require_api_key),
) -> list[CampaignResponse]:
    """List all active campaigns."""
    from malwar.storage.database import get_db
    from malwar.storage.repositories.campaigns import CampaignRepository

    db = await get_db()
    repo = CampaignRepository(db)
    rows = await repo.list_active()
    return [_row_to_response(row) for row in rows]


@router.get("/campaigns/{campaign_id}", response_model=CampaignDetailResponse)
async def get_campaign(
    campaign_id: str,
    _api_key: str = Depends(require_api_key),
) -> CampaignDetailResponse:
    """Retrieve a single campaign with details."""
    from malwar.storage.database import get_db
    from malwar.storage.repositories.campaigns import CampaignRepository

    db = await get_db()
    repo = CampaignRepository(db)
    row = await repo.get(campaign_id)
    if row is None:
        raise HTTPException(
            status_code=404, detail=f"Campaign {campaign_id} not found"
        )

    iocs_raw = row.get("iocs", "[]")
    iocs = json.loads(iocs_raw) if isinstance(iocs_raw, str) else iocs_raw

    # Count associated signatures
    cursor = await db.execute(
        "SELECT COUNT(*) FROM signatures WHERE campaign_id = ?", (campaign_id,)
    )
    count_row = await cursor.fetchone()
    signature_count = count_row[0] if count_row else 0

    return CampaignDetailResponse(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        attributed_to=row.get("attributed_to"),
        iocs=iocs,
        total_skills_affected=row.get("total_skills_affected", 0),
        status=row["status"],
        signature_count=signature_count,
    )
