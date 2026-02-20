# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Signature CRUD API endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from malwar.api.auth import require_api_key

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class SignatureCreateRequest(BaseModel):
    name: str
    description: str
    severity: str = Field(description="critical | high | medium | low | info")
    category: str = Field(description="Threat category from ThreatCategory enum")
    pattern_type: str = Field(description="regex | exact | fuzzy | ioc")
    pattern_value: str
    ioc_type: str | None = Field(default=None, description="ip | domain | url | hash | email")
    campaign_id: str | None = None
    source: str = "manual"
    enabled: bool = True


class SignatureUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    category: str | None = None
    pattern_type: str | None = None
    pattern_value: str | None = None
    ioc_type: str | None = None
    campaign_id: str | None = None
    source: str | None = None
    enabled: bool | None = None


class SignatureResponse(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    category: str
    pattern_type: str
    pattern_value: str
    ioc_type: str | None = None
    campaign_id: str | None = None
    source: str
    enabled: bool
    created_at: str | None = None
    updated_at: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_response(row: dict) -> SignatureResponse:
    """Convert a database row dict to a SignatureResponse."""
    return SignatureResponse(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        severity=row["severity"],
        category=row["category"],
        pattern_type=row["pattern_type"],
        pattern_value=row["pattern_value"],
        ioc_type=row.get("ioc_type"),
        campaign_id=row.get("campaign_id"),
        source=row.get("source", "manual"),
        enabled=bool(row.get("enabled", 1)),
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


async def _get_repo():
    """Get a SignatureRepository bound to the active DB connection."""
    from malwar.storage.database import get_db
    from malwar.storage.repositories.signatures import SignatureRepository

    db = await get_db()
    return SignatureRepository(db)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/signatures", response_model=list[SignatureResponse])
async def list_signatures(
    pattern_type: str | None = None,
    ioc_type: str | None = None,
    campaign_id: str | None = None,
    _api_key: str = Depends(require_api_key),
) -> list[SignatureResponse]:
    """List all signatures with optional filters."""
    repo = await _get_repo()
    rows = await repo.get_all(
        pattern_type=pattern_type,
        ioc_type=ioc_type,
        campaign_id=campaign_id,
    )
    return [_row_to_response(row) for row in rows]


@router.get("/signatures/{sig_id}", response_model=SignatureResponse)
async def get_signature(
    sig_id: str,
    _api_key: str = Depends(require_api_key),
) -> SignatureResponse:
    """Get a single signature by ID."""
    repo = await _get_repo()
    row = await repo.get_by_id(sig_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Signature {sig_id} not found")
    return _row_to_response(row)


@router.post("/signatures", response_model=SignatureResponse, status_code=201)
async def create_signature(
    body: SignatureCreateRequest,
    _api_key: str = Depends(require_api_key),
) -> SignatureResponse:
    """Create a new threat signature."""
    repo = await _get_repo()

    sig_id = f"sig-{uuid.uuid4().hex[:12]}"
    sig_data = {
        "id": sig_id,
        "name": body.name,
        "description": body.description,
        "severity": body.severity,
        "category": body.category,
        "pattern_type": body.pattern_type,
        "pattern_value": body.pattern_value,
        "ioc_type": body.ioc_type,
        "campaign_id": body.campaign_id,
        "source": body.source,
        "enabled": body.enabled,
    }

    await repo.create(sig_data)

    # Fetch back the created record to include timestamps
    row = await repo.get_by_id(sig_id)
    return _row_to_response(row)


@router.put("/signatures/{sig_id}", response_model=SignatureResponse)
async def update_signature(
    sig_id: str,
    body: SignatureUpdateRequest,
    _api_key: str = Depends(require_api_key),
) -> SignatureResponse:
    """Update an existing signature."""
    repo = await _get_repo()

    existing = await repo.get_by_id(sig_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Signature {sig_id} not found")

    updates = body.model_dump(exclude_none=True)
    if updates:
        await repo.update(sig_id, updates)

    row = await repo.get_by_id(sig_id)
    return _row_to_response(row)


@router.delete("/signatures/{sig_id}", status_code=204)
async def delete_signature(
    sig_id: str,
    _api_key: str = Depends(require_api_key),
) -> None:
    """Delete a signature."""
    repo = await _get_repo()

    deleted = await repo.delete(sig_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Signature {sig_id} not found")
