# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Audit log API endpoints for querying the compliance audit trail."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from malwar.api.auth import require_api_key

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class AuditEventResponse(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    actor: str
    resource_type: str
    resource_id: str
    action: str
    details: dict[str, Any] = Field(default_factory=dict)
    ip_address: str


class AuditListResponse(BaseModel):
    total: int
    events: list[AuditEventResponse]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_response(row: dict[str, Any]) -> AuditEventResponse:
    """Convert a database row dict to an AuditEventResponse."""
    return AuditEventResponse(
        event_id=row["event_id"],
        timestamp=row["timestamp"],
        event_type=row["event_type"],
        actor=row["actor"],
        resource_type=row.get("resource_type", ""),
        resource_id=row.get("resource_id", ""),
        action=row.get("action", ""),
        details=row.get("details", {}),
        ip_address=row.get("ip_address", ""),
    )


async def _get_store():
    """Get an AuditStore bound to the active DB connection."""
    from malwar.audit.store import AuditStore
    from malwar.storage.database import get_db

    db = await get_db()
    return AuditStore(db)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/audit", response_model=AuditListResponse)
async def list_audit_events(
    event_type: str | None = None,
    actor: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    limit: int = 100,
    offset: int = 0,
    _api_key: str = Depends(require_api_key),
) -> AuditListResponse:
    """List audit events with optional filtering by date range, event_type, and actor."""
    store = await _get_store()

    total = await store.count_events(
        event_type=event_type,
        actor=actor,
        start_date=start_date,
        end_date=end_date,
    )
    events = await store.list_events(
        event_type=event_type,
        actor=actor,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )

    return AuditListResponse(
        total=total,
        events=[_row_to_response(row) for row in events],
    )


@router.get("/audit/{event_id}", response_model=AuditEventResponse)
async def get_audit_event(
    event_id: str,
    _api_key: str = Depends(require_api_key),
) -> AuditEventResponse:
    """Get a single audit event by ID."""
    store = await _get_store()
    row = await store.get_by_id(event_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Audit event {event_id} not found")
    return _row_to_response(row)
