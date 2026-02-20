# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Public IOC feed endpoint.

Provides a machine-readable feed of all Indicators of Compromise (IOCs)
stored in the signature database.  Supports filtering by campaign, IOC
type, severity, and date.  Supports JSON and CSV output formats as well
as ETag-based conditional requests for efficient polling.
"""

from __future__ import annotations

import csv
import hashlib
import io
from typing import Any

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter()


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


class IOCEntry(BaseModel):
    """A single IOC record returned by the feed."""

    id: str
    name: str
    pattern_value: str
    ioc_type: str | None = None
    severity: str
    campaign_id: str | None = None
    source: str
    updated_at: str | None = None


class IOCFeedResponse(BaseModel):
    """Paginated IOC feed response."""

    total: int
    offset: int
    limit: int
    items: list[IOCEntry]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_entry(row: dict[str, Any]) -> IOCEntry:
    return IOCEntry(
        id=row["id"],
        name=row["name"],
        pattern_value=row["pattern_value"],
        ioc_type=row.get("ioc_type"),
        severity=row["severity"],
        campaign_id=row.get("campaign_id"),
        source=row.get("source", "manual"),
        updated_at=row.get("updated_at"),
    )


def _compute_etag(rows: list[dict[str, Any]]) -> str:
    """Compute an ETag from the latest updated_at across all rows."""
    latest = ""
    for row in rows:
        updated = row.get("updated_at") or ""
        if updated > latest:
            latest = updated
    digest = hashlib.md5(latest.encode()).hexdigest()  # noqa: S324
    return f'"{digest}"'


def _rows_to_csv(rows: list[dict[str, Any]]) -> str:
    """Serialise rows to CSV string."""
    output = io.StringIO()
    fieldnames = [
        "id",
        "name",
        "pattern_value",
        "ioc_type",
        "severity",
        "campaign_id",
        "source",
        "updated_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "id": row["id"],
                "name": row["name"],
                "pattern_value": row["pattern_value"],
                "ioc_type": row.get("ioc_type") or "",
                "severity": row["severity"],
                "campaign_id": row.get("campaign_id") or "",
                "source": row.get("source", "manual"),
                "updated_at": row.get("updated_at") or "",
            }
        )
    return output.getvalue()


async def _query_iocs(
    *,
    campaign_id: str | None = None,
    ioc_type: str | None = None,
    severity: str | None = None,
    since: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Query the signatures table with filters and return (rows, total)."""
    from malwar.storage.database import get_db

    db = await get_db()

    clauses: list[str] = ["enabled = 1"]
    params: list[Any] = []

    if campaign_id is not None:
        clauses.append("campaign_id = ?")
        params.append(campaign_id)
    if ioc_type is not None:
        clauses.append("ioc_type = ?")
        params.append(ioc_type)
    if severity is not None:
        clauses.append("severity = ?")
        params.append(severity)
    if since is not None:
        clauses.append("updated_at > ?")
        params.append(since)

    where = " WHERE " + " AND ".join(clauses)

    # Total count for pagination
    count_cursor = await db.execute(
        f"SELECT COUNT(*) FROM signatures{where}",  # noqa: S608
        params,
    )
    count_row = await count_cursor.fetchone()
    total = int(count_row[0]) if count_row else 0

    # Fetch page
    query = (
        f"SELECT * FROM signatures{where}"  # noqa: S608
        " ORDER BY updated_at DESC, id"
        " LIMIT ? OFFSET ?"
    )
    cursor = await db.execute(query, [*params, limit, offset])
    rows = await cursor.fetchall()

    return [dict(r) for r in rows], total


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get("/feed/iocs")
async def get_ioc_feed(
    request: Request,
    campaign_id: str | None = Query(default=None, description="Filter by campaign ID"),
    ioc_type: str | None = Query(
        default=None, description="Filter by IOC type (ip, domain, url, hash)"
    ),
    severity: str | None = Query(
        default=None, description="Filter by severity (critical, high, medium, low, info)"
    ),
    since: str | None = Query(
        default=None, description="ISO datetime; only IOCs updated after this date"
    ),
    format: str = Query(  # noqa: A002
        default="json", description="Response format: json (default) or csv"
    ),
    limit: int = Query(default=100, ge=1, le=1000, description="Page size"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
) -> Response:
    """Return IOCs from the signature database.

    Supports ETag / If-None-Match for efficient polling.
    """
    rows, total = await _query_iocs(
        campaign_id=campaign_id,
        ioc_type=ioc_type,
        severity=severity,
        since=since,
        limit=limit,
        offset=offset,
    )

    # Compute ETag from the latest updated_at in the *full* result set
    # (not just the current page) for consistency.  We use the page rows
    # for simplicity since the caller is polling this specific view.
    etag = _compute_etag(rows)

    # Check If-None-Match
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})

    if format == "csv":
        csv_text = _rows_to_csv(rows)
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={"ETag": etag},
        )

    # JSON (default)
    entries = [_row_to_entry(r) for r in rows]
    body = IOCFeedResponse(
        total=total,
        offset=offset,
        limit=limit,
        items=entries,
    )
    return JSONResponse(
        content=body.model_dump(),
        headers={"ETag": etag},
    )
