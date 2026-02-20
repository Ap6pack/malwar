# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Analytics API endpoints for API usage metering."""

from __future__ import annotations

import logging
from datetime import date

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from malwar.api.auth import require_api_key

logger = logging.getLogger("malwar.api.analytics")

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class DailyBucket(BaseModel):
    date: str
    count: int


class EndpointCount(BaseModel):
    endpoint: str
    count: int


class VerdictCount(BaseModel):
    verdict: str
    count: int


class AnalyticsResponse(BaseModel):
    total_requests: int
    requests_by_endpoint: list[EndpointCount]
    requests_by_verdict: list[VerdictCount]
    requests_over_time: list[DailyBucket]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _table_exists(db: object, table_name: str) -> bool:
    """Check whether *table_name* exists in the database."""
    cursor = await db.execute(  # type: ignore[union-attr]
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    return await cursor.fetchone() is not None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/analytics", response_model=AnalyticsResponse)
async def get_analytics(
    start_date: date | None = Query(default=None, description="Start date (YYYY-MM-DD)"),  # noqa: B008
    end_date: date | None = Query(default=None, description="End date (YYYY-MM-DD)"),  # noqa: B008
    api_key: str | None = Query(default=None, description="Filter by API key"),
    _auth_key: str = Depends(require_api_key),
) -> AnalyticsResponse:
    """Return API usage statistics.

    Supports optional filtering by date range and API key.
    Returns empty stats if the ``api_usage`` table has not been created yet.
    """
    from malwar.storage.database import get_db

    db = await get_db()

    # Graceful degradation: if table doesn't exist, return empty stats
    if not await _table_exists(db, "api_usage"):
        return AnalyticsResponse(
            total_requests=0,
            requests_by_endpoint=[],
            requests_by_verdict=[],
            requests_over_time=[],
        )

    # Build WHERE clause dynamically
    conditions: list[str] = []
    params: list[str] = []

    if start_date is not None:
        conditions.append("timestamp >= ?")
        params.append(start_date.isoformat())
    if end_date is not None:
        conditions.append("timestamp < date(?, '+1 day')")
        params.append(end_date.isoformat())
    if api_key is not None:
        conditions.append("api_key = ?")
        params.append(api_key)

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    # Total requests
    cursor = await db.execute(
        f"SELECT COUNT(*) FROM api_usage{where}", params  # noqa: S608
    )
    row = await cursor.fetchone()
    total_requests = row[0] if row else 0

    # Requests by endpoint
    cursor = await db.execute(
        f"SELECT endpoint, COUNT(*) AS cnt FROM api_usage{where} GROUP BY endpoint ORDER BY cnt DESC",  # noqa: S608
        params,
    )
    endpoint_rows = await cursor.fetchall()
    requests_by_endpoint = [
        EndpointCount(endpoint=r[0], count=r[1]) for r in endpoint_rows
    ]

    # Requests by verdict -- join with scans table via endpoint pattern
    # We track the scan endpoint's status_code; for verdict we need to
    # correlate with the scans table.  A simpler approach: count by status_code
    # group in the usage table.  However, the issue specifies "by verdict".
    # We join api_usage rows that hit /api/v1/scan (POST) with scans to get
    # verdicts.  For simplicity, we count verdicts from the scans table
    # directly, applying the same date/key filters where possible.
    verdict_conditions: list[str] = []
    verdict_params: list[str] = []
    if start_date is not None:
        verdict_conditions.append("created_at >= ?")
        verdict_params.append(start_date.isoformat())
    if end_date is not None:
        verdict_conditions.append("created_at < date(?, '+1 day')")
        verdict_params.append(end_date.isoformat())
    verdict_where = (
        (" WHERE " + " AND ".join(verdict_conditions)) if verdict_conditions else ""
    )

    cursor = await db.execute(
        f"SELECT verdict, COUNT(*) AS cnt FROM scans{verdict_where} GROUP BY verdict ORDER BY cnt DESC",  # noqa: S608
        verdict_params,
    )
    verdict_rows = await cursor.fetchall()
    requests_by_verdict = [
        VerdictCount(verdict=r[0], count=r[1]) for r in verdict_rows
    ]

    # Requests over time (daily buckets)
    cursor = await db.execute(
        f"SELECT date(timestamp) AS day, COUNT(*) AS cnt FROM api_usage{where} GROUP BY day ORDER BY day",  # noqa: S608
        params,
    )
    time_rows = await cursor.fetchall()
    requests_over_time = [
        DailyBucket(date=r[0], count=r[1]) for r in time_rows
    ]

    return AnalyticsResponse(
        total_requests=total_requests,
        requests_by_endpoint=requests_by_endpoint,
        requests_by_verdict=requests_by_verdict,
        requests_over_time=requests_over_time,
    )
