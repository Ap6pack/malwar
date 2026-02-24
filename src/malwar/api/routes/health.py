# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Health check endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from malwar import __version__

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class ReadyResponse(BaseModel):
    status: str
    database: str


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", service="malwar", version=__version__)


@router.get("/ready", response_model=ReadyResponse)
async def ready() -> ReadyResponse:
    from malwar.storage.database import get_db

    try:
        db = await get_db()
        cursor = await db.execute("SELECT 1")
        await cursor.fetchone()
        return ReadyResponse(status="ready", database="connected")
    except Exception as exc:
        return ReadyResponse(status="not_ready", database=str(exc))
