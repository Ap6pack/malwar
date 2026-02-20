# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Health check endpoints."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "malwar", "version": "0.1.0"}


@router.get("/ready")
async def ready() -> dict[str, str]:
    from malwar.storage.database import get_db

    try:
        db = await get_db()
        cursor = await db.execute("SELECT 1")
        await cursor.fetchone()
        return {"status": "ready", "database": "connected"}
    except Exception as exc:
        return {"status": "not_ready", "database": str(exc)}
