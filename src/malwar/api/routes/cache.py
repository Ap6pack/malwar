# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Cache management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from malwar.api.rbac import require_config_manage

router = APIRouter()


class CacheClearResponse(BaseModel):
    cleared: int
    message: str


class CacheStatsResponse(BaseModel):
    hits: int
    misses: int
    total: int
    hit_rate: float
    size: int


@router.post("/cache/clear", response_model=CacheClearResponse)
async def clear_cache(
    _auth: object = Depends(require_config_manage),
) -> CacheClearResponse:
    """Flush the scan result cache (admin only)."""
    from malwar.cache.manager import get_cache_manager

    mgr = get_cache_manager()
    count = await mgr.clear()
    return CacheClearResponse(cleared=count, message=f"Cleared {count} cached entries")


@router.get("/cache/stats", response_model=CacheStatsResponse)
async def cache_stats(
    _auth: object = Depends(require_config_manage),
) -> CacheStatsResponse:
    """Show cache hit/miss statistics and current size."""
    from malwar.cache.manager import get_cache_manager

    mgr = get_cache_manager()
    stats = mgr.stats
    current_size = await mgr.size()
    return CacheStatsResponse(
        hits=stats.hits,
        misses=stats.misses,
        total=stats.total,
        hit_rate=round(stats.hit_rate, 4),
        size=current_size,
    )
