# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Repository for campaign records."""

from __future__ import annotations

from typing import Any

import aiosqlite


class CampaignRepository:
    """Query tracked malware campaigns."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get(self, campaign_id: str) -> dict[str, Any] | None:
        """Retrieve a campaign by ID."""
        cursor = await self._db.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    async def list_active(self) -> list[dict[str, Any]]:
        """List all campaigns with status='active'."""
        cursor = await self._db.execute(
            "SELECT * FROM campaigns WHERE status = 'active' ORDER BY last_seen DESC"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
