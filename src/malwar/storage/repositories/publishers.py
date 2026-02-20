# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Repository for publisher/author records."""

from __future__ import annotations

from typing import Any

import aiosqlite


class PublisherRepository:
    """Query and manage publisher reputation data."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get(self, publisher_id: str) -> dict[str, Any] | None:
        """Retrieve a publisher by ID (author handle)."""
        cursor = await self._db.execute(
            "SELECT * FROM publishers WHERE id = ?", (publisher_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    async def is_known_threat_actor(self, publisher_id: str) -> bool:
        """Check whether a publisher is flagged as a known threat actor."""
        cursor = await self._db.execute(
            "SELECT is_known_threat_actor FROM publishers WHERE id = ?",
            (publisher_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return False
        return bool(row["is_known_threat_actor"])

    async def update_reputation(self, publisher_id: str, score: float) -> None:
        """Update a publisher's reputation score."""
        await self._db.execute(
            "UPDATE publishers SET reputation_score = ?, updated_at = datetime('now') WHERE id = ?",
            (score, publisher_id),
        )
        await self._db.commit()
