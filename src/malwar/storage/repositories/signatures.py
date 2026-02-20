# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Repository for threat signature records."""

from __future__ import annotations

from typing import Any

import aiosqlite


class SignatureRepository:
    """Query and manage threat signatures."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def get_by_id(self, sig_id: str) -> dict[str, Any] | None:
        """Return a single signature by ID, or None if not found."""
        cursor = await self._db.execute(
            "SELECT * FROM signatures WHERE id = ?", (sig_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_all(
        self,
        *,
        pattern_type: str | None = None,
        ioc_type: str | None = None,
        campaign_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all signatures with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if pattern_type is not None:
            clauses.append("pattern_type = ?")
            params.append(pattern_type)
        if ioc_type is not None:
            clauses.append("ioc_type = ?")
            params.append(ioc_type)
        if campaign_id is not None:
            clauses.append("campaign_id = ?")
            params.append(campaign_id)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await self._db.execute(
            f"SELECT * FROM signatures{where} ORDER BY severity, name",  # noqa: S608
            params,
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_all_enabled(self) -> list[dict[str, Any]]:
        """Return all enabled signatures."""
        cursor = await self._db.execute(
            "SELECT * FROM signatures WHERE enabled = 1 ORDER BY severity, name"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_by_campaign(self, campaign_id: str) -> list[dict[str, Any]]:
        """Return all signatures linked to a campaign."""
        cursor = await self._db.execute(
            "SELECT * FROM signatures WHERE campaign_id = ? ORDER BY name",
            (campaign_id,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def create(self, signature: dict[str, Any]) -> None:
        """Insert a new signature."""
        await self._db.execute(
            """
            INSERT INTO signatures (
                id, name, description, severity, category,
                pattern_type, pattern_value, ioc_type,
                campaign_id, source, enabled
            ) VALUES (
                :id, :name, :description, :severity, :category,
                :pattern_type, :pattern_value, :ioc_type,
                :campaign_id, :source, :enabled
            )
            """,
            {
                "id": signature["id"],
                "name": signature["name"],
                "description": signature["description"],
                "severity": signature["severity"],
                "category": signature["category"],
                "pattern_type": signature["pattern_type"],
                "pattern_value": signature["pattern_value"],
                "ioc_type": signature.get("ioc_type"),
                "campaign_id": signature.get("campaign_id"),
                "source": signature.get("source", "manual"),
                "enabled": 1 if signature.get("enabled", True) else 0,
            },
        )
        await self._db.commit()

    async def update(self, sig_id: str, updates: dict[str, Any]) -> None:
        """Update fields on an existing signature."""
        if not updates:
            return

        # Always refresh updated_at
        updates["updated_at"] = "datetime('now')"

        set_parts: list[str] = []
        params: list[Any] = []

        for key, value in updates.items():
            if key == "updated_at":
                set_parts.append("updated_at = datetime('now')")
            else:
                set_parts.append(f"{key} = ?")
                params.append(value)

        params.append(sig_id)
        set_clause = ", ".join(set_parts)
        await self._db.execute(
            f"UPDATE signatures SET {set_clause} WHERE id = ?",  # noqa: S608
            params,
        )
        await self._db.commit()

    async def delete(self, sig_id: str) -> bool:
        """Delete a signature by ID. Return True if a row was deleted."""
        cursor = await self._db.execute(
            "DELETE FROM signatures WHERE id = ?", (sig_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0
