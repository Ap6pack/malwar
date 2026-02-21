# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Audit event persistence to the SQLite audit_log table."""

from __future__ import annotations

import json
from typing import Any

import aiosqlite

from malwar.audit.events import AuditEvent


class AuditStore:
    """Repository for persisting and querying audit events in SQLite."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def insert(self, event: AuditEvent) -> None:
        """Persist a single audit event."""
        await self._db.execute(
            """
            INSERT INTO audit_log (
                event_id, timestamp, event_type, actor,
                resource_type, resource_id, action, details, ip_address
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.timestamp.isoformat(),
                str(event.event_type),
                event.actor,
                event.resource_type,
                event.resource_id,
                event.action,
                json.dumps(event.details),
                event.ip_address,
            ),
        )
        await self._db.commit()

    async def get_by_id(self, event_id: str) -> dict[str, Any] | None:
        """Retrieve a single audit event by its ID."""
        cursor = await self._db.execute(
            "SELECT * FROM audit_log WHERE event_id = ?", (event_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_dict(row)

    async def list_events(
        self,
        *,
        event_type: str | None = None,
        actor: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit events with optional filters.

        Args:
            event_type: Filter by AuditEventType value.
            actor: Filter by actor (API key hash or 'cli').
            start_date: ISO-format lower bound on timestamp (inclusive).
            end_date: ISO-format upper bound on timestamp (inclusive).
            limit: Maximum number of results.
            offset: Number of rows to skip.

        Returns:
            List of audit event dicts ordered by timestamp descending.
        """
        clauses: list[str] = []
        params: list[Any] = []

        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        if actor is not None:
            clauses.append("actor = ?")
            params.append(actor)
        if start_date is not None:
            clauses.append("timestamp >= ?")
            params.append(start_date)
        if end_date is not None:
            clauses.append("timestamp <= ?")
            params.append(end_date)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        query = f"SELECT * FROM audit_log{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"  # noqa: S608
        params.extend([limit, offset])

        cursor = await self._db.execute(query, params)
        rows = await cursor.fetchall()
        return [_row_to_dict(row) for row in rows]

    async def count_events(
        self,
        *,
        event_type: str | None = None,
        actor: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> int:
        """Return the total count of events matching the given filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        if actor is not None:
            clauses.append("actor = ?")
            params.append(actor)
        if start_date is not None:
            clauses.append("timestamp >= ?")
            params.append(start_date)
        if end_date is not None:
            clauses.append("timestamp <= ?")
            params.append(end_date)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await self._db.execute(
            f"SELECT COUNT(*) FROM audit_log{where}",  # noqa: S608
            params,
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    """Convert an aiosqlite Row to a plain dict, parsing JSON details."""
    d = dict(row)
    if "details" in d and isinstance(d["details"], str):
        try:
            d["details"] = json.loads(d["details"])
        except (json.JSONDecodeError, TypeError):
            d["details"] = {}
    return d
