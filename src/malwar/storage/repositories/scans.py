# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Repository for scan records."""

from __future__ import annotations

import json
from typing import Any

import aiosqlite

from malwar.models.scan import ScanResult


class ScanRepository:
    """CRUD operations for the scans table."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def create(self, scan: ScanResult) -> None:
        """Persist a ScanResult to the database."""
        await self._db.execute(
            """
            INSERT INTO scans (
                id, target, skill_name, skill_author, skill_sha256,
                status, risk_score, overall_severity, verdict,
                layers_executed, errors, started_at, completed_at, duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan.scan_id,
                scan.target,
                scan.skill_name,
                scan.skill_author,
                scan.skill_sha256,
                str(scan.status),
                scan.risk_score,
                str(scan.overall_severity),
                scan.verdict,
                json.dumps(scan.layers_executed),
                json.dumps(scan.errors),
                scan.started_at.isoformat(),
                scan.completed_at.isoformat() if scan.completed_at else None,
                scan.duration_ms,
            ),
        )
        await self._db.commit()

    async def get(self, scan_id: str) -> ScanResult | None:
        """Retrieve a scan by ID, returning a ScanResult or None."""
        cursor = await self._db.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_scan_result(row)

    async def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """List the most recent scans as dicts, ordered by created_at desc."""
        cursor = await self._db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def update_status(
        self,
        scan_id: str,
        status: str,
        *,
        risk_score: int | None = None,
        overall_severity: str | None = None,
        verdict: str | None = None,
        completed_at: str | None = None,
        duration_ms: int | None = None,
        layers_executed: list[str] | None = None,
        errors: list[str] | None = None,
    ) -> None:
        """Update a scan's status and optional result fields."""
        fields: list[str] = ["status = ?"]
        params: list[Any] = [status]

        if risk_score is not None:
            fields.append("risk_score = ?")
            params.append(risk_score)
        if overall_severity is not None:
            fields.append("overall_severity = ?")
            params.append(overall_severity)
        if verdict is not None:
            fields.append("verdict = ?")
            params.append(verdict)
        if completed_at is not None:
            fields.append("completed_at = ?")
            params.append(completed_at)
        if duration_ms is not None:
            fields.append("duration_ms = ?")
            params.append(duration_ms)
        if layers_executed is not None:
            fields.append("layers_executed = ?")
            params.append(json.dumps(layers_executed))
        if errors is not None:
            fields.append("errors = ?")
            params.append(json.dumps(errors))

        params.append(scan_id)
        set_clause = ", ".join(fields)
        await self._db.execute(
            f"UPDATE scans SET {set_clause} WHERE id = ?",  # noqa: S608
            params,
        )
        await self._db.commit()

    @staticmethod
    def _row_to_scan_result(row: aiosqlite.Row) -> ScanResult:
        """Convert a database row to a ScanResult model."""
        data = dict(row)
        return ScanResult(
            scan_id=data["id"],
            target=data["target"],
            skill_name=data.get("skill_name"),
            skill_author=data.get("skill_author"),
            skill_sha256=data.get("skill_sha256") or "",
            status=data["status"],
            started_at=data["started_at"],
            completed_at=data.get("completed_at"),
            duration_ms=data.get("duration_ms"),
            layers_executed=json.loads(data.get("layers_executed") or "[]"),
            errors=json.loads(data.get("errors") or "[]"),
            # findings are not stored in the scans table; loaded separately
            findings=[],
        )
