# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Repository for finding records."""

from __future__ import annotations

import json
from typing import Any

import aiosqlite

from malwar.models.finding import Finding


class FindingRepository:
    """CRUD operations for the findings table."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def create_many(self, scan_id: str, findings: list[Finding]) -> None:
        """Bulk-insert findings for a given scan."""
        rows = [
            (
                f.id,
                scan_id,
                f.rule_id,
                f.title,
                f.description,
                str(f.severity),
                f.confidence,
                str(f.category),
                str(f.detector_layer),
                f.location.line_start if f.location else None,
                f.location.line_end if f.location else None,
                f.location.snippet if f.location else None,
                json.dumps(f.evidence),
                json.dumps(f.ioc_values),
                f.remediation,
                f.detected_at.isoformat(),
            )
            for f in findings
        ]
        await self._db.executemany(
            """
            INSERT INTO findings (
                id, scan_id, rule_id, title, description,
                severity, confidence, category, detector_layer,
                line_start, line_end, snippet,
                evidence, ioc_values, remediation, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        await self._db.commit()

    async def get_by_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """Retrieve all findings for a scan."""
        cursor = await self._db.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, detected_at",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_by_severity(
        self, severity: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Retrieve findings by severity level."""
        cursor = await self._db.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY detected_at DESC LIMIT ?",
            (severity, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
