# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""JobStore — persist scheduled scan jobs and run history to SQLite."""

from __future__ import annotations

from datetime import UTC, datetime

import aiosqlite

from malwar.scheduler.jobs import JobRun, ScanJob


class JobStore:
    """Persists scheduled scan jobs and their run history to SQLite."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Job CRUD
    # ------------------------------------------------------------------

    async def create_job(self, job: ScanJob) -> None:
        """Insert a new scheduled job."""
        await self._db.execute(
            """
            INSERT INTO scheduled_jobs
                (id, name, target_path, schedule, layers, enabled,
                 last_run, next_run, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job.job_id,
                job.name,
                job.target_path,
                job.schedule,
                ",".join(job.layers),
                1 if job.enabled else 0,
                job.last_run.isoformat() if job.last_run else None,
                job.next_run.isoformat() if job.next_run else None,
                job.created_at.isoformat(),
            ),
        )
        await self._db.commit()

    async def get_job(self, job_id: str) -> ScanJob | None:
        """Retrieve a single job by ID."""
        cursor = await self._db.execute(
            "SELECT * FROM scheduled_jobs WHERE id = ?", (job_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_job(row)

    async def list_jobs(self) -> list[ScanJob]:
        """Return all scheduled jobs ordered by creation time."""
        cursor = await self._db.execute(
            "SELECT * FROM scheduled_jobs ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [self._row_to_job(row) for row in rows]

    async def list_enabled_due_jobs(self, now: datetime) -> list[ScanJob]:
        """Return enabled jobs whose next_run is at or before *now*."""
        cursor = await self._db.execute(
            "SELECT * FROM scheduled_jobs WHERE enabled = 1 AND next_run <= ?",
            (now.isoformat(),),
        )
        rows = await cursor.fetchall()
        return [self._row_to_job(row) for row in rows]

    async def update_job(self, job: ScanJob) -> None:
        """Update an existing job's mutable fields."""
        await self._db.execute(
            """
            UPDATE scheduled_jobs
            SET name = ?, target_path = ?, schedule = ?, layers = ?,
                enabled = ?, last_run = ?, next_run = ?
            WHERE id = ?
            """,
            (
                job.name,
                job.target_path,
                job.schedule,
                ",".join(job.layers),
                1 if job.enabled else 0,
                job.last_run.isoformat() if job.last_run else None,
                job.next_run.isoformat() if job.next_run else None,
                job.job_id,
            ),
        )
        await self._db.commit()

    async def delete_job(self, job_id: str) -> bool:
        """Delete a job and its run history. Returns True if the job existed."""
        cursor = await self._db.execute(
            "DELETE FROM scheduled_jobs WHERE id = ?", (job_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Run history
    # ------------------------------------------------------------------

    async def create_run(self, run: JobRun) -> None:
        """Insert a new job run record."""
        await self._db.execute(
            """
            INSERT INTO job_runs
                (id, job_id, scan_id, status, verdict, risk_score,
                 error, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.run_id,
                run.job_id,
                run.scan_id,
                run.status,
                run.verdict,
                run.risk_score,
                run.error,
                run.started_at.isoformat(),
                run.completed_at.isoformat() if run.completed_at else None,
            ),
        )
        await self._db.commit()

    async def update_run(self, run: JobRun) -> None:
        """Update a run record (typically after completion)."""
        await self._db.execute(
            """
            UPDATE job_runs
            SET scan_id = ?, status = ?, verdict = ?, risk_score = ?,
                error = ?, completed_at = ?
            WHERE id = ?
            """,
            (
                run.scan_id,
                run.status,
                run.verdict,
                run.risk_score,
                run.error,
                run.completed_at.isoformat() if run.completed_at else None,
                run.run_id,
            ),
        )
        await self._db.commit()

    async def get_runs_for_job(self, job_id: str, limit: int = 20) -> list[JobRun]:
        """Return recent runs for a job, newest first."""
        cursor = await self._db.execute(
            "SELECT * FROM job_runs WHERE job_id = ? ORDER BY started_at DESC LIMIT ?",
            (job_id, limit),
        )
        rows = await cursor.fetchall()
        return [self._row_to_run(row) for row in rows]

    # ------------------------------------------------------------------
    # Row conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_job(row: aiosqlite.Row) -> ScanJob:
        data = dict(row)
        layers_str = data.get("layers") or ""
        layers = [part.strip() for part in layers_str.split(",") if part.strip()]
        return ScanJob(
            job_id=data["id"],
            name=data["name"],
            target_path=data["target_path"],
            schedule=data["schedule"],
            layers=layers if layers else ["rule_engine", "url_crawler", "llm_analyzer", "threat_intel"],
            enabled=bool(data["enabled"]),
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            next_run=datetime.fromisoformat(data["next_run"]) if data.get("next_run") else None,
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(UTC),
        )

    @staticmethod
    def _row_to_run(row: aiosqlite.Row) -> JobRun:
        data = dict(row)
        return JobRun(
            run_id=data["id"],
            job_id=data["job_id"],
            scan_id=data.get("scan_id"),
            status=data["status"],
            verdict=data.get("verdict"),
            risk_score=data.get("risk_score"),
            error=data.get("error"),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else datetime.now(UTC),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
        )
