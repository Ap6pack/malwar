# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""SchedulerEngine — runs scheduled scan jobs on configurable cron schedules.

Uses pure asyncio (no external scheduler dependencies).  The engine is
started as a background task during ``malwar serve`` and checks for due
jobs every 30 seconds.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from datetime import UTC, datetime

from malwar.scheduler.cron import CronParseError, next_run_from_cron
from malwar.scheduler.jobs import JobRun, ScanJob
from malwar.scheduler.store import JobStore

logger = logging.getLogger("malwar.scheduler.engine")

_CHECK_INTERVAL_SECONDS = 30


class SchedulerEngine:
    """Asyncio-based scheduler that polls for due jobs and executes scans."""

    def __init__(self, store: JobStore, *, check_interval: float = _CHECK_INTERVAL_SECONDS) -> None:
        self._store = store
        self._check_interval = check_interval
        self._task: asyncio.Task[None] | None = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    async def start(self) -> None:
        """Start the scheduler background loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Scheduler engine started (interval=%ss)", self._check_interval)

    async def stop(self) -> None:
        """Gracefully stop the scheduler."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        logger.info("Scheduler engine stopped")

    async def _loop(self) -> None:
        """Main loop — check for due jobs at regular intervals."""
        while self._running:
            try:
                await self._tick()
            except Exception:
                logger.exception("Scheduler tick failed")
            await asyncio.sleep(self._check_interval)

    async def _tick(self) -> None:
        """Single tick — find and execute all due jobs."""
        now = datetime.now(UTC)
        due_jobs = await self._store.list_enabled_due_jobs(now)

        for job in due_jobs:
            logger.info("Executing due job: %s (%s)", job.job_id, job.name)
            await self.execute_job(job)

    async def execute_job(self, job: ScanJob) -> JobRun:
        """Execute a single scan job and record the run.

        Uses the existing ScanPipeline for scan execution to ensure
        consistent behavior with manual scans.
        """
        run = JobRun(
            run_id=uuid.uuid4().hex[:12],
            job_id=job.job_id,
            status="running",
            started_at=datetime.now(UTC),
        )
        await self._store.create_run(run)

        try:
            result = await self._run_scan(job)

            run.scan_id = result.scan_id
            run.status = "completed"
            run.verdict = result.verdict
            run.risk_score = result.risk_score
            run.completed_at = datetime.now(UTC)
        except Exception as exc:
            run.status = "failed"
            run.error = str(exc)
            run.completed_at = datetime.now(UTC)
            logger.error("Job %s failed: %s", job.job_id, exc)

        await self._store.update_run(run)

        # Update job's last_run and calculate next_run
        job.last_run = run.started_at
        try:
            job.next_run = next_run_from_cron(job.schedule, datetime.now(UTC))
        except CronParseError:
            logger.error("Invalid cron for job %s: %s", job.job_id, job.schedule)
        await self._store.update_job(job)

        return run

    async def _run_scan(self, job: ScanJob):
        """Execute the actual scan using the ScanPipeline."""
        from malwar.core.config import get_settings
        from malwar.detectors.llm_analyzer.detector import LlmAnalyzerDetector
        from malwar.detectors.rule_engine.detector import RuleEngineDetector
        from malwar.detectors.threat_intel.detector import ThreatIntelDetector
        from malwar.detectors.url_crawler.detector import UrlCrawlerDetector
        from malwar.scanner.pipeline import ScanPipeline

        settings = get_settings()

        pipeline = ScanPipeline(settings=settings)
        pipeline.register_detector(RuleEngineDetector())
        pipeline.register_detector(UrlCrawlerDetector())
        pipeline.register_detector(LlmAnalyzerDetector(settings=settings))
        pipeline.register_detector(ThreatIntelDetector())

        result = await pipeline.scan_file(
            job.target_path,
            layers=job.layers if job.layers else None,
        )

        # Persist scan result to the database (same as API scans)
        try:
            from malwar.storage.database import get_db
            from malwar.storage.repositories.findings import FindingRepository
            from malwar.storage.repositories.scans import ScanRepository

            db = await get_db()
            scan_repo = ScanRepository(db)
            finding_repo = FindingRepository(db)

            await scan_repo.create(result)
            if result.findings:
                await finding_repo.create_many(result.scan_id, result.findings)
        except Exception:
            logger.exception("Failed to persist scheduled scan %s", result.scan_id)

        return result
