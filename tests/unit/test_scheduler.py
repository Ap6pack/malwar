# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for the scheduled scanning subsystem (issue #26).

Covers cron parsing, job management (CRUD), store persistence,
and scheduler engine logic.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import aiosqlite
import pytest

from malwar.scheduler.cron import CronParseError, next_run_from_cron, parse_cron
from malwar.scheduler.engine import SchedulerEngine
from malwar.scheduler.jobs import JobRun, ScanJob
from malwar.scheduler.store import JobStore
from malwar.storage.database import close_db, init_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db():
    """In-memory database with all migrations applied."""
    import malwar.storage.database as db_mod

    db_mod._db = None
    conn = await init_db(":memory:")
    yield conn
    await close_db()


@pytest.fixture
async def store(db: aiosqlite.Connection) -> JobStore:
    """A JobStore backed by the in-memory database."""
    return JobStore(db)


def _make_job(**overrides) -> ScanJob:
    """Create a ScanJob with sensible defaults, accepting overrides."""
    defaults = {
        "job_id": "sched-test-001",
        "name": "Test scan",
        "target_path": "/tmp/test/SKILL.md",
        "schedule": "0 */6 * * *",
        "layers": ["rule_engine"],
        "enabled": True,
        "last_run": None,
        "next_run": datetime(2026, 3, 1, 6, 0, tzinfo=UTC),
        "created_at": datetime(2026, 2, 20, 12, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return ScanJob(**defaults)


# =========================================================================
# Cron parsing tests
# =========================================================================


class TestCronParsing:
    """Tests for the cron expression parser."""

    def test_parse_all_stars(self):
        """'* * * * *' matches every minute."""
        minutes, hours, days, months, weekdays = parse_cron("* * * * *")
        assert minutes == set(range(0, 60))
        assert hours == set(range(0, 24))
        assert days == set(range(1, 32))
        assert months == set(range(1, 13))
        assert weekdays == set(range(0, 7))

    def test_parse_specific_values(self):
        """'30 14 1 6 3' should match exactly those values."""
        minutes, hours, days, months, weekdays = parse_cron("30 14 1 6 3")
        assert minutes == {30}
        assert hours == {14}
        assert days == {1}
        assert months == {6}
        assert weekdays == {3}

    def test_parse_step_values(self):
        """'*/15 */6 * * *' should produce correct step intervals."""
        minutes, hours, _days, _months, _weekdays = parse_cron("*/15 */6 * * *")
        assert minutes == {0, 15, 30, 45}
        assert hours == {0, 6, 12, 18}

    def test_parse_range(self):
        """'0 9-17 * * *' matches hours 9 through 17."""
        minutes, hours, _days, _months, _weekdays = parse_cron("0 9-17 * * *")
        assert minutes == {0}
        assert hours == set(range(9, 18))

    def test_parse_list(self):
        """'0 0 1,15 * *' matches days 1 and 15."""
        _minutes, _hours, days, _months, _weekdays = parse_cron("0 0 1,15 * *")
        assert days == {1, 15}

    def test_parse_combined_list_and_range(self):
        """'0,30 1-3 * * *' combines comma-separated and range values."""
        minutes, hours, _days, _months, _weekdays = parse_cron("0,30 1-3 * * *")
        assert minutes == {0, 30}
        assert hours == {1, 2, 3}

    def test_invalid_field_count(self):
        """Expressions with wrong number of fields should raise CronParseError."""
        with pytest.raises(CronParseError, match="5 fields"):
            parse_cron("* * *")

    def test_invalid_value(self):
        """Non-numeric values should raise CronParseError."""
        with pytest.raises(CronParseError, match="Invalid value"):
            parse_cron("abc * * * *")

    def test_out_of_bounds_minute(self):
        """Minute value 60 is out of range 0-59."""
        with pytest.raises(CronParseError, match="out of bounds"):
            parse_cron("60 * * * *")

    def test_out_of_bounds_hour(self):
        """Hour value 25 is out of range 0-23."""
        with pytest.raises(CronParseError, match="out of bounds"):
            parse_cron("0 25 * * *")

    def test_out_of_bounds_day(self):
        """Day value 32 is out of range 1-31."""
        with pytest.raises(CronParseError, match="out of bounds"):
            parse_cron("0 0 32 * *")

    def test_invalid_step_zero(self):
        """Step of 0 should raise CronParseError."""
        with pytest.raises(CronParseError, match="Step must be positive"):
            parse_cron("*/0 * * * *")

    def test_invalid_range_reversed(self):
        """Range 17-9 (lo > hi) should raise CronParseError."""
        with pytest.raises(CronParseError, match="out of bounds"):
            parse_cron("0 17-9 * * *")


# =========================================================================
# next_run_from_cron tests
# =========================================================================


class TestNextRunFromCron:
    """Tests for calculating the next scheduled run time."""

    def test_every_hour(self):
        """'0 * * * *' after 14:30 should give 15:00."""
        after = datetime(2026, 2, 20, 14, 30, 0, tzinfo=UTC)
        result = next_run_from_cron("0 * * * *", after)
        assert result == datetime(2026, 2, 20, 15, 0, tzinfo=UTC)

    def test_every_6_hours(self):
        """'0 */6 * * *' after 07:00 should give 12:00."""
        after = datetime(2026, 2, 20, 7, 0, 0, tzinfo=UTC)
        result = next_run_from_cron("0 */6 * * *", after)
        assert result == datetime(2026, 2, 20, 12, 0, tzinfo=UTC)

    def test_specific_time_tomorrow(self):
        """'30 2 * * *' after 02:30 should give 02:30 tomorrow."""
        after = datetime(2026, 2, 20, 2, 30, 0, tzinfo=UTC)
        result = next_run_from_cron("30 2 * * *", after)
        assert result == datetime(2026, 2, 21, 2, 30, tzinfo=UTC)

    def test_monthly_job(self):
        """'0 0 1 * *' after Jan 2 should give Feb 1."""
        after = datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC)
        result = next_run_from_cron("0 0 1 * *", after)
        assert result == datetime(2026, 2, 1, 0, 0, tzinfo=UTC)

    def test_every_minute(self):
        """'* * * * *' should return the next full minute."""
        after = datetime(2026, 2, 20, 12, 34, 56, tzinfo=UTC)
        result = next_run_from_cron("* * * * *", after)
        assert result == datetime(2026, 2, 20, 12, 35, tzinfo=UTC)

    def test_every_15_minutes(self):
        """'*/15 * * * *' after 12:16 should give 12:30."""
        after = datetime(2026, 2, 20, 12, 16, 0, tzinfo=UTC)
        result = next_run_from_cron("*/15 * * * *", after)
        assert result == datetime(2026, 2, 20, 12, 30, tzinfo=UTC)


# =========================================================================
# ScanJob dataclass tests
# =========================================================================


class TestScanJob:
    """Tests for the ScanJob dataclass."""

    def test_defaults(self):
        """Default fields should be set correctly."""
        job = ScanJob(
            job_id="sched-abc",
            name="Test",
            target_path="/tmp/test.md",
            schedule="0 * * * *",
        )
        assert job.enabled is True
        assert job.last_run is None
        assert job.next_run is None
        assert len(job.layers) == 4

    def test_to_dict(self):
        """to_dict should serialize all fields."""
        job = _make_job()
        d = job.to_dict()
        assert d["job_id"] == "sched-test-001"
        assert d["name"] == "Test scan"
        assert d["target_path"] == "/tmp/test/SKILL.md"
        assert d["schedule"] == "0 */6 * * *"
        assert d["layers"] == "rule_engine"
        assert d["enabled"] is True

    def test_to_dict_with_none_last_run(self):
        """to_dict should handle None datetime fields."""
        job = _make_job(last_run=None)
        d = job.to_dict()
        assert d["last_run"] is None


class TestJobRun:
    """Tests for the JobRun dataclass."""

    def test_defaults(self):
        run = JobRun(run_id="run-001", job_id="sched-001")
        assert run.status == "pending"
        assert run.scan_id is None
        assert run.verdict is None

    def test_to_dict(self):
        now = datetime(2026, 2, 20, 12, 0, tzinfo=UTC)
        run = JobRun(
            run_id="run-001",
            job_id="sched-001",
            scan_id="scan-abc",
            status="completed",
            verdict="CLEAN",
            risk_score=0,
            started_at=now,
            completed_at=now,
        )
        d = run.to_dict()
        assert d["run_id"] == "run-001"
        assert d["status"] == "completed"
        assert d["verdict"] == "CLEAN"


# =========================================================================
# JobStore persistence tests
# =========================================================================


class TestJobStore:
    """Tests for JobStore database operations."""

    async def test_create_and_get_job(self, store: JobStore):
        """Creating a job then fetching it should return the same data."""
        job = _make_job()
        await store.create_job(job)

        fetched = await store.get_job("sched-test-001")
        assert fetched is not None
        assert fetched.job_id == "sched-test-001"
        assert fetched.name == "Test scan"
        assert fetched.target_path == "/tmp/test/SKILL.md"
        assert fetched.schedule == "0 */6 * * *"
        assert fetched.enabled is True

    async def test_get_nonexistent_job(self, store: JobStore):
        """Getting a non-existent job should return None."""
        result = await store.get_job("nonexistent")
        assert result is None

    async def test_list_jobs(self, store: JobStore):
        """list_jobs should return all created jobs."""
        await store.create_job(_make_job(job_id="sched-a", name="Job A"))
        await store.create_job(_make_job(job_id="sched-b", name="Job B"))

        jobs = await store.list_jobs()
        assert len(jobs) == 2
        ids = {j.job_id for j in jobs}
        assert ids == {"sched-a", "sched-b"}

    async def test_update_job(self, store: JobStore):
        """Updating a job should persist the changes."""
        job = _make_job()
        await store.create_job(job)

        job.name = "Updated name"
        job.enabled = False
        await store.update_job(job)

        fetched = await store.get_job("sched-test-001")
        assert fetched is not None
        assert fetched.name == "Updated name"
        assert fetched.enabled is False

    async def test_delete_job(self, store: JobStore):
        """Deleting a job should remove it from the database."""
        job = _make_job()
        await store.create_job(job)

        deleted = await store.delete_job("sched-test-001")
        assert deleted is True

        fetched = await store.get_job("sched-test-001")
        assert fetched is None

    async def test_delete_nonexistent_returns_false(self, store: JobStore):
        """Deleting a non-existent job should return False."""
        deleted = await store.delete_job("nonexistent")
        assert deleted is False

    async def test_list_enabled_due_jobs(self, store: JobStore):
        """list_enabled_due_jobs should return only enabled jobs with next_run <= now."""
        now = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)

        # Due (next_run is in the past)
        await store.create_job(
            _make_job(
                job_id="sched-due",
                next_run=datetime(2026, 3, 1, 6, 0, tzinfo=UTC),
                enabled=True,
            )
        )
        # Not yet due (next_run is in the future)
        await store.create_job(
            _make_job(
                job_id="sched-future",
                next_run=datetime(2026, 3, 2, 6, 0, tzinfo=UTC),
                enabled=True,
            )
        )
        # Due but disabled
        await store.create_job(
            _make_job(
                job_id="sched-disabled",
                next_run=datetime(2026, 3, 1, 6, 0, tzinfo=UTC),
                enabled=False,
            )
        )

        due_jobs = await store.list_enabled_due_jobs(now)
        assert len(due_jobs) == 1
        assert due_jobs[0].job_id == "sched-due"

    async def test_create_and_get_run(self, store: JobStore):
        """Creating a run and fetching runs for its job should work."""
        job = _make_job()
        await store.create_job(job)

        run = JobRun(
            run_id="run-001",
            job_id="sched-test-001",
            status="completed",
            verdict="CLEAN",
            risk_score=0,
            started_at=datetime(2026, 2, 20, 12, 0, tzinfo=UTC),
            completed_at=datetime(2026, 2, 20, 12, 1, tzinfo=UTC),
        )
        await store.create_run(run)

        runs = await store.get_runs_for_job("sched-test-001")
        assert len(runs) == 1
        assert runs[0].run_id == "run-001"
        assert runs[0].verdict == "CLEAN"

    async def test_update_run(self, store: JobStore):
        """Updating a run should persist changes."""
        job = _make_job()
        await store.create_job(job)

        run = JobRun(
            run_id="run-002",
            job_id="sched-test-001",
            status="running",
            started_at=datetime(2026, 2, 20, 12, 0, tzinfo=UTC),
        )
        await store.create_run(run)

        run.status = "completed"
        run.verdict = "SUSPICIOUS"
        run.risk_score = 45
        run.completed_at = datetime(2026, 2, 20, 12, 5, tzinfo=UTC)
        await store.update_run(run)

        runs = await store.get_runs_for_job("sched-test-001")
        assert runs[0].status == "completed"
        assert runs[0].verdict == "SUSPICIOUS"
        assert runs[0].risk_score == 45

    async def test_delete_job_cascades_runs(self, store: JobStore):
        """Deleting a job should cascade-delete its run history."""
        job = _make_job()
        await store.create_job(job)

        run = JobRun(
            run_id="run-003",
            job_id="sched-test-001",
            status="completed",
            started_at=datetime(2026, 2, 20, 12, 0, tzinfo=UTC),
        )
        await store.create_run(run)

        await store.delete_job("sched-test-001")
        runs = await store.get_runs_for_job("sched-test-001")
        assert len(runs) == 0


# =========================================================================
# SchedulerEngine tests
# =========================================================================


class TestSchedulerEngine:
    """Tests for the SchedulerEngine scheduling logic."""

    async def test_start_and_stop(self, store: JobStore):
        """Engine should start and stop cleanly."""
        engine = SchedulerEngine(store, check_interval=0.1)
        await engine.start()
        assert engine.running is True

        await engine.stop()
        assert engine.running is False

    async def test_start_is_idempotent(self, store: JobStore):
        """Starting an already-running engine should be a no-op."""
        engine = SchedulerEngine(store, check_interval=0.1)
        await engine.start()
        await engine.start()  # second start should not raise
        assert engine.running is True
        await engine.stop()

    async def test_stop_when_not_running(self, store: JobStore):
        """Stopping a non-running engine should not raise."""
        engine = SchedulerEngine(store, check_interval=0.1)
        await engine.stop()  # should not raise
        assert engine.running is False

    async def test_execute_job_creates_run_record(self, store: JobStore, monkeypatch):
        """execute_job should create a run record in the store."""
        job = _make_job()
        await store.create_job(job)

        engine = SchedulerEngine(store)

        # Mock _run_scan to avoid needing real scan pipeline
        from unittest.mock import AsyncMock

        from malwar.models.scan import ScanResult

        mock_result = ScanResult(
            scan_id="scan-mock-001",
            target="/tmp/test/SKILL.md",
        )
        monkeypatch.setattr(engine, "_run_scan", AsyncMock(return_value=mock_result))

        run = await engine.execute_job(job)

        assert run.status == "completed"
        assert run.scan_id == "scan-mock-001"

        # Verify run was persisted
        runs = await store.get_runs_for_job("sched-test-001")
        assert len(runs) == 1
        assert runs[0].run_id == run.run_id

    async def test_execute_job_updates_last_run_and_next_run(self, store: JobStore, monkeypatch):
        """After execution, the job's last_run and next_run should be updated."""
        job = _make_job()
        await store.create_job(job)

        engine = SchedulerEngine(store)

        from unittest.mock import AsyncMock

        from malwar.models.scan import ScanResult

        mock_result = ScanResult(
            scan_id="scan-mock-002",
            target="/tmp/test/SKILL.md",
        )
        monkeypatch.setattr(engine, "_run_scan", AsyncMock(return_value=mock_result))

        await engine.execute_job(job)

        # Refetch job from store to see updates
        updated = await store.get_job("sched-test-001")
        assert updated is not None
        assert updated.last_run is not None
        assert updated.next_run is not None
        # next_run should be in the future relative to last_run
        assert updated.next_run > updated.last_run

    async def test_execute_job_handles_scan_failure(self, store: JobStore, monkeypatch):
        """If the scan raises, the run should be recorded as failed."""
        job = _make_job()
        await store.create_job(job)

        engine = SchedulerEngine(store)

        from unittest.mock import AsyncMock

        monkeypatch.setattr(
            engine, "_run_scan", AsyncMock(side_effect=RuntimeError("scan exploded"))
        )

        run = await engine.execute_job(job)
        assert run.status == "failed"
        assert "scan exploded" in (run.error or "")

    async def test_tick_processes_due_jobs(self, store: JobStore, monkeypatch):
        """_tick should find and execute all due jobs."""
        # Create a due job
        now = datetime.now(UTC)
        job = _make_job(next_run=now - timedelta(minutes=5))
        await store.create_job(job)

        engine = SchedulerEngine(store)

        from unittest.mock import AsyncMock

        from malwar.models.scan import ScanResult

        mock_result = ScanResult(
            scan_id="scan-tick-001",
            target="/tmp/test/SKILL.md",
        )
        monkeypatch.setattr(engine, "_run_scan", AsyncMock(return_value=mock_result))

        await engine._tick()

        runs = await store.get_runs_for_job("sched-test-001")
        assert len(runs) == 1
        assert runs[0].status == "completed"

    async def test_tick_skips_future_jobs(self, store: JobStore, monkeypatch):
        """_tick should not execute jobs whose next_run is in the future."""
        future = datetime.now(UTC) + timedelta(hours=1)
        job = _make_job(next_run=future)
        await store.create_job(job)

        engine = SchedulerEngine(store)

        from unittest.mock import AsyncMock

        execute_mock = AsyncMock()
        monkeypatch.setattr(engine, "execute_job", execute_mock)

        await engine._tick()

        execute_mock.assert_not_called()


# =========================================================================
# Migration tests for scheduled_jobs / job_runs tables
# =========================================================================


class TestMigration005ScheduledScanning:
    """Migration 005 should create the scheduled_jobs and job_runs tables."""

    async def test_scheduled_jobs_table_exists(self, db: aiosqlite.Connection):
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scheduled_jobs'"
        )
        row = await cursor.fetchone()
        assert row is not None

    async def test_job_runs_table_exists(self, db: aiosqlite.Connection):
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='job_runs'"
        )
        row = await cursor.fetchone()
        assert row is not None

    async def test_scheduled_jobs_columns(self, db: aiosqlite.Connection):
        cursor = await db.execute("PRAGMA table_info(scheduled_jobs)")
        rows = await cursor.fetchall()
        col_names = {row[1] for row in rows}
        expected = {
            "id", "name", "target_path", "schedule", "layers",
            "enabled", "last_run", "next_run", "created_at",
        }
        assert expected == col_names

    async def test_job_runs_columns(self, db: aiosqlite.Connection):
        cursor = await db.execute("PRAGMA table_info(job_runs)")
        rows = await cursor.fetchall()
        col_names = {row[1] for row in rows}
        expected = {
            "id", "job_id", "scan_id", "status", "verdict",
            "risk_score", "error", "started_at", "completed_at",
        }
        assert expected == col_names

    async def test_indexes_created(self, db: aiosqlite.Connection):
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND (name LIKE 'idx_scheduled_jobs%' OR name LIKE 'idx_job_runs%')"
        )
        rows = await cursor.fetchall()
        index_names = {row[0] for row in rows}
        assert "idx_scheduled_jobs_enabled" in index_names
        assert "idx_scheduled_jobs_next_run" in index_names
        assert "idx_job_runs_job_id" in index_names
        assert "idx_job_runs_started_at" in index_names
