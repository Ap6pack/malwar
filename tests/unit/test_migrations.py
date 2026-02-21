# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for the versioned database migration system."""

from __future__ import annotations

import aiosqlite
import pytest

from malwar.storage.database import close_db, init_db
from malwar.storage.migrations import (
    get_current_version,
    get_pending_migrations,
    run_migrations,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db():
    """Create an in-memory database with all migrations applied."""
    import malwar.storage.database as db_mod

    db_mod._db = None

    conn = await init_db(":memory:")
    yield conn
    await close_db()


@pytest.fixture
async def bare_db():
    """Create an in-memory database with NO migrations applied."""
    import malwar.storage.database as db_mod

    db_mod._db = None

    conn = await init_db(":memory:", auto_migrate=False)
    yield conn
    await close_db()


# ---------------------------------------------------------------------------
# Fresh database gets all migrations applied
# ---------------------------------------------------------------------------


class TestFreshDatabase:
    """A brand-new database should receive all migrations."""

    async def test_fresh_db_gets_all_migrations(self, db: aiosqlite.Connection):
        """After init_db, all migrations should be recorded in schema_migrations."""
        cursor = await db.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version"
        )
        rows = await cursor.fetchall()
        versions = [row[0] for row in rows]

        assert 1 in versions
        assert 2 in versions

    async def test_fresh_db_version_is_latest(self, db: aiosqlite.Connection):
        """Current version should be the highest registered migration."""
        version = await get_current_version(db)
        assert version == 5

    async def test_no_pending_after_full_migration(self, db: aiosqlite.Connection):
        """There should be no pending migrations after a full run."""
        pending = await get_pending_migrations(db)
        assert pending == []


# ---------------------------------------------------------------------------
# Already-migrated database skips applied migrations
# ---------------------------------------------------------------------------


class TestAlreadyMigrated:
    """A database that has already been migrated should skip applied migrations."""

    async def test_second_run_returns_no_applied(self, db: aiosqlite.Connection):
        """Running run_migrations again should return an empty list."""
        applied = await run_migrations(db)
        assert applied == []

    async def test_version_unchanged_after_second_run(self, db: aiosqlite.Connection):
        """The version should remain the same after a no-op migration run."""
        version_before = await get_current_version(db)
        await run_migrations(db)
        version_after = await get_current_version(db)
        assert version_before == version_after


# ---------------------------------------------------------------------------
# Version tracking works correctly
# ---------------------------------------------------------------------------


class TestVersionTracking:
    """The schema_migrations table accurately tracks applied versions."""

    async def test_bare_db_version_is_zero(self, bare_db: aiosqlite.Connection):
        """A database with no migrations should report version 0."""
        version = await get_current_version(bare_db)
        assert version == 0

    async def test_bare_db_has_all_pending(self, bare_db: aiosqlite.Connection):
        """A bare database should list all migrations as pending."""
        pending = await get_pending_migrations(bare_db)
        assert len(pending) == 5
        assert pending[0].version == 1
        assert pending[-1].version == 5

    async def test_partial_migration_tracking(self, bare_db: aiosqlite.Connection):
        """Manually recording version 1 should leave only version 2 as pending."""
        from malwar.storage.migrations import _ensure_migrations_table

        await _ensure_migrations_table(bare_db)

        # Simulate that migration 1 was already applied by inserting its record
        # and running its SQL manually.
        from malwar.storage.migrations import _MIGRATIONS

        mig_001 = _MIGRATIONS[0]
        await mig_001.func(bare_db)
        await bare_db.execute(
            "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
            (1, "initial_schema"),
        )
        await bare_db.commit()

        version = await get_current_version(bare_db)
        assert version == 1

        pending = await get_pending_migrations(bare_db)
        assert len(pending) == 4
        assert pending[0].version == 2

    async def test_migration_names_recorded(self, db: aiosqlite.Connection):
        """Migration names should be stored alongside their version numbers."""
        cursor = await db.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version"
        )
        rows = await cursor.fetchall()
        name_map = {row[0]: row[1] for row in rows}

        assert name_map[1] == "initial_schema"
        assert name_map[2] == "api_usage_table"

    async def test_applied_at_timestamp_set(self, db: aiosqlite.Connection):
        """Each migration record should have a non-null applied_at timestamp."""
        cursor = await db.execute(
            "SELECT applied_at FROM schema_migrations"
        )
        rows = await cursor.fetchall()
        for row in rows:
            assert row[0] is not None
            # Timestamp should look like a datetime string
            assert len(row[0]) >= 19  # e.g. "2026-02-20 12:00:00"


# ---------------------------------------------------------------------------
# Migration 002 creates api_usage table
# ---------------------------------------------------------------------------


class TestMigration002ApiUsage:
    """Migration 002 should create the api_usage table with expected schema."""

    async def test_api_usage_table_exists(self, db: aiosqlite.Connection):
        """The api_usage table should exist after migrations."""
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='api_usage'"
        )
        row = await cursor.fetchone()
        assert row is not None

    async def test_api_usage_columns(self, db: aiosqlite.Connection):
        """The api_usage table should have the expected columns."""
        cursor = await db.execute("PRAGMA table_info(api_usage)")
        rows = await cursor.fetchall()
        col_names = {row[1] for row in rows}

        expected = {"id", "api_key", "endpoint", "method", "status_code", "timestamp"}
        assert expected == col_names

    async def test_api_usage_indexes(self, db: aiosqlite.Connection):
        """Indexes on api_key and timestamp should exist."""
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_api_usage%'"
        )
        rows = await cursor.fetchall()
        index_names = {row[0] for row in rows}

        assert "idx_api_usage_key" in index_names
        assert "idx_api_usage_timestamp" in index_names

    async def test_api_usage_insert_and_query(self, db: aiosqlite.Connection):
        """Basic insert and select should work on api_usage."""
        await db.execute(
            "INSERT INTO api_usage (api_key, endpoint, method, status_code) "
            "VALUES (?, ?, ?, ?)",
            ("key-123", "/api/v1/scan", "POST", 200),
        )
        await db.commit()

        cursor = await db.execute("SELECT * FROM api_usage WHERE api_key = 'key-123'")
        row = await cursor.fetchone()
        assert row is not None
        data = dict(row)
        assert data["endpoint"] == "/api/v1/scan"
        assert data["method"] == "POST"
        assert data["status_code"] == 200
        assert data["timestamp"] is not None

    async def test_api_usage_autoincrement_id(self, db: aiosqlite.Connection):
        """The id column should auto-increment."""
        await db.execute(
            "INSERT INTO api_usage (endpoint, method) VALUES (?, ?)",
            ("/api/v1/health", "GET"),
        )
        await db.execute(
            "INSERT INTO api_usage (endpoint, method) VALUES (?, ?)",
            ("/api/v1/scan", "POST"),
        )
        await db.commit()

        cursor = await db.execute("SELECT id FROM api_usage ORDER BY id")
        rows = await cursor.fetchall()
        ids = [row[0] for row in rows]
        assert len(ids) == 2
        assert ids[1] > ids[0]


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    """Running migrations multiple times should be safe and produce identical results."""

    async def test_repeated_runs_are_idempotent(self, db: aiosqlite.Connection):
        """Running run_migrations three extra times should not raise or change state."""
        for _ in range(3):
            applied = await run_migrations(db)
            assert applied == []

        version = await get_current_version(db)
        assert version == 5

        # Ensure seed data was not duplicated
        cursor = await db.execute("SELECT COUNT(*) FROM campaigns")
        row = await cursor.fetchone()
        assert row[0] == 3  # ClawHavoc, SnykToxic, ShadowPkg

        cursor = await db.execute("SELECT COUNT(*) FROM signatures WHERE campaign_id = 'campaign-clawhavoc-001'")
        row = await cursor.fetchone()
        assert row[0] == 4

    async def test_idempotent_table_creation(self, db: aiosqlite.Connection):
        """Tables should not be duplicated or error on repeated creation."""
        cursor = await db.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='api_usage'"
        )
        row = await cursor.fetchone()
        assert row[0] == 1

        # Run migrations again
        await run_migrations(db)

        cursor = await db.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='api_usage'"
        )
        row = await cursor.fetchone()
        assert row[0] == 1
