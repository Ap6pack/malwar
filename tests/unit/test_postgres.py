# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for PostgreSQL backend support: interface, query adaptation, config, and mock backend."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from malwar.core.config import Settings
from malwar.core.exceptions import ConfigurationError, StorageError
from malwar.storage.backend import DatabaseBackend
from malwar.storage.query_adapter import adapt_named_to_positional, adapt_query
from malwar.storage.sqlite_backend import SQLiteBackend

# ---------------------------------------------------------------------------
# DatabaseBackend interface tests
# ---------------------------------------------------------------------------


class TestDatabaseBackendInterface:
    """Verify that the abstract interface is correctly defined."""

    def test_is_abstract(self) -> None:
        """DatabaseBackend cannot be instantiated directly."""
        with pytest.raises(TypeError):
            DatabaseBackend()  # type: ignore[abstract]

    def test_sqlite_backend_is_subclass(self) -> None:
        assert issubclass(SQLiteBackend, DatabaseBackend)

    def test_postgres_backend_is_subclass(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        assert issubclass(PostgresDatabase, DatabaseBackend)

    def test_abstract_methods_defined(self) -> None:
        """The ABC should declare all required methods."""
        required = {
            "execute",
            "executemany",
            "fetch_one",
            "fetch_all",
            "commit",
            "close",
            "backend_name",
        }
        # __abstractmethods__ contains method names (and property names)
        assert required.issubset(DatabaseBackend.__abstractmethods__)


# ---------------------------------------------------------------------------
# SQLiteBackend property test
# ---------------------------------------------------------------------------


class TestSQLiteBackend:
    """Tests for the SQLite backend wrapper."""

    def test_backend_name(self) -> None:
        mock_conn = MagicMock()
        backend = SQLiteBackend(mock_conn)
        assert backend.backend_name == "sqlite"

    def test_raw_connection(self) -> None:
        mock_conn = MagicMock()
        backend = SQLiteBackend(mock_conn)
        assert backend.raw_connection is mock_conn

    async def test_execute_with_params(self) -> None:
        mock_conn = AsyncMock()
        backend = SQLiteBackend(mock_conn)
        await backend.execute("SELECT * FROM scans WHERE id = ?", ("scan-1",))
        mock_conn.execute.assert_awaited_once_with(
            "SELECT * FROM scans WHERE id = ?", ("scan-1",)
        )

    async def test_execute_without_params(self) -> None:
        mock_conn = AsyncMock()
        backend = SQLiteBackend(mock_conn)
        await backend.execute("SELECT 1")
        mock_conn.execute.assert_awaited_once_with("SELECT 1")

    async def test_executemany(self) -> None:
        mock_conn = AsyncMock()
        backend = SQLiteBackend(mock_conn)
        await backend.executemany("INSERT INTO t (x) VALUES (?)", [("a",), ("b",)])
        mock_conn.executemany.assert_awaited_once_with(
            "INSERT INTO t (x) VALUES (?)", [("a",), ("b",)]
        )

    async def test_commit(self) -> None:
        mock_conn = AsyncMock()
        backend = SQLiteBackend(mock_conn)
        await backend.commit()
        mock_conn.commit.assert_awaited_once()

    async def test_close(self) -> None:
        mock_conn = AsyncMock()
        backend = SQLiteBackend(mock_conn)
        await backend.close()
        mock_conn.close.assert_awaited_once()

    async def test_fetch_one_returns_dict(self) -> None:
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        # Simulate aiosqlite.Row (supports dict())
        mock_row = MagicMock()
        mock_row.keys.return_value = ["id", "name"]
        mock_row.__iter__ = MagicMock(return_value=iter(["scan-1", "test"]))
        mock_cursor.fetchone.return_value = mock_row
        mock_conn.execute.return_value = mock_cursor
        backend = SQLiteBackend(mock_conn)

        result = await backend.fetch_one("SELECT * FROM scans WHERE id = ?", ("scan-1",))
        assert result is not None

    async def test_fetch_one_returns_none(self) -> None:
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.fetchone.return_value = None
        mock_conn.execute.return_value = mock_cursor
        backend = SQLiteBackend(mock_conn)

        result = await backend.fetch_one("SELECT * FROM scans WHERE id = ?", ("none",))
        assert result is None

    async def test_fetch_all_returns_list(self) -> None:
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.fetchall.return_value = []
        mock_conn.execute.return_value = mock_cursor
        backend = SQLiteBackend(mock_conn)

        result = await backend.fetch_all("SELECT * FROM scans")
        assert result == []


# ---------------------------------------------------------------------------
# Query parameter adaptation tests
# ---------------------------------------------------------------------------


class TestQueryAdapter:
    """Tests for ? -> $N placeholder conversion."""

    def test_sqlite_passthrough(self) -> None:
        """SQLite dialect returns the query unchanged."""
        query = "SELECT * FROM scans WHERE id = ? AND target = ?"
        assert adapt_query(query, "sqlite") == query

    def test_postgres_single_param(self) -> None:
        result = adapt_query("SELECT * FROM scans WHERE id = ?", "postgres")
        assert result == "SELECT * FROM scans WHERE id = $1"

    def test_postgres_multiple_params(self) -> None:
        result = adapt_query(
            "INSERT INTO t (a, b, c) VALUES (?, ?, ?)", "postgres"
        )
        assert result == "INSERT INTO t (a, b, c) VALUES ($1, $2, $3)"

    def test_postgres_params_in_where_and_set(self) -> None:
        query = "UPDATE scans SET status = ?, risk_score = ? WHERE id = ?"
        result = adapt_query(query, "postgres")
        assert result == "UPDATE scans SET status = $1, risk_score = $2 WHERE id = $3"

    def test_no_params(self) -> None:
        query = "SELECT COUNT(*) FROM scans"
        assert adapt_query(query, "postgres") == query

    def test_question_in_string_literal_untouched(self) -> None:
        """Question marks inside single-quoted strings must NOT be replaced."""
        query = "INSERT INTO t (msg) VALUES ('what is this?')"
        result = adapt_query(query, "postgres")
        assert result == "INSERT INTO t (msg) VALUES ('what is this?')"

    def test_mixed_string_and_param(self) -> None:
        query = "SELECT * FROM t WHERE msg = 'why?' AND id = ?"
        result = adapt_query(query, "postgres")
        assert result == "SELECT * FROM t WHERE msg = 'why?' AND id = $1"

    def test_escaped_quote_in_string(self) -> None:
        """Escaped single quotes ('') inside strings."""
        query = "INSERT INTO t (msg) VALUES ('it''s a ? test') WHERE id = ?"
        result = adapt_query(query, "postgres")
        # The ? inside the string is untouched, the second is $1
        assert result == "INSERT INTO t (msg) VALUES ('it''s a ? test') WHERE id = $1"

    def test_unknown_dialect_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown SQL dialect"):
            adapt_query("SELECT 1", "mysql")

    def test_many_params(self) -> None:
        """Test with 16 positional parameters (like a large INSERT)."""
        placeholders = ", ".join(["?"] * 16)
        query = "INSERT INTO findings VALUES (" + placeholders + ")"  # noqa: S608
        result = adapt_query(query, "postgres")
        expected = ", ".join([f"${i}" for i in range(1, 17)])
        assert result == "INSERT INTO findings VALUES (" + expected + ")"  # noqa: S608


class TestNamedToPositional:
    """Tests for :name -> positional conversion."""

    def test_sqlite_conversion(self) -> None:
        query = "SELECT * FROM t WHERE a = :foo AND b = :bar"
        params = {"foo": 1, "bar": "x"}
        new_q, new_p = adapt_named_to_positional(query, params, "sqlite")
        assert new_q == "SELECT * FROM t WHERE a = ? AND b = ?"
        assert new_p == (1, "x")

    def test_postgres_conversion(self) -> None:
        query = "SELECT * FROM t WHERE a = :foo AND b = :bar"
        params = {"foo": 1, "bar": "x"}
        new_q, new_p = adapt_named_to_positional(query, params, "postgres")
        assert new_q == "SELECT * FROM t WHERE a = $1 AND b = $2"
        assert new_p == (1, "x")


# ---------------------------------------------------------------------------
# Config validation tests
# ---------------------------------------------------------------------------


class TestConfigValidation:
    """Tests for database backend configuration."""

    def test_default_backend_is_sqlite(self) -> None:
        settings = Settings(
            _env_file=None,
            anthropic_api_key="test",
        )
        assert settings.db_backend == "sqlite"

    def test_postgres_backend_setting(self) -> None:
        settings = Settings(
            _env_file=None,
            db_backend="postgres",
            postgres_url="postgresql://user:pass@localhost:5432/malwar",
            anthropic_api_key="test",
        )
        assert settings.db_backend == "postgres"
        assert settings.postgres_url == "postgresql://user:pass@localhost:5432/malwar"

    def test_pool_size_defaults(self) -> None:
        settings = Settings(
            _env_file=None,
            anthropic_api_key="test",
        )
        assert settings.postgres_pool_min == 2
        assert settings.postgres_pool_max == 10

    def test_custom_pool_sizes(self) -> None:
        settings = Settings(
            _env_file=None,
            postgres_pool_min=5,
            postgres_pool_max=20,
            anthropic_api_key="test",
        )
        assert settings.postgres_pool_min == 5
        assert settings.postgres_pool_max == 20

    def test_env_prefix(self) -> None:
        """Config should read MALWAR_DB_BACKEND from environment."""
        with patch.dict(os.environ, {"MALWAR_DB_BACKEND": "postgres", "MALWAR_POSTGRES_URL": "postgresql://test"}):
            settings = Settings(_env_file=None)
            assert settings.db_backend == "postgres"
            assert settings.postgres_url == "postgresql://test"


# ---------------------------------------------------------------------------
# PostgresDatabase mock tests (no running PostgreSQL required)
# ---------------------------------------------------------------------------


class TestPostgresDatabase:
    """Mock-based tests for the PostgresDatabase class."""

    @pytest.fixture(autouse=True)
    def _enable_asyncpg(self) -> None:  # type: ignore[return]
        """Patch HAS_ASYNCPG to True so PostgresDatabase can be instantiated with mocks."""
        from malwar.storage import postgres as pg_mod

        original = pg_mod.HAS_ASYNCPG
        pg_mod.HAS_ASYNCPG = True
        yield
        pg_mod.HAS_ASYNCPG = original

    def test_backend_name(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = MagicMock()
        db = PostgresDatabase(mock_pool)
        assert db.backend_name == "postgres"

    def test_pool_property(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = MagicMock()
        db = PostgresDatabase(mock_pool)
        assert db.pool is mock_pool

    async def test_execute_adapts_query(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        db = PostgresDatabase(mock_pool)
        await db.execute("SELECT * FROM scans WHERE id = ?", ("scan-1",))
        mock_conn.execute.assert_awaited_once_with(
            "SELECT * FROM scans WHERE id = $1", "scan-1"
        )

    async def test_execute_without_params(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        db = PostgresDatabase(mock_pool)
        await db.execute("SELECT 1")
        mock_conn.execute.assert_awaited_once_with("SELECT 1")

    async def test_executemany(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        db = PostgresDatabase(mock_pool)
        await db.executemany(
            "INSERT INTO t (a) VALUES (?)", [("x",), ("y",)]
        )
        mock_conn.executemany.assert_awaited_once_with(
            "INSERT INTO t (a) VALUES ($1)", [("x",), ("y",)]
        )

    async def test_fetch_one(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_record = {"id": "scan-1", "target": "/tmp/test.md"}
        mock_conn.fetchrow.return_value = mock_record
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        db = PostgresDatabase(mock_pool)
        result = await db.fetch_one("SELECT * FROM scans WHERE id = ?", ("scan-1",))
        assert result == {"id": "scan-1", "target": "/tmp/test.md"}

    async def test_fetch_one_returns_none(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow.return_value = None
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        db = PostgresDatabase(mock_pool)
        result = await db.fetch_one("SELECT * FROM scans WHERE id = ?", ("none",))
        assert result is None

    async def test_fetch_all(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch.return_value = [
            {"id": "scan-1"},
            {"id": "scan-2"},
        ]
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        db = PostgresDatabase(mock_pool)
        result = await db.fetch_all("SELECT * FROM scans")
        assert len(result) == 2
        assert result[0]["id"] == "scan-1"

    async def test_commit_is_noop(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = MagicMock()
        db = PostgresDatabase(mock_pool)
        # Should not raise
        await db.commit()

    async def test_close_closes_pool(self) -> None:
        from malwar.storage.postgres import PostgresDatabase

        mock_pool = AsyncMock()
        db = PostgresDatabase(mock_pool)
        await db.close()
        mock_pool.close.assert_awaited_once()


# ---------------------------------------------------------------------------
# Graceful fallback: asyncpg not installed
# ---------------------------------------------------------------------------


class TestAsyncpgNotInstalled:
    """Verify clear error when asyncpg is missing."""

    def test_require_asyncpg_raises(self) -> None:
        """_require_asyncpg raises StorageError when HAS_ASYNCPG is False."""
        from malwar.storage import postgres as pg_mod

        original = pg_mod.HAS_ASYNCPG
        try:
            pg_mod.HAS_ASYNCPG = False
            with pytest.raises(StorageError, match="asyncpg"):
                pg_mod._require_asyncpg()
        finally:
            pg_mod.HAS_ASYNCPG = original

    def test_constructor_raises_without_asyncpg(self) -> None:
        from malwar.storage import postgres as pg_mod
        from malwar.storage.postgres import PostgresDatabase

        original = pg_mod.HAS_ASYNCPG
        try:
            pg_mod.HAS_ASYNCPG = False
            with pytest.raises(StorageError, match="pip install malwar\\[postgres\\]"):
                PostgresDatabase(MagicMock())
        finally:
            pg_mod.HAS_ASYNCPG = original


# ---------------------------------------------------------------------------
# init_backend tests
# ---------------------------------------------------------------------------


class TestInitBackend:
    """Tests for the backend factory function."""

    async def test_init_sqlite_backend(self) -> None:
        import malwar.storage.database as db_mod

        db_mod._db = None
        db_mod._backend = None

        backend = await db_mod.init_backend(
            backend="sqlite",
            db_path=":memory:",
            auto_migrate=True,
        )
        try:
            assert backend.backend_name == "sqlite"
        finally:
            await db_mod.close_db()

    async def test_init_backend_returns_cached(self) -> None:
        import malwar.storage.database as db_mod

        db_mod._db = None
        db_mod._backend = None

        backend1 = await db_mod.init_backend(
            backend="sqlite",
            db_path=":memory:",
            auto_migrate=True,
        )
        backend2 = await db_mod.init_backend(backend="sqlite")
        try:
            assert backend1 is backend2
        finally:
            await db_mod.close_db()

    async def test_unknown_backend_raises(self) -> None:
        import malwar.storage.database as db_mod

        db_mod._db = None
        db_mod._backend = None

        with pytest.raises(ConfigurationError, match="Unknown database backend"):
            await db_mod.init_backend(backend="mysql")

    async def test_postgres_without_url_raises(self) -> None:
        import malwar.storage.database as db_mod

        db_mod._db = None
        db_mod._backend = None

        with patch.dict(os.environ, {}, clear=False):
            # Ensure MALWAR_POSTGRES_URL is not set
            os.environ.pop("MALWAR_POSTGRES_URL", None)
            with pytest.raises(ConfigurationError, match="no connection URL"):
                await db_mod.init_backend(backend="postgres")

    async def test_get_backend_raises_when_not_initialized(self) -> None:
        import malwar.storage.database as db_mod

        db_mod._backend = None
        with pytest.raises(StorageError, match="not initialized"):
            await db_mod.get_backend()

    async def test_close_db_resets_backend(self) -> None:
        import malwar.storage.database as db_mod

        db_mod._db = None
        db_mod._backend = None

        await db_mod.init_backend(
            backend="sqlite", db_path=":memory:", auto_migrate=True
        )
        assert db_mod._backend is not None
        await db_mod.close_db()
        assert db_mod._backend is None
        assert db_mod._db is None


# ---------------------------------------------------------------------------
# PostgreSQL migrations (structure tests, no live DB)
# ---------------------------------------------------------------------------


class TestPgMigrations:
    """Test migration structure and helpers without a live PostgreSQL."""

    def test_migrations_registered(self) -> None:
        from malwar.storage.pg_migrations import _PG_MIGRATIONS

        assert len(_PG_MIGRATIONS) >= 5
        versions = [m[0] for m in _PG_MIGRATIONS]
        assert versions == sorted(versions), "Migrations must be in order"

    def test_migration_names(self) -> None:
        from malwar.storage.pg_migrations import _PG_MIGRATIONS

        names = [m[1] for m in _PG_MIGRATIONS]
        assert "initial_schema" in names
        assert "api_usage_table" in names
        assert "audit_log_table" in names
        assert "api_keys_table" in names
        assert "scheduled_scanning_tables" in names

    def test_pg_schema_uses_postgres_types(self) -> None:
        """Spot-check that PG DDL uses PostgreSQL-specific types."""
        from malwar.storage.pg_migrations import (
            _PG_CREATE_API_USAGE,
            _PG_CREATE_CAMPAIGNS,
            _PG_CREATE_FINDINGS,
            _PG_CREATE_PUBLISHERS,
            _PG_CREATE_SCANS,
            _PG_CREATE_SIGNATURES,
        )

        # VARCHAR for bounded columns
        assert "VARCHAR" in _PG_CREATE_CAMPAIGNS
        assert "VARCHAR" in _PG_CREATE_SCANS

        # TIMESTAMP instead of TEXT for datetime
        assert "TIMESTAMP" in _PG_CREATE_CAMPAIGNS
        assert "TIMESTAMP" in _PG_CREATE_FINDINGS

        # BIGINT for large integers
        assert "BIGINT" in _PG_CREATE_CAMPAIGNS
        assert "BIGINT" in _PG_CREATE_SCANS

        # BOOLEAN for flags
        assert "BOOLEAN" in _PG_CREATE_SIGNATURES
        assert "BOOLEAN" in _PG_CREATE_PUBLISHERS

        # BIGSERIAL for auto-increment
        assert "BIGSERIAL" in _PG_CREATE_API_USAGE

        # DOUBLE PRECISION for floats
        assert "DOUBLE PRECISION" in _PG_CREATE_FINDINGS

    def test_seed_data_uses_on_conflict(self) -> None:
        """PG seed SQL should use ON CONFLICT DO NOTHING instead of INSERT OR IGNORE."""
        from malwar.storage.pg_migrations import (
            _PG_SEED_CAMPAIGNS,
            _PG_SEED_PUBLISHER_SQL,
            _PG_SEED_SIGNATURE_SQL,
        )

        for sql in _PG_SEED_CAMPAIGNS:
            assert "ON CONFLICT" in sql
            assert "INSERT OR IGNORE" not in sql

        assert "ON CONFLICT" in _PG_SEED_SIGNATURE_SQL
        assert "ON CONFLICT" in _PG_SEED_PUBLISHER_SQL

    def test_seed_signatures_count(self) -> None:
        from malwar.storage.pg_migrations import _PG_SEED_SIGNATURES

        assert len(_PG_SEED_SIGNATURES) == 12

    def test_seed_publishers_count(self) -> None:
        from malwar.storage.pg_migrations import _PG_SEED_PUBLISHERS

        assert len(_PG_SEED_PUBLISHERS) == 9
