# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Database connection management with pluggable backend support.

Supports both SQLite (aiosqlite, default) and PostgreSQL (asyncpg).
The active backend is controlled by the ``MALWAR_DB_BACKEND`` env var.
"""

from __future__ import annotations

import os
from pathlib import Path

import aiosqlite

from malwar.core.exceptions import ConfigurationError, StorageError
from malwar.storage.backend import DatabaseBackend
from malwar.storage.migrations import run_migrations

_db: aiosqlite.Connection | None = None
_backend: DatabaseBackend | None = None


# ---------------------------------------------------------------------------
# Backend-aware initialisation
# ---------------------------------------------------------------------------


async def init_db(
    db_path: Path | str = "malwar.db",
    *,
    auto_migrate: bool = True,
) -> aiosqlite.Connection:
    """Initialize database connection, optionally run migrations, return connection.

    Enables WAL mode and foreign keys for performance and integrity.
    When *auto_migrate* is True (the default), schema migrations are
    applied automatically on every initialization.
    """
    global _db

    if _db is not None:
        return _db

    try:
        _db = await aiosqlite.connect(str(db_path))
        _db.row_factory = aiosqlite.Row

        # Enable WAL mode for concurrent read performance
        await _db.execute("PRAGMA journal_mode=WAL")
        # Enable foreign key constraint enforcement
        await _db.execute("PRAGMA foreign_keys=ON")

        if auto_migrate:
            await run_migrations(_db)

        return _db
    except Exception as exc:
        _db = None
        msg = f"Failed to initialize database at {db_path}: {exc}"
        raise StorageError(msg) from exc


async def init_backend(
    *,
    backend: str | None = None,
    db_path: Path | str = "malwar.db",
    postgres_url: str = "",
    postgres_pool_min: int = 2,
    postgres_pool_max: int = 10,
    auto_migrate: bool = True,
) -> DatabaseBackend:
    """Initialise and return the configured :class:`DatabaseBackend`.

    Args:
        backend: ``"sqlite"`` or ``"postgres"``.  Falls back to the
            ``MALWAR_DB_BACKEND`` env var (default ``"sqlite"``).
        db_path: Path for the SQLite database file.
        postgres_url: PostgreSQL DSN (``postgresql://…``).
        postgres_pool_min: Minimum pool size for PostgreSQL.
        postgres_pool_max: Maximum pool size for PostgreSQL.
        auto_migrate: Run schema migrations on startup.

    Returns:
        A ready-to-use :class:`DatabaseBackend`.
    """
    global _backend

    if _backend is not None:
        return _backend

    chosen = (backend or os.environ.get("MALWAR_DB_BACKEND", "sqlite")).lower()

    if chosen == "sqlite":
        conn = await init_db(db_path, auto_migrate=auto_migrate)
        from malwar.storage.sqlite_backend import SQLiteBackend

        _backend = SQLiteBackend(conn)
        return _backend

    if chosen == "postgres":
        url = postgres_url or os.environ.get("MALWAR_POSTGRES_URL", "")
        if not url:
            msg = (
                "PostgreSQL backend selected but no connection URL provided. "
                "Set MALWAR_POSTGRES_URL or pass postgres_url."
            )
            raise ConfigurationError(msg)

        from malwar.storage.postgres import PostgresDatabase

        pg = await PostgresDatabase.create(
            url, min_size=postgres_pool_min, max_size=postgres_pool_max
        )

        if auto_migrate:
            from malwar.storage.pg_migrations import run_pg_migrations

            await run_pg_migrations(pg)

        _backend = pg
        return _backend

    msg = f"Unknown database backend: {chosen!r}. Expected 'sqlite' or 'postgres'."
    raise ConfigurationError(msg)


async def get_db() -> aiosqlite.Connection:
    """Get the active database connection.

    Raises StorageError if the database has not been initialized.
    """
    if _db is None:
        raise StorageError("Database not initialized. Call init_db() first.")
    return _db


async def get_backend() -> DatabaseBackend:
    """Get the active :class:`DatabaseBackend`.

    Raises :class:`StorageError` if no backend has been initialised.
    """
    if _backend is None:
        raise StorageError("Database backend not initialized. Call init_backend() first.")
    return _backend


async def close_db() -> None:
    """Close the database connection."""
    global _db, _backend

    if _backend is not None:
        await _backend.close()
        _backend = None

    if _db is not None:
        await _db.close()
        _db = None
