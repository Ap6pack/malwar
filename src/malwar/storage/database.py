# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""SQLite connection management using aiosqlite."""

from __future__ import annotations

from pathlib import Path

import aiosqlite

from malwar.core.exceptions import StorageError
from malwar.storage.migrations import run_migrations

_db: aiosqlite.Connection | None = None


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


async def get_db() -> aiosqlite.Connection:
    """Get the active database connection.

    Raises StorageError if the database has not been initialized.
    """
    if _db is None:
        raise StorageError("Database not initialized. Call init_db() first.")
    return _db


async def close_db() -> None:
    """Close the database connection."""
    global _db

    if _db is not None:
        await _db.close()
        _db = None
