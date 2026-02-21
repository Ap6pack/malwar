# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""SQLite implementation of the abstract :class:`DatabaseBackend`.

Wraps an :mod:`aiosqlite` connection and exposes the uniform query
interface used by repositories.
"""

from __future__ import annotations

from typing import Any

import aiosqlite

from malwar.storage.backend import DatabaseBackend


class SQLiteBackend(DatabaseBackend):
    """Async SQLite backend backed by an :class:`aiosqlite.Connection`."""

    def __init__(self, connection: aiosqlite.Connection) -> None:
        self._conn = connection

    # ------------------------------------------------------------------
    # Query execution
    # ------------------------------------------------------------------

    async def execute(self, query: str, params: tuple[Any, ...] | None = None) -> Any:
        if params:
            return await self._conn.execute(query, params)
        return await self._conn.execute(query)

    async def executemany(
        self,
        query: str,
        params_seq: list[tuple[Any, ...]],
    ) -> None:
        await self._conn.executemany(query, params_seq)

    async def fetch_one(
        self, query: str, params: tuple[Any, ...] | None = None
    ) -> dict[str, Any] | None:
        cursor = await self.execute(query, params)
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    async def fetch_all(
        self, query: str, params: tuple[Any, ...] | None = None
    ) -> list[dict[str, Any]]:
        cursor = await self.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Transaction / connection lifecycle
    # ------------------------------------------------------------------

    async def commit(self) -> None:
        await self._conn.commit()

    async def close(self) -> None:
        await self._conn.close()

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def backend_name(self) -> str:
        return "sqlite"

    # ------------------------------------------------------------------
    # Convenience: expose the raw connection for legacy code paths
    # ------------------------------------------------------------------

    @property
    def raw_connection(self) -> aiosqlite.Connection:
        """Return the underlying :class:`aiosqlite.Connection`."""
        return self._conn
