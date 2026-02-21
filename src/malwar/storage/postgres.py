# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""PostgreSQL implementation of the abstract :class:`DatabaseBackend`.

Wraps an :mod:`asyncpg` connection pool and exposes the uniform query
interface used by repositories.  Install with ``pip install malwar[postgres]``.
"""

from __future__ import annotations

from typing import Any

from malwar.core.exceptions import StorageError
from malwar.storage.backend import DatabaseBackend
from malwar.storage.query_adapter import adapt_query

try:
    import asyncpg  # type: ignore[import-not-found]

    HAS_ASYNCPG = True
except ImportError:  # pragma: no cover
    HAS_ASYNCPG = False
    asyncpg = None  # type: ignore[assignment]


def _require_asyncpg() -> None:
    """Raise a helpful error when asyncpg is not installed."""
    if not HAS_ASYNCPG:
        msg = (
            "PostgreSQL backend requires the 'asyncpg' package. "
            "Install it with:  pip install malwar[postgres]"
        )
        raise StorageError(msg)


class PostgresDatabase(DatabaseBackend):
    """Async PostgreSQL backend backed by an :class:`asyncpg.Pool`.

    Parameters:
        pool: An already-created :class:`asyncpg.Pool`.
    """

    def __init__(self, pool: Any) -> None:
        _require_asyncpg()
        self._pool = pool

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    async def create(
        cls,
        dsn: str,
        *,
        min_size: int = 2,
        max_size: int = 10,
    ) -> PostgresDatabase:
        """Create a :class:`PostgresDatabase` by establishing a connection pool.

        Args:
            dsn: PostgreSQL connection URI (``postgresql://user:pass@host/db``).
            min_size: Minimum number of connections in the pool.
            max_size: Maximum number of connections in the pool.

        Returns:
            A ready-to-use :class:`PostgresDatabase` instance.

        Raises:
            StorageError: If *asyncpg* is not installed or the connection fails.
        """
        _require_asyncpg()
        try:
            pool = await asyncpg.create_pool(  # type: ignore[union-attr]
                dsn,
                min_size=min_size,
                max_size=max_size,
            )
            return cls(pool)
        except Exception as exc:
            msg = f"Failed to create PostgreSQL connection pool: {exc}"
            raise StorageError(msg) from exc

    # ------------------------------------------------------------------
    # Query execution
    # ------------------------------------------------------------------

    def _adapt(self, query: str) -> str:
        """Convert ``?`` placeholders to ``$N`` for asyncpg."""
        return adapt_query(query, "postgres")

    async def execute(self, query: str, params: tuple[Any, ...] | None = None) -> Any:
        adapted = self._adapt(query)
        async with self._pool.acquire() as conn:
            if params:
                return await conn.execute(adapted, *params)
            return await conn.execute(adapted)

    async def executemany(
        self,
        query: str,
        params_seq: list[tuple[Any, ...]],
    ) -> None:
        adapted = self._adapt(query)
        async with self._pool.acquire() as conn:
            await conn.executemany(adapted, params_seq)

    async def fetch_one(
        self, query: str, params: tuple[Any, ...] | None = None
    ) -> dict[str, Any] | None:
        adapted = self._adapt(query)
        async with self._pool.acquire() as conn:
            if params:
                row = await conn.fetchrow(adapted, *params)
            else:
                row = await conn.fetchrow(adapted)
        if row is None:
            return None
        return dict(row)

    async def fetch_all(
        self, query: str, params: tuple[Any, ...] | None = None
    ) -> list[dict[str, Any]]:
        adapted = self._adapt(query)
        async with self._pool.acquire() as conn:
            if params:
                rows = await conn.fetch(adapted, *params)
            else:
                rows = await conn.fetch(adapted)
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Transaction / connection lifecycle
    # ------------------------------------------------------------------

    async def commit(self) -> None:
        """No-op — asyncpg uses auto-commit by default."""

    async def close(self) -> None:
        """Gracefully close all connections in the pool."""
        await self._pool.close()

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def backend_name(self) -> str:
        return "postgres"

    @property
    def pool(self) -> Any:
        """Return the underlying :class:`asyncpg.Pool`."""
        return self._pool
