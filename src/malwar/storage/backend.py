# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Abstract database backend interface for pluggable storage engines.

Both the SQLite (aiosqlite) and PostgreSQL (asyncpg) backends implement
this interface so that repositories and application code can remain
backend-agnostic.
"""

from __future__ import annotations

import abc
from typing import Any


class DatabaseBackend(abc.ABC):
    """Abstract base class for async database backends.

    Concrete implementations wrap a connection (SQLite) or connection pool
    (PostgreSQL) and expose a uniform query interface.
    """

    # ------------------------------------------------------------------
    # Query execution
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def execute(self, query: str, params: tuple[Any, ...] | None = None) -> Any:
        """Execute a single SQL statement.

        Args:
            query: SQL query string with ``?`` placeholders.
            params: Optional tuple of bind parameters.

        Returns:
            A backend-specific cursor/result object.
        """

    @abc.abstractmethod
    async def executemany(
        self,
        query: str,
        params_seq: list[tuple[Any, ...]],
    ) -> None:
        """Execute a SQL statement for each parameter set in *params_seq*.

        Args:
            query: SQL query string with ``?`` placeholders.
            params_seq: Sequence of parameter tuples.
        """

    @abc.abstractmethod
    async def fetch_one(
        self, query: str, params: tuple[Any, ...] | None = None
    ) -> dict[str, Any] | None:
        """Execute a query and return the first row as a dict, or ``None``."""

    @abc.abstractmethod
    async def fetch_all(
        self, query: str, params: tuple[Any, ...] | None = None
    ) -> list[dict[str, Any]]:
        """Execute a query and return all rows as a list of dicts."""

    # ------------------------------------------------------------------
    # Transaction / connection lifecycle
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def commit(self) -> None:
        """Commit the current transaction (no-op for auto-commit pools)."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Release the underlying connection or pool."""

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    @abc.abstractmethod
    def backend_name(self) -> str:
        """Return ``'sqlite'`` or ``'postgres'``."""
