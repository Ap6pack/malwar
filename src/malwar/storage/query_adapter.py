# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Query parameter adapter for cross-database compatibility.

SQLite uses ``?`` placeholders while PostgreSQL uses ``$1, $2, …``
positional parameters.  The :func:`adapt_query` function rewrites a
query written with ``?`` markers into the target dialect.
"""

from __future__ import annotations

import re


def adapt_query(query: str, dialect: str) -> str:
    """Rewrite ``?`` parameter placeholders for the target *dialect*.

    Args:
        query: SQL query with ``?`` positional placeholders.
        dialect: ``"sqlite"`` (no-op) or ``"postgres"`` (``$N``).

    Returns:
        The rewritten query string.

    Raises:
        ValueError: If *dialect* is not recognised.
    """
    if dialect == "sqlite":
        return query

    if dialect == "postgres":
        return _question_to_dollar(query)

    msg = f"Unknown SQL dialect: {dialect!r}. Expected 'sqlite' or 'postgres'."
    raise ValueError(msg)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Pattern that matches a literal ``?`` that is *not* inside a single-quoted
# string.  We use a simple state-machine approach instead of regex look-arounds
# because SQL strings can contain escaped quotes.


def _question_to_dollar(query: str) -> str:
    """Replace each ``?`` outside of single-quoted strings with ``$N``.

    This handles:
    * Simple queries:  ``WHERE id = ?``  -> ``WHERE id = $1``
    * Multiple params: ``VALUES (?, ?)`` -> ``VALUES ($1, $2)``
    * Quoted strings containing ``?`` are left untouched.
    """
    result: list[str] = []
    counter = 0
    in_string = False

    i = 0
    while i < len(query):
        ch = query[i]

        if ch == "'" and not in_string:
            # Entering a string literal
            in_string = True
            result.append(ch)
        elif ch == "'" and in_string:
            # Check for escaped quote ('')
            if i + 1 < len(query) and query[i + 1] == "'":
                result.append("''")
                i += 2
                continue
            in_string = False
            result.append(ch)
        elif ch == "?" and not in_string:
            counter += 1
            result.append(f"${counter}")
        else:
            result.append(ch)

        i += 1

    return "".join(result)


def adapt_named_to_positional(query: str, params: dict[str, object], dialect: str) -> tuple[str, tuple[object, ...]]:
    """Convert a ``:name`` style query + dict params to positional ``?``/``$N``.

    Returns:
        A tuple of (rewritten_query, positional_params_tuple).
    """
    positional: list[object] = []
    counter = 0

    def _replacer(match: re.Match[str]) -> str:
        nonlocal counter
        name = match.group(1)
        positional.append(params[name])
        counter += 1
        if dialect == "postgres":
            return f"${counter}"
        return "?"

    rewritten = re.sub(r":(\w+)", _replacer, query)
    return rewritten, tuple(positional)
