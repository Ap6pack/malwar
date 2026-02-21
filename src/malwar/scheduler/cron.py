# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Simple cron expression parser.

Supports standard 5-field cron expressions:
    minute hour day month weekday

Each field supports:
    *           — any value
    N           — specific value (e.g. 5)
    N,M         — list of values (e.g. 1,15)
    N-M         — range of values (e.g. 1-5)
    */N         — step values (e.g. */15)
"""

from __future__ import annotations

from datetime import datetime, timedelta


class CronParseError(Exception):
    """Raised when a cron expression is invalid."""


def _parse_field(field: str, min_val: int, max_val: int) -> set[int]:
    """Parse a single cron field into a set of matching integer values."""
    values: set[int] = set()

    for part in field.split(","):
        part = part.strip()

        if part == "*":
            values.update(range(min_val, max_val + 1))
        elif part.startswith("*/"):
            try:
                step = int(part[2:])
            except ValueError as exc:
                raise CronParseError(f"Invalid step value: {part}") from exc
            if step <= 0:
                raise CronParseError(f"Step must be positive: {part}")
            values.update(range(min_val, max_val + 1, step))
        elif "-" in part:
            try:
                lo, hi = part.split("-", 1)
                lo_val, hi_val = int(lo), int(hi)
            except ValueError as exc:
                raise CronParseError(f"Invalid range: {part}") from exc
            if lo_val < min_val or hi_val > max_val or lo_val > hi_val:
                raise CronParseError(
                    f"Range {part} out of bounds ({min_val}-{max_val})"
                )
            values.update(range(lo_val, hi_val + 1))
        else:
            try:
                val = int(part)
            except ValueError as exc:
                raise CronParseError(f"Invalid value: {part}") from exc
            if val < min_val or val > max_val:
                raise CronParseError(
                    f"Value {val} out of bounds ({min_val}-{max_val})"
                )
            values.add(val)

    return values


def parse_cron(expression: str) -> tuple[set[int], set[int], set[int], set[int], set[int]]:
    """Parse a 5-field cron expression into (minutes, hours, days, months, weekdays).

    Returns:
        Tuple of five sets of valid integer values for each field.

    Raises:
        CronParseError: If the expression is malformed.
    """
    parts = expression.strip().split()
    if len(parts) != 5:
        raise CronParseError(
            f"Cron expression must have exactly 5 fields, got {len(parts)}: {expression!r}"
        )

    minutes = _parse_field(parts[0], 0, 59)
    hours = _parse_field(parts[1], 0, 23)
    days = _parse_field(parts[2], 1, 31)
    months = _parse_field(parts[3], 1, 12)
    weekdays = _parse_field(parts[4], 0, 6)  # 0=Sunday ... 6=Saturday

    return minutes, hours, days, months, weekdays


def next_run_from_cron(expression: str, after: datetime) -> datetime:
    """Calculate the next datetime matching the given cron expression after *after*.

    Searches up to 366 days from *after*; raises CronParseError if no match
    is found (e.g. impossible date like Feb 31).
    """
    minutes, hours, days, months, weekdays = parse_cron(expression)

    # Start from the next minute boundary
    candidate = after.replace(second=0, microsecond=0) + timedelta(minutes=1)

    max_iterations = 366 * 24 * 60  # one year of minutes
    for _ in range(max_iterations):
        if (
            candidate.month in months
            and candidate.day in days
            and candidate.weekday() in _isoweekday_to_cron(weekdays)
            and candidate.hour in hours
            and candidate.minute in minutes
        ):
            return candidate
        candidate += timedelta(minutes=1)

    raise CronParseError(
        f"Could not find next run for cron expression: {expression!r}"
    )


def _isoweekday_to_cron(weekdays: set[int]) -> set[int]:
    """Convert cron weekday set (0=Sun) to Python weekday set (0=Mon).

    Cron: 0=Sun, 1=Mon, 2=Tue, 3=Wed, 4=Thu, 5=Fri, 6=Sat
    Python: 0=Mon, 1=Tue, 2=Wed, 3=Thu, 4=Fri, 5=Sat, 6=Sun
    """
    mapping = {0: 6, 1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5}
    return {mapping[d] for d in weekdays}
