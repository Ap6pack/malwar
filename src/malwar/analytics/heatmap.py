# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Heatmap data generation — day-of-week x hour-of-day, severity heatmap."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from malwar.analytics.aggregator import FindingRecord, ScanRecord

logger = logging.getLogger("malwar.analytics.heatmap")

# Day-of-week labels (Monday = 0)
_WEEKDAY_NAMES = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
]

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True, slots=True)
class HeatmapCell:
    """A single cell in the activity heatmap grid."""

    day: str  # e.g. "Monday"
    hour: int  # 0-23
    count: int


@dataclass(frozen=True, slots=True)
class SeverityHeatmapCell:
    """A single cell in the severity heatmap grid."""

    day: str
    severity: str
    count: int


class HeatmapGenerator:
    """Generates heatmap data from scan and finding records.

    Produces two types of heatmaps:

    1. **Activity heatmap** — 7 days x 24 hours grid of scan counts.
    2. **Severity heatmap** — 7 days x severity-level grid of finding counts.
    """

    def __init__(
        self,
        scans: list[ScanRecord] | None = None,
        findings: list[FindingRecord] | None = None,
    ) -> None:
        self.scans: list[ScanRecord] = scans or []
        self.findings: list[FindingRecord] = findings or []
        # Pre-build scan_id -> started_at lookup for severity heatmap
        self._scan_times = {s.scan_id: s.started_at for s in self.scans}

    # ------------------------------------------------------------------
    # Activity heatmap (day x hour)
    # ------------------------------------------------------------------

    def activity_heatmap(self) -> list[HeatmapCell]:
        """Return scan activity counts as a day-of-week x hour-of-day grid.

        Always returns all 168 cells (7 x 24), even if count is 0.
        """
        grid: dict[tuple[int, int], int] = {}
        for day in range(7):
            for hour in range(24):
                grid[(day, hour)] = 0

        for s in self.scans:
            weekday = s.started_at.weekday()  # Monday=0
            hour = s.started_at.hour
            grid[(weekday, hour)] += 1

        return [
            HeatmapCell(day=_WEEKDAY_NAMES[day], hour=hour, count=grid[(day, hour)])
            for day in range(7)
            for hour in range(24)
        ]

    def activity_heatmap_sparse(self) -> list[HeatmapCell]:
        """Return scan activity counts, only including non-zero cells.

        Useful when the full 168-cell grid is not needed.
        """
        grid: dict[tuple[int, int], int] = {}
        for s in self.scans:
            key = (s.started_at.weekday(), s.started_at.hour)
            grid[key] = grid.get(key, 0) + 1

        return [
            HeatmapCell(day=_WEEKDAY_NAMES[day], hour=hour, count=count)
            for (day, hour), count in sorted(grid.items())
        ]

    # ------------------------------------------------------------------
    # Severity heatmap (day x severity)
    # ------------------------------------------------------------------

    def severity_heatmap(self) -> list[SeverityHeatmapCell]:
        """Return finding severity counts grouped by day-of-week.

        Findings are associated with their parent scan's ``started_at``
        timestamp to determine the day-of-week.  Always returns all
        35 cells (7 days x 5 severities).
        """
        grid: dict[tuple[int, str], int] = {}
        for day in range(7):
            for sev in _SEVERITY_ORDER:
                grid[(day, sev)] = 0

        for f in self.findings:
            scan_time = self._scan_times.get(f.scan_id)
            if scan_time is None:
                continue
            weekday = scan_time.weekday()
            sev = f.severity if f.severity in _SEVERITY_ORDER else "info"
            grid[(weekday, sev)] += 1

        return [
            SeverityHeatmapCell(
                day=_WEEKDAY_NAMES[day], severity=sev, count=grid[(day, sev)]
            )
            for day in range(7)
            for sev in _SEVERITY_ORDER
        ]

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def activity_heatmap_as_dicts(self) -> list[dict[str, object]]:
        """Activity heatmap as plain dicts (for JSON serialization)."""
        return [
            {"day": c.day, "hour": c.hour, "count": c.count}
            for c in self.activity_heatmap()
        ]

    def severity_heatmap_as_dicts(self) -> list[dict[str, object]]:
        """Severity heatmap as plain dicts (for JSON serialization)."""
        return [
            {"day": c.day, "severity": c.severity, "count": c.count}
            for c in self.severity_heatmap()
        ]
