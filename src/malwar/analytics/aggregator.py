# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Analytics aggregator — computes dashboard analytics from scan history."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

logger = logging.getLogger("malwar.analytics.aggregator")


class TimeBucket(StrEnum):
    """Supported time bucket granularities."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """Minimal scan record used by the aggregator.

    Fields map to the columns stored in the ``scans`` and ``findings`` tables.
    """

    scan_id: str
    verdict: str
    risk_score: int
    started_at: datetime
    duration_ms: int | None = None
    layers_executed: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class FindingRecord:
    """Minimal finding record used by the aggregator."""

    finding_id: str
    scan_id: str
    rule_id: str
    category: str
    detector_layer: str
    severity: str


@dataclass(slots=True)
class OverviewStats:
    """High-level overview statistics."""

    total_scans: int = 0
    verdict_breakdown: dict[str, int] = field(default_factory=dict)
    avg_risk_score: float = 0.0
    total_findings: int = 0


class AnalyticsAggregator:
    """Computes analytics from lists of scan and finding records.

    This class is a pure in-memory aggregator. It takes pre-fetched data
    (lists of ``ScanRecord`` and ``FindingRecord``) and computes various
    analytics slices without touching the database directly.
    """

    def __init__(
        self,
        scans: list[ScanRecord] | None = None,
        findings: list[FindingRecord] | None = None,
    ) -> None:
        self.scans: list[ScanRecord] = scans or []
        self.findings: list[FindingRecord] = findings or []

    # ------------------------------------------------------------------
    # Overview
    # ------------------------------------------------------------------

    def overview(self) -> OverviewStats:
        """Compute high-level overview stats."""
        if not self.scans:
            return OverviewStats()

        verdict_breakdown: dict[str, int] = {}
        total_risk = 0
        for s in self.scans:
            verdict_breakdown[s.verdict] = verdict_breakdown.get(s.verdict, 0) + 1
            total_risk += s.risk_score

        return OverviewStats(
            total_scans=len(self.scans),
            verdict_breakdown=verdict_breakdown,
            avg_risk_score=round(total_risk / len(self.scans), 2),
            total_findings=len(self.findings),
        )

    # ------------------------------------------------------------------
    # Scan volume over time
    # ------------------------------------------------------------------

    def scan_volume(
        self,
        bucket: TimeBucket = TimeBucket.DAILY,
    ) -> list[dict[str, object]]:
        """Return scan counts bucketed by time period.

        Returns a list of ``{"bucket": <str>, "count": <int>}`` dicts
        sorted chronologically.
        """
        if not self.scans:
            return []

        buckets: dict[str, int] = {}
        for s in self.scans:
            key = _bucket_key(s.started_at, bucket)
            buckets[key] = buckets.get(key, 0) + 1

        return [
            {"bucket": k, "count": v}
            for k, v in sorted(buckets.items())
        ]

    # ------------------------------------------------------------------
    # Verdict distribution (pie chart data)
    # ------------------------------------------------------------------

    def verdict_distribution(self) -> list[dict[str, object]]:
        """Return verdict counts suitable for a pie chart."""
        if not self.scans:
            return []

        counts: dict[str, int] = {}
        for s in self.scans:
            counts[s.verdict] = counts.get(s.verdict, 0) + 1

        return [
            {"verdict": v, "count": c}
            for v, c in sorted(counts.items())
        ]

    # ------------------------------------------------------------------
    # Risk score distribution (histogram data)
    # ------------------------------------------------------------------

    def risk_score_distribution(self, bin_width: int = 10) -> list[dict[str, object]]:
        """Return risk score histogram data.

        Scores are grouped into bins of *bin_width* (default 10).
        Returns ``[{"range": "0-9", "count": N}, ...]``.
        """
        if not self.scans:
            return []

        bins: dict[str, int] = {}
        for s in self.scans:
            lo = (s.risk_score // bin_width) * bin_width
            hi = lo + bin_width - 1
            label = f"{lo}-{hi}"
            bins[label] = bins.get(label, 0) + 1

        return [
            {"range": k, "count": v}
            for k, v in sorted(bins.items(), key=lambda x: int(x[0].split("-")[0]))
        ]

    # ------------------------------------------------------------------
    # Top triggered rules
    # ------------------------------------------------------------------

    def top_rules(self, limit: int = 10) -> list[dict[str, object]]:
        """Return the top triggered rules by count.

        Returns ``[{"rule_id": <str>, "count": <int>}, ...]`` sorted
        descending by count.
        """
        if not self.findings:
            return []

        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1

        sorted_rules = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return [
            {"rule_id": rule_id, "count": count}
            for rule_id, count in sorted_rules[:limit]
        ]

    # ------------------------------------------------------------------
    # Threat category breakdown
    # ------------------------------------------------------------------

    def category_breakdown(self) -> list[dict[str, object]]:
        """Return findings count grouped by threat category."""
        if not self.findings:
            return []

        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1

        return [
            {"category": cat, "count": cnt}
            for cat, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True)
        ]

    # ------------------------------------------------------------------
    # Detection layer effectiveness
    # ------------------------------------------------------------------

    def layer_effectiveness(self) -> list[dict[str, object]]:
        """Return findings count grouped by detection layer."""
        if not self.findings:
            return []

        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.detector_layer] = counts.get(f.detector_layer, 0) + 1

        return [
            {"layer": layer, "findings_count": cnt}
            for layer, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True)
        ]

    # ------------------------------------------------------------------
    # Average scan latency over time
    # ------------------------------------------------------------------

    def avg_latency(
        self,
        bucket: TimeBucket = TimeBucket.DAILY,
    ) -> list[dict[str, object]]:
        """Return average scan latency (ms) bucketed by time period.

        Scans with ``duration_ms is None`` are excluded.
        """
        scans_with_duration = [s for s in self.scans if s.duration_ms is not None]
        if not scans_with_duration:
            return []

        totals: dict[str, int] = {}
        counts: dict[str, int] = {}

        for s in scans_with_duration:
            key = _bucket_key(s.started_at, bucket)
            totals[key] = totals.get(key, 0) + (s.duration_ms or 0)
            counts[key] = counts.get(key, 0) + 1

        return [
            {"bucket": k, "avg_latency_ms": round(totals[k] / counts[k], 2)}
            for k in sorted(totals)
        ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bucket_key(dt: datetime, bucket: TimeBucket) -> str:
    """Convert a datetime into a string bucket key."""
    if bucket == TimeBucket.HOURLY:
        return dt.strftime("%Y-%m-%dT%H:00")
    if bucket == TimeBucket.DAILY:
        return dt.strftime("%Y-%m-%d")
    if bucket == TimeBucket.WEEKLY:
        # ISO week: Monday-based
        iso_year, iso_week, _ = dt.isocalendar()
        return f"{iso_year}-W{iso_week:02d}"
    if bucket == TimeBucket.MONTHLY:
        return dt.strftime("%Y-%m")
    return dt.strftime("%Y-%m-%d")


def _now_utc() -> datetime:
    """Return the current UTC datetime (test-friendly helper)."""
    return datetime.now(UTC)
