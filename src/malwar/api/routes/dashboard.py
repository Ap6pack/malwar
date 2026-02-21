# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Dashboard analytics API endpoints — overview, trends, heatmaps, rules, layers."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from malwar.analytics.aggregator import FindingRecord, ScanRecord
from malwar.api.auth import require_api_key

logger = logging.getLogger("malwar.api.dashboard")

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class OverviewResponse(BaseModel):
    total_scans: int
    verdict_breakdown: dict[str, int]
    avg_risk_score: float
    total_findings: int


class TimeBucketEntry(BaseModel):
    bucket: str
    value: float
    moving_avg: float


class TrendsResponse(BaseModel):
    series: list[TimeBucketEntry]
    period_comparison: dict[str, object]
    anomalies: list[dict[str, object]]


class HeatmapCell(BaseModel):
    day: str
    hour: int
    count: int


class SeverityHeatmapCell(BaseModel):
    day: str
    severity: str
    count: int


class HeatmapResponse(BaseModel):
    activity: list[HeatmapCell]
    severity: list[SeverityHeatmapCell]


class RuleEntry(BaseModel):
    rule_id: str
    count: int


class RulesResponse(BaseModel):
    top_rules: list[RuleEntry]


class LayerEntry(BaseModel):
    layer: str
    findings_count: int


class LayersResponse(BaseModel):
    layers: list[LayerEntry]


# ---------------------------------------------------------------------------
# Helpers — fetch data from the database
# ---------------------------------------------------------------------------


async def _table_exists(db: object, table_name: str) -> bool:
    """Check whether *table_name* exists in the database."""
    cursor = await db.execute(  # type: ignore[attr-defined]
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    return await cursor.fetchone() is not None


async def _fetch_scan_records(
    db: object,
    days: int | None = None,
) -> tuple[list[ScanRecord], list[FindingRecord]]:
    """Fetch scan and finding records from the database.

    Returns ``(scan_rows, finding_rows)`` where each row is an
    ``aiosqlite.Row``.
    """
    from malwar.analytics.aggregator import FindingRecord, ScanRecord

    if not await _table_exists(db, "scans"):  # type: ignore[arg-type]
        return [], []

    # Build date filter
    where = ""
    params: list[str] = []
    if days is not None:
        cutoff = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")
        # Compute cutoff manually
        from datetime import timedelta

        cutoff_dt = datetime.now(UTC) - timedelta(days=days)
        cutoff = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%S")
        where = " WHERE started_at >= ?"
        params = [cutoff]

    cursor = await db.execute(  # type: ignore[attr-defined]
        f"SELECT id, verdict, risk_score, started_at, duration_ms, layers_executed FROM scans{where} ORDER BY started_at",  # noqa: S608
        params,
    )
    scan_rows = await cursor.fetchall()

    scans: list[ScanRecord] = []
    scan_ids: list[str] = []
    for row in scan_rows:
        started_at_str = row[3] or ""
        try:
            started_at = datetime.fromisoformat(started_at_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            started_at = datetime.now(UTC)

        # Ensure timezone-aware
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=UTC)

        layers_raw = row[5] or "[]"
        try:
            layers = json.loads(layers_raw) if isinstance(layers_raw, str) else []
        except (json.JSONDecodeError, TypeError):
            layers = []

        scans.append(
            ScanRecord(
                scan_id=row[0],
                verdict=row[1] or "CLEAN",
                risk_score=row[2] or 0,
                started_at=started_at,
                duration_ms=row[4],
                layers_executed=layers,
            )
        )
        scan_ids.append(row[0])

    # Fetch findings
    findings: list[FindingRecord] = []
    if scan_ids and await _table_exists(db, "findings"):  # type: ignore[arg-type]
        # Build IN clause
        placeholders = ",".join("?" for _ in scan_ids)
        cursor = await db.execute(  # type: ignore[attr-defined]
            f"SELECT id, scan_id, rule_id, category, detector_layer, severity FROM findings WHERE scan_id IN ({placeholders})",  # noqa: S608
            scan_ids,
        )
        finding_rows = await cursor.fetchall()
        for row in finding_rows:
            findings.append(
                FindingRecord(
                    finding_id=row[0],
                    scan_id=row[1],
                    rule_id=row[2],
                    category=row[3],
                    detector_layer=row[4],
                    severity=row[5],
                )
            )

    return scans, findings


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/analytics/overview", response_model=OverviewResponse)
async def analytics_overview(
    days: int | None = Query(default=None, description="Limit to last N days"),
    _auth_key: str = Depends(require_api_key),
) -> OverviewResponse:
    """Return high-level dashboard stats: total scans, verdict breakdown, avg risk."""
    from malwar.analytics.aggregator import AnalyticsAggregator
    from malwar.storage.database import get_db

    db = await get_db()
    scans, findings = await _fetch_scan_records(db, days=days)

    agg = AnalyticsAggregator(scans=scans, findings=findings)
    overview = agg.overview()

    return OverviewResponse(
        total_scans=overview.total_scans,
        verdict_breakdown=overview.verdict_breakdown,
        avg_risk_score=overview.avg_risk_score,
        total_findings=overview.total_findings,
    )


@router.get("/analytics/trends", response_model=TrendsResponse)
async def analytics_trends(
    period: str = Query(default="daily", description="Bucket period: hourly/daily/weekly/monthly"),
    days: int | None = Query(default=None, description="Limit to last N days"),
    window: int = Query(default=7, description="Moving average window size"),
    _auth_key: str = Depends(require_api_key),
) -> TrendsResponse:
    """Return time-series trend data with moving averages and anomaly detection."""
    from malwar.analytics.aggregator import TimeBucket
    from malwar.analytics.trends import TrendAnalyzer
    from malwar.storage.database import get_db

    db = await get_db()
    scans, _findings = await _fetch_scan_records(db, days=days)

    bucket = TimeBucket(period) if period in TimeBucket.__members__.values() else TimeBucket.DAILY

    trend = TrendAnalyzer(scans=scans)
    ma_data = trend.moving_average(bucket=bucket, window=window)
    comparison = trend.period_comparison()
    anomalies = trend.detect_anomalies(bucket=bucket)

    series = [
        TimeBucketEntry(
            bucket=str(entry["bucket"]),
            value=float(entry["value"]),  # type: ignore[arg-type]
            moving_avg=float(entry["moving_avg"]),  # type: ignore[arg-type]
        )
        for entry in ma_data
    ]

    return TrendsResponse(
        series=series,
        period_comparison={
            "current_count": comparison.current_count,
            "previous_count": comparison.previous_count,
            "change_absolute": comparison.change_absolute,
            "change_percent": comparison.change_percent,
        },
        anomalies=[
            {
                "alert_type": a.alert_type,
                "bucket": a.bucket,
                "value": a.value,
                "threshold": a.threshold,
                "message": a.message,
            }
            for a in anomalies
        ],
    )


@router.get("/analytics/heatmap", response_model=HeatmapResponse)
async def analytics_heatmap(
    days: int | None = Query(default=None, description="Limit to last N days"),
    _auth_key: str = Depends(require_api_key),
) -> HeatmapResponse:
    """Return activity and severity heatmap data."""
    from malwar.analytics.heatmap import HeatmapGenerator
    from malwar.storage.database import get_db

    db = await get_db()
    scans, findings = await _fetch_scan_records(db, days=days)

    hm = HeatmapGenerator(scans=scans, findings=findings)

    activity = [
        HeatmapCell(day=c.day, hour=c.hour, count=c.count)
        for c in hm.activity_heatmap()
    ]
    severity = [
        SeverityHeatmapCell(day=c.day, severity=c.severity, count=c.count)
        for c in hm.severity_heatmap()
    ]

    return HeatmapResponse(activity=activity, severity=severity)


@router.get("/analytics/rules", response_model=RulesResponse)
async def analytics_rules(
    limit: int = Query(default=10, description="Number of top rules to return"),
    days: int | None = Query(default=None, description="Limit to last N days"),
    _auth_key: str = Depends(require_api_key),
) -> RulesResponse:
    """Return top triggered rules with counts."""
    from malwar.analytics.aggregator import AnalyticsAggregator
    from malwar.storage.database import get_db

    db = await get_db()
    scans, findings = await _fetch_scan_records(db, days=days)

    agg = AnalyticsAggregator(scans=scans, findings=findings)
    top = agg.top_rules(limit=limit)

    return RulesResponse(
        top_rules=[RuleEntry(rule_id=str(r["rule_id"]), count=int(r["count"])) for r in top]  # type: ignore[call-overload]
    )


@router.get("/analytics/layers", response_model=LayersResponse)
async def analytics_layers(
    days: int | None = Query(default=None, description="Limit to last N days"),
    _auth_key: str = Depends(require_api_key),
) -> LayersResponse:
    """Return detection layer effectiveness stats."""
    from malwar.analytics.aggregator import AnalyticsAggregator
    from malwar.storage.database import get_db

    db = await get_db()
    scans, findings = await _fetch_scan_records(db, days=days)

    agg = AnalyticsAggregator(scans=scans, findings=findings)
    layers = agg.layer_effectiveness()

    return LayersResponse(
        layers=[
            LayerEntry(layer=str(le["layer"]), findings_count=int(le["findings_count"]))  # type: ignore[call-overload]
            for le in layers
        ]
    )
