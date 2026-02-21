# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for dashboard analytics — aggregation, trends, heatmaps, and edge cases."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from malwar.analytics.aggregator import (
    AnalyticsAggregator,
    FindingRecord,
    OverviewStats,
    ScanRecord,
    TimeBucket,
)
from malwar.analytics.heatmap import HeatmapGenerator
from malwar.analytics.trends import AnomalyAlert, PeriodComparison, TrendAnalyzer

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 2, 20, 14, 30, 0, tzinfo=UTC)


def _make_scan(
    scan_id: str = "scan-001",
    verdict: str = "CLEAN",
    risk_score: int = 0,
    started_at: datetime | None = None,
    duration_ms: int | None = 150,
    layers: list[str] | None = None,
) -> ScanRecord:
    return ScanRecord(
        scan_id=scan_id,
        verdict=verdict,
        risk_score=risk_score,
        started_at=started_at or _NOW,
        duration_ms=duration_ms,
        layers_executed=layers or ["rule_engine"],
    )


def _make_finding(
    finding_id: str = "f-001",
    scan_id: str = "scan-001",
    rule_id: str = "RULE-001",
    category: str = "prompt_injection",
    detector_layer: str = "rule_engine",
    severity: str = "high",
) -> FindingRecord:
    return FindingRecord(
        finding_id=finding_id,
        scan_id=scan_id,
        rule_id=rule_id,
        category=category,
        detector_layer=detector_layer,
        severity=severity,
    )


@pytest.fixture
def sample_scans() -> list[ScanRecord]:
    """Build a diverse sample of scans over multiple days."""
    scans = []
    base = datetime(2026, 2, 10, 8, 0, 0, tzinfo=UTC)
    verdicts = ["CLEAN", "CLEAN", "CAUTION", "SUSPICIOUS", "MALICIOUS"]
    for i in range(10):
        scans.append(
            _make_scan(
                scan_id=f"scan-{i:03d}",
                verdict=verdicts[i % len(verdicts)],
                risk_score=(i * 10),
                started_at=base + timedelta(days=i, hours=i % 24),
                duration_ms=100 + i * 20,
            )
        )
    return scans


@pytest.fixture
def sample_findings() -> list[FindingRecord]:
    """Build sample findings linked to sample scans."""
    findings = []
    rules = ["RULE-001", "RULE-002", "RULE-001", "RULE-003", "RULE-001"]
    categories = [
        "prompt_injection",
        "data_exfiltration",
        "prompt_injection",
        "obfuscated_command",
        "prompt_injection",
    ]
    layers = [
        "rule_engine",
        "url_crawler",
        "rule_engine",
        "llm_analyzer",
        "rule_engine",
    ]
    severities = ["high", "critical", "high", "medium", "high"]
    for i in range(5):
        findings.append(
            _make_finding(
                finding_id=f"f-{i:03d}",
                scan_id=f"scan-{i:03d}",
                rule_id=rules[i],
                category=categories[i],
                detector_layer=layers[i],
                severity=severities[i],
            )
        )
    return findings


# =========================================================================
# AnalyticsAggregator — Overview
# =========================================================================


class TestOverview:
    def test_overview_with_data(
        self, sample_scans: list[ScanRecord], sample_findings: list[FindingRecord]
    ) -> None:
        agg = AnalyticsAggregator(scans=sample_scans, findings=sample_findings)
        overview = agg.overview()

        assert overview.total_scans == 10
        assert overview.total_findings == 5
        assert overview.avg_risk_score == 45.0  # sum(0,10,...,90)/10
        assert isinstance(overview.verdict_breakdown, dict)
        assert "CLEAN" in overview.verdict_breakdown

    def test_overview_empty(self) -> None:
        agg = AnalyticsAggregator()
        overview = agg.overview()

        assert overview.total_scans == 0
        assert overview.total_findings == 0
        assert overview.avg_risk_score == 0.0
        assert overview.verdict_breakdown == {}

    def test_overview_single_scan(self) -> None:
        scans = [_make_scan(risk_score=42, verdict="SUSPICIOUS")]
        agg = AnalyticsAggregator(scans=scans)
        overview = agg.overview()

        assert overview.total_scans == 1
        assert overview.avg_risk_score == 42.0
        assert overview.verdict_breakdown == {"SUSPICIOUS": 1}


# =========================================================================
# AnalyticsAggregator — Scan Volume
# =========================================================================


class TestScanVolume:
    def test_daily_buckets(self, sample_scans: list[ScanRecord]) -> None:
        agg = AnalyticsAggregator(scans=sample_scans)
        vol = agg.scan_volume(bucket=TimeBucket.DAILY)

        assert len(vol) > 0
        assert all("bucket" in v and "count" in v for v in vol)
        # Total count should match
        assert sum(v["count"] for v in vol) == 10

    def test_hourly_buckets(self, sample_scans: list[ScanRecord]) -> None:
        agg = AnalyticsAggregator(scans=sample_scans)
        vol = agg.scan_volume(bucket=TimeBucket.HOURLY)

        assert len(vol) > 0
        assert sum(v["count"] for v in vol) == 10

    def test_weekly_buckets(self, sample_scans: list[ScanRecord]) -> None:
        agg = AnalyticsAggregator(scans=sample_scans)
        vol = agg.scan_volume(bucket=TimeBucket.WEEKLY)

        assert len(vol) > 0
        assert sum(v["count"] for v in vol) == 10

    def test_monthly_buckets(self, sample_scans: list[ScanRecord]) -> None:
        agg = AnalyticsAggregator(scans=sample_scans)
        vol = agg.scan_volume(bucket=TimeBucket.MONTHLY)

        assert len(vol) > 0
        assert sum(v["count"] for v in vol) == 10

    def test_empty_scans(self) -> None:
        agg = AnalyticsAggregator()
        assert agg.scan_volume() == []


# =========================================================================
# AnalyticsAggregator — Verdict Distribution
# =========================================================================


class TestVerdictDistribution:
    def test_verdict_distribution(self, sample_scans: list[ScanRecord]) -> None:
        agg = AnalyticsAggregator(scans=sample_scans)
        dist = agg.verdict_distribution()

        assert len(dist) > 0
        verdicts = {d["verdict"] for d in dist}
        assert "CLEAN" in verdicts
        assert sum(d["count"] for d in dist) == 10

    def test_empty(self) -> None:
        agg = AnalyticsAggregator()
        assert agg.verdict_distribution() == []


# =========================================================================
# AnalyticsAggregator — Risk Score Distribution
# =========================================================================


class TestRiskScoreDistribution:
    def test_histogram(self, sample_scans: list[ScanRecord]) -> None:
        agg = AnalyticsAggregator(scans=sample_scans)
        hist = agg.risk_score_distribution(bin_width=10)

        assert len(hist) > 0
        assert all("range" in h and "count" in h for h in hist)
        assert sum(h["count"] for h in hist) == 10

    def test_custom_bin_width(self, sample_scans: list[ScanRecord]) -> None:
        agg = AnalyticsAggregator(scans=sample_scans)
        hist = agg.risk_score_distribution(bin_width=25)

        assert len(hist) > 0
        assert sum(h["count"] for h in hist) == 10

    def test_empty(self) -> None:
        agg = AnalyticsAggregator()
        assert agg.risk_score_distribution() == []


# =========================================================================
# AnalyticsAggregator — Top Rules
# =========================================================================


class TestTopRules:
    def test_top_rules(self, sample_findings: list[FindingRecord]) -> None:
        agg = AnalyticsAggregator(findings=sample_findings)
        rules = agg.top_rules(limit=5)

        assert len(rules) > 0
        # RULE-001 appears 3 times, should be first
        assert rules[0]["rule_id"] == "RULE-001"
        assert rules[0]["count"] == 3

    def test_limit(self, sample_findings: list[FindingRecord]) -> None:
        agg = AnalyticsAggregator(findings=sample_findings)
        rules = agg.top_rules(limit=1)
        assert len(rules) == 1

    def test_empty(self) -> None:
        agg = AnalyticsAggregator()
        assert agg.top_rules() == []


# =========================================================================
# AnalyticsAggregator — Category Breakdown
# =========================================================================


class TestCategoryBreakdown:
    def test_categories(self, sample_findings: list[FindingRecord]) -> None:
        agg = AnalyticsAggregator(findings=sample_findings)
        cats = agg.category_breakdown()

        assert len(cats) > 0
        cat_names = {c["category"] for c in cats}
        assert "prompt_injection" in cat_names
        # prompt_injection appears 3 times, should be first
        assert cats[0]["category"] == "prompt_injection"
        assert cats[0]["count"] == 3

    def test_empty(self) -> None:
        agg = AnalyticsAggregator()
        assert agg.category_breakdown() == []


# =========================================================================
# AnalyticsAggregator — Layer Effectiveness
# =========================================================================


class TestLayerEffectiveness:
    def test_layers(self, sample_findings: list[FindingRecord]) -> None:
        agg = AnalyticsAggregator(findings=sample_findings)
        layers = agg.layer_effectiveness()

        assert len(layers) > 0
        layer_names = {le["layer"] for le in layers}
        assert "rule_engine" in layer_names
        # rule_engine appears 3 times
        assert layers[0]["layer"] == "rule_engine"
        assert layers[0]["findings_count"] == 3

    def test_empty(self) -> None:
        agg = AnalyticsAggregator()
        assert agg.layer_effectiveness() == []


# =========================================================================
# AnalyticsAggregator — Average Latency
# =========================================================================


class TestAvgLatency:
    def test_avg_latency(self, sample_scans: list[ScanRecord]) -> None:
        agg = AnalyticsAggregator(scans=sample_scans)
        latency = agg.avg_latency(bucket=TimeBucket.DAILY)

        assert len(latency) > 0
        assert all("bucket" in entry and "avg_latency_ms" in entry for entry in latency)

    def test_empty(self) -> None:
        agg = AnalyticsAggregator()
        assert agg.avg_latency() == []

    def test_no_duration(self) -> None:
        scans = [_make_scan(duration_ms=None)]
        agg = AnalyticsAggregator(scans=scans)
        assert agg.avg_latency() == []


# =========================================================================
# TrendAnalyzer — Moving Average
# =========================================================================


class TestMovingAverage:
    def test_moving_average_volume(self, sample_scans: list[ScanRecord]) -> None:
        trend = TrendAnalyzer(scans=sample_scans)
        ma = trend.moving_average(bucket=TimeBucket.DAILY, window=3)

        assert len(ma) > 0
        assert all("bucket" in m and "value" in m and "moving_avg" in m for m in ma)

    def test_moving_average_risk(self, sample_scans: list[ScanRecord]) -> None:
        trend = TrendAnalyzer(scans=sample_scans)
        ma = trend.moving_average(bucket=TimeBucket.DAILY, window=3, metric="risk")

        assert len(ma) > 0
        # First entry moving_avg equals its own value (window of 1 effective)
        assert ma[0]["moving_avg"] == ma[0]["value"]

    def test_empty(self) -> None:
        trend = TrendAnalyzer()
        assert trend.moving_average() == []


# =========================================================================
# TrendAnalyzer — Period Comparison
# =========================================================================


class TestPeriodComparison:
    def test_comparison(self, sample_scans: list[ScanRecord]) -> None:
        ref = datetime(2026, 2, 20, 23, 59, 59, tzinfo=UTC)
        trend = TrendAnalyzer(scans=sample_scans)
        comp = trend.period_comparison(period_days=7, reference_time=ref)

        assert isinstance(comp, PeriodComparison)
        assert comp.current_count >= 0
        assert comp.previous_count >= 0
        assert comp.change_absolute == comp.current_count - comp.previous_count

    def test_comparison_empty(self) -> None:
        trend = TrendAnalyzer()
        comp = trend.period_comparison()

        assert comp.current_count == 0
        assert comp.previous_count == 0
        assert comp.change_percent == 0.0

    def test_comparison_all_current(self) -> None:
        """All scans in current period, none in previous."""
        now = datetime(2026, 2, 20, 12, 0, 0, tzinfo=UTC)
        scans = [
            _make_scan(scan_id="s1", started_at=now - timedelta(hours=1)),
            _make_scan(scan_id="s2", started_at=now - timedelta(hours=2)),
        ]
        trend = TrendAnalyzer(scans=scans)
        comp = trend.period_comparison(period_days=7, reference_time=now)

        assert comp.current_count == 2
        assert comp.previous_count == 0
        assert comp.change_percent == 100.0


# =========================================================================
# TrendAnalyzer — Anomaly Detection
# =========================================================================


class TestAnomalyDetection:
    def test_no_anomaly_uniform(self) -> None:
        """Uniform distribution should produce no anomalies."""
        base = datetime(2026, 2, 1, 12, 0, 0, tzinfo=UTC)
        scans = [
            _make_scan(scan_id=f"s-{i}", started_at=base + timedelta(days=i))
            for i in range(10)
        ]
        trend = TrendAnalyzer(scans=scans)
        alerts = trend.detect_anomalies(bucket=TimeBucket.DAILY)
        assert alerts == []

    def test_spike_detected(self) -> None:
        """A massive spike on one day should be flagged."""
        base = datetime(2026, 2, 1, 12, 0, 0, tzinfo=UTC)
        scans = []
        # 1 scan per day for days 0-9
        for i in range(10):
            scans.append(
                _make_scan(scan_id=f"normal-{i}", started_at=base + timedelta(days=i))
            )
        # Spike: 50 scans on day 10
        for j in range(50):
            scans.append(
                _make_scan(
                    scan_id=f"spike-{j}",
                    started_at=base + timedelta(days=10, minutes=j),
                )
            )

        trend = TrendAnalyzer(scans=scans)
        alerts = trend.detect_anomalies(bucket=TimeBucket.DAILY, z_threshold=2.0)

        assert len(alerts) > 0
        assert any(a.alert_type == "volume_spike" for a in alerts)

    def test_empty(self) -> None:
        trend = TrendAnalyzer()
        assert trend.detect_anomalies() == []

    def test_too_few_data_points(self) -> None:
        """Fewer than 3 data points should not trigger anomalies."""
        scans = [
            _make_scan(scan_id="s1", started_at=_NOW),
            _make_scan(scan_id="s2", started_at=_NOW + timedelta(days=1)),
        ]
        trend = TrendAnalyzer(scans=scans)
        alerts = trend.detect_anomalies(bucket=TimeBucket.DAILY)
        assert alerts == []


# =========================================================================
# HeatmapGenerator — Activity Heatmap
# =========================================================================


class TestActivityHeatmap:
    def test_full_grid(self, sample_scans: list[ScanRecord]) -> None:
        hm = HeatmapGenerator(scans=sample_scans)
        grid = hm.activity_heatmap()

        # 7 days x 24 hours = 168 cells
        assert len(grid) == 168

    def test_sparse(self, sample_scans: list[ScanRecord]) -> None:
        hm = HeatmapGenerator(scans=sample_scans)
        sparse = hm.activity_heatmap_sparse()

        # Only non-zero cells
        assert all(c.count > 0 for c in sparse)
        assert len(sparse) <= 168

    def test_empty(self) -> None:
        hm = HeatmapGenerator()
        grid = hm.activity_heatmap()

        assert len(grid) == 168
        assert all(c.count == 0 for c in grid)

    def test_single_scan(self) -> None:
        # Wednesday at 14:30 UTC
        scan = _make_scan(started_at=datetime(2026, 2, 18, 14, 30, 0, tzinfo=UTC))
        hm = HeatmapGenerator(scans=[scan])
        grid = hm.activity_heatmap()

        # Find Wednesday hour=14
        wed_14 = [c for c in grid if c.day == "Wednesday" and c.hour == 14]
        assert len(wed_14) == 1
        assert wed_14[0].count == 1

        # All other cells should be 0
        others = [c for c in grid if not (c.day == "Wednesday" and c.hour == 14)]
        assert all(c.count == 0 for c in others)

    def test_as_dicts(self, sample_scans: list[ScanRecord]) -> None:
        hm = HeatmapGenerator(scans=sample_scans)
        dicts = hm.activity_heatmap_as_dicts()

        assert len(dicts) == 168
        assert all(isinstance(d, dict) for d in dicts)
        assert all("day" in d and "hour" in d and "count" in d for d in dicts)


# =========================================================================
# HeatmapGenerator — Severity Heatmap
# =========================================================================


class TestSeverityHeatmap:
    def test_full_grid(
        self, sample_scans: list[ScanRecord], sample_findings: list[FindingRecord]
    ) -> None:
        hm = HeatmapGenerator(scans=sample_scans, findings=sample_findings)
        grid = hm.severity_heatmap()

        # 7 days x 5 severities = 35 cells
        assert len(grid) == 35

    def test_empty_scans_and_findings(self) -> None:
        hm = HeatmapGenerator()
        grid = hm.severity_heatmap()

        assert len(grid) == 35
        assert all(c.count == 0 for c in grid)

    def test_finding_without_matching_scan(self) -> None:
        """Findings whose scan_id doesn't match any scan should be skipped."""
        findings = [_make_finding(scan_id="nonexistent")]
        hm = HeatmapGenerator(scans=[], findings=findings)
        grid = hm.severity_heatmap()

        assert all(c.count == 0 for c in grid)

    def test_as_dicts(
        self, sample_scans: list[ScanRecord], sample_findings: list[FindingRecord]
    ) -> None:
        hm = HeatmapGenerator(scans=sample_scans, findings=sample_findings)
        dicts = hm.severity_heatmap_as_dicts()

        assert len(dicts) == 35
        assert all("day" in d and "severity" in d and "count" in d for d in dicts)


# =========================================================================
# OverviewStats dataclass
# =========================================================================


class TestOverviewStatsDefaults:
    def test_defaults(self) -> None:
        stats = OverviewStats()
        assert stats.total_scans == 0
        assert stats.verdict_breakdown == {}
        assert stats.avg_risk_score == 0.0
        assert stats.total_findings == 0


# =========================================================================
# TimeBucket enum
# =========================================================================


class TestTimeBucket:
    def test_values(self) -> None:
        assert TimeBucket.HOURLY == "hourly"
        assert TimeBucket.DAILY == "daily"
        assert TimeBucket.WEEKLY == "weekly"
        assert TimeBucket.MONTHLY == "monthly"


# =========================================================================
# Integration: aggregator + trends + heatmap together
# =========================================================================


class TestIntegration:
    def test_full_pipeline(
        self, sample_scans: list[ScanRecord], sample_findings: list[FindingRecord]
    ) -> None:
        """Verify all three analytics modules work together without errors."""
        agg = AnalyticsAggregator(scans=sample_scans, findings=sample_findings)
        overview = agg.overview()
        assert overview.total_scans == 10

        vol = agg.scan_volume()
        assert len(vol) > 0

        top = agg.top_rules()
        assert len(top) > 0

        layers = agg.layer_effectiveness()
        assert len(layers) > 0

        cats = agg.category_breakdown()
        assert len(cats) > 0

        trend = TrendAnalyzer(scans=sample_scans)
        ma = trend.moving_average()
        assert len(ma) > 0

        comp = trend.period_comparison(
            reference_time=datetime(2026, 2, 21, 0, 0, 0, tzinfo=UTC)
        )
        assert isinstance(comp, PeriodComparison)

        hm = HeatmapGenerator(scans=sample_scans, findings=sample_findings)
        activity = hm.activity_heatmap()
        assert len(activity) == 168

        severity = hm.severity_heatmap()
        assert len(severity) == 35


# =========================================================================
# Edge cases — all modules with single scan
# =========================================================================


class TestSingleScanEdge:
    def test_all_analytics_single_scan(self) -> None:
        scan = _make_scan(
            scan_id="only-scan",
            verdict="MALICIOUS",
            risk_score=95,
            duration_ms=200,
        )
        finding = _make_finding(
            finding_id="only-finding",
            scan_id="only-scan",
            rule_id="RULE-999",
        )

        agg = AnalyticsAggregator(scans=[scan], findings=[finding])
        assert agg.overview().total_scans == 1
        assert agg.scan_volume() == [{"bucket": "2026-02-20", "count": 1}]
        assert agg.verdict_distribution() == [{"verdict": "MALICIOUS", "count": 1}]
        assert agg.risk_score_distribution() == [{"range": "90-99", "count": 1}]
        assert agg.top_rules() == [{"rule_id": "RULE-999", "count": 1}]
        assert agg.category_breakdown() == [{"category": "prompt_injection", "count": 1}]
        assert agg.layer_effectiveness() == [{"layer": "rule_engine", "findings_count": 1}]
        assert len(agg.avg_latency()) == 1

        trend = TrendAnalyzer(scans=[scan])
        ma = trend.moving_average()
        assert len(ma) == 1
        assert ma[0]["value"] == 1.0
        assert ma[0]["moving_avg"] == 1.0

        hm = HeatmapGenerator(scans=[scan], findings=[finding])
        assert len(hm.activity_heatmap()) == 168
        assert len(hm.severity_heatmap()) == 35


# =========================================================================
# Bucket key function edge cases
# =========================================================================


class TestBucketKey:
    def test_all_bucket_types(self) -> None:
        from malwar.analytics.aggregator import _bucket_key

        dt = datetime(2026, 2, 20, 14, 30, 0, tzinfo=UTC)

        assert _bucket_key(dt, TimeBucket.HOURLY) == "2026-02-20T14:00"
        assert _bucket_key(dt, TimeBucket.DAILY) == "2026-02-20"
        assert _bucket_key(dt, TimeBucket.MONTHLY) == "2026-02"
        # Weekly: 2026-02-20 is a Friday, ISO week 8
        weekly = _bucket_key(dt, TimeBucket.WEEKLY)
        assert weekly.startswith("2026-W")


# =========================================================================
# AnomalyAlert dataclass
# =========================================================================


class TestAnomalyAlertDataclass:
    def test_fields(self) -> None:
        alert = AnomalyAlert(
            alert_type="volume_spike",
            bucket="2026-02-20",
            value=50.0,
            threshold=10.0,
            message="Test alert",
        )
        assert alert.alert_type == "volume_spike"
        assert alert.value == 50.0


# =========================================================================
# Malicious spike anomaly detection
# =========================================================================


class TestMaliciousSpikeAnomaly:
    def test_malicious_spike(self) -> None:
        """A sudden spike in MALICIOUS scans should be detected."""
        base = datetime(2026, 2, 1, 12, 0, 0, tzinfo=UTC)
        scans = []
        # 1 MALICIOUS scan per day for days 0-9
        for i in range(10):
            scans.append(
                _make_scan(
                    scan_id=f"m-{i}",
                    verdict="MALICIOUS",
                    risk_score=90,
                    started_at=base + timedelta(days=i),
                )
            )
        # Spike: 30 MALICIOUS scans on day 10
        for j in range(30):
            scans.append(
                _make_scan(
                    scan_id=f"spike-m-{j}",
                    verdict="MALICIOUS",
                    risk_score=95,
                    started_at=base + timedelta(days=10, minutes=j),
                )
            )

        trend = TrendAnalyzer(scans=scans)
        alerts = trend.detect_anomalies(bucket=TimeBucket.DAILY)

        malicious_alerts = [a for a in alerts if a.alert_type == "malicious_spike"]
        assert len(malicious_alerts) > 0
