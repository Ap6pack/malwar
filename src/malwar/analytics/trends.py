# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Trend analysis — moving averages, period-over-period comparison, anomaly detection."""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from malwar.analytics.aggregator import ScanRecord, TimeBucket, _bucket_key

logger = logging.getLogger("malwar.analytics.trends")


@dataclass(frozen=True, slots=True)
class PeriodComparison:
    """Period-over-period comparison result."""

    current_count: int = 0
    previous_count: int = 0
    change_absolute: int = 0
    change_percent: float = 0.0


@dataclass(frozen=True, slots=True)
class AnomalyAlert:
    """Anomaly detected in scan volume or malicious rate."""

    alert_type: str
    bucket: str
    value: float
    threshold: float
    message: str


class TrendAnalyzer:
    """Analyzes scan data trends.

    Operates on a list of :class:`ScanRecord` instances and provides:

    * Moving averages of scan volume or risk scores
    * Period-over-period comparison (this week vs last week, etc.)
    * Anomaly detection for sudden spikes in malicious scans
    """

    def __init__(self, scans: list[ScanRecord] | None = None) -> None:
        self.scans: list[ScanRecord] = scans or []

    # ------------------------------------------------------------------
    # Moving averages
    # ------------------------------------------------------------------

    def moving_average(
        self,
        bucket: TimeBucket = TimeBucket.DAILY,
        window: int = 7,
        metric: str = "volume",
    ) -> list[dict[str, object]]:
        """Compute a moving average over bucketed scan data.

        Parameters
        ----------
        bucket:
            Time granularity for grouping scans.
        window:
            Number of buckets for the moving-average window.
        metric:
            ``"volume"`` for scan count, ``"risk"`` for average risk score.

        Returns
        -------
        A list of ``{"bucket": <str>, "value": <float>, "moving_avg": <float>}``
        dicts sorted chronologically.
        """
        if not self.scans:
            return []

        # Group by bucket
        groups: dict[str, list[ScanRecord]] = {}
        for s in self.scans:
            key = _bucket_key(s.started_at, bucket)
            groups.setdefault(key, []).append(s)

        sorted_keys = sorted(groups)
        values: list[float] = []
        for key in sorted_keys:
            group = groups[key]
            if metric == "risk":
                val = sum(s.risk_score for s in group) / len(group)
            else:
                val = float(len(group))
            values.append(val)

        # Compute moving average
        result: list[dict[str, object]] = []
        for i, key in enumerate(sorted_keys):
            start = max(0, i - window + 1)
            window_slice = values[start : i + 1]
            ma = round(sum(window_slice) / len(window_slice), 2)
            result.append({
                "bucket": key,
                "value": round(values[i], 2),
                "moving_avg": ma,
            })

        return result

    # ------------------------------------------------------------------
    # Period-over-period comparison
    # ------------------------------------------------------------------

    def period_comparison(
        self,
        period_days: int = 7,
        reference_time: datetime | None = None,
    ) -> PeriodComparison:
        """Compare the current period with the previous period.

        Parameters
        ----------
        period_days:
            Length of each period in days (default 7 = weekly).
        reference_time:
            End of the current period.  Defaults to ``now(UTC)``.
        """
        now = reference_time or datetime.now(UTC)
        current_start = now - timedelta(days=period_days)
        previous_start = current_start - timedelta(days=period_days)

        current_count = sum(
            1 for s in self.scans if current_start <= s.started_at <= now
        )
        previous_count = sum(
            1 for s in self.scans if previous_start <= s.started_at < current_start
        )

        change_absolute = current_count - previous_count
        if previous_count > 0:
            change_percent = round((change_absolute / previous_count) * 100, 2)
        else:
            change_percent = 100.0 if current_count > 0 else 0.0

        return PeriodComparison(
            current_count=current_count,
            previous_count=previous_count,
            change_absolute=change_absolute,
            change_percent=change_percent,
        )

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def detect_anomalies(
        self,
        bucket: TimeBucket = TimeBucket.DAILY,
        z_threshold: float = 2.0,
    ) -> list[AnomalyAlert]:
        """Detect anomalous spikes in scan volume or malicious scan rate.

        Uses a simple z-score approach: any bucket whose value exceeds
        ``mean + z_threshold * stddev`` is flagged.

        Parameters
        ----------
        bucket:
            Time granularity for grouping scans.
        z_threshold:
            Number of standard deviations above the mean to trigger an alert.
        """
        if not self.scans:
            return []

        # Build volume and malicious-rate series
        volume_groups: dict[str, int] = {}
        malicious_groups: dict[str, int] = {}
        for s in self.scans:
            key = _bucket_key(s.started_at, bucket)
            volume_groups[key] = volume_groups.get(key, 0) + 1
            if s.verdict == "MALICIOUS":
                malicious_groups[key] = malicious_groups.get(key, 0) + 1

        alerts: list[AnomalyAlert] = []

        # Volume anomalies
        alerts.extend(
            _check_series(volume_groups, z_threshold, alert_type="volume_spike")
        )

        # Malicious rate anomalies
        if malicious_groups:
            alerts.extend(
                _check_series(
                    malicious_groups, z_threshold, alert_type="malicious_spike"
                )
            )

        return alerts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_series(
    series: dict[str, int],
    z_threshold: float,
    alert_type: str,
) -> list[AnomalyAlert]:
    """Check a time series for z-score anomalies."""
    values = list(series.values())
    if len(values) < 3:
        # Not enough data to compute meaningful stats
        return []

    mean = statistics.mean(values)
    stdev = statistics.pstdev(values)

    if stdev == 0:
        return []

    threshold_val = mean + z_threshold * stdev

    alerts: list[AnomalyAlert] = []
    for bucket_key, value in series.items():
        if value > threshold_val:
            alerts.append(
                AnomalyAlert(
                    alert_type=alert_type,
                    bucket=bucket_key,
                    value=float(value),
                    threshold=round(threshold_val, 2),
                    message=f"{alert_type}: {value} in {bucket_key} exceeds threshold {threshold_val:.2f}",
                )
            )

    return alerts
