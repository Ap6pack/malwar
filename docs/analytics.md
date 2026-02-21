# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

# Dashboard Analytics

Malwar includes a built-in analytics engine that computes trends, heatmaps, and timeline data from scan history. This page covers the analytics module, API endpoints, and CLI commands.

## Overview

The analytics system consists of three core modules:

| Module | Purpose |
|--------|---------|
| `AnalyticsAggregator` | Computes aggregated statistics from scan history |
| `TrendAnalyzer` | Moving averages, period-over-period comparison, anomaly detection |
| `HeatmapGenerator` | Day-of-week x hour-of-day activity grids, severity heatmaps |

## API Endpoints

All endpoints require authentication via `X-API-Key` header and are prefixed with `/api/v1`.

### GET `/api/v1/analytics/overview`

High-level dashboard statistics.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `days` | int (optional) | Limit to last N days |

**Response:**

```json
{
  "total_scans": 1234,
  "verdict_breakdown": {
    "CLEAN": 900,
    "CAUTION": 200,
    "SUSPICIOUS": 100,
    "MALICIOUS": 34
  },
  "avg_risk_score": 18.5,
  "total_findings": 567
}
```

### GET `/api/v1/analytics/trends`

Time-series trend data with moving averages and anomaly detection.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `period` | string | `daily` | Bucket period: `hourly`, `daily`, `weekly`, `monthly` |
| `days` | int | - | Limit to last N days |
| `window` | int | 7 | Moving average window size |

**Response:**

```json
{
  "series": [
    {"bucket": "2026-02-18", "value": 42.0, "moving_avg": 38.5},
    {"bucket": "2026-02-19", "value": 55.0, "moving_avg": 41.2}
  ],
  "period_comparison": {
    "current_count": 300,
    "previous_count": 250,
    "change_absolute": 50,
    "change_percent": 20.0
  },
  "anomalies": [
    {
      "alert_type": "volume_spike",
      "bucket": "2026-02-19",
      "value": 55.0,
      "threshold": 48.3,
      "message": "volume_spike: 55 in 2026-02-19 exceeds threshold 48.30"
    }
  ]
}
```

### GET `/api/v1/analytics/heatmap`

Activity and severity heatmap data.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `days` | int (optional) | Limit to last N days |

**Response:**

```json
{
  "activity": [
    {"day": "Monday", "hour": 0, "count": 5},
    {"day": "Monday", "hour": 1, "count": 3}
  ],
  "severity": [
    {"day": "Monday", "severity": "critical", "count": 2},
    {"day": "Monday", "severity": "high", "count": 8}
  ]
}
```

The activity heatmap always returns all 168 cells (7 days x 24 hours). The severity heatmap returns 35 cells (7 days x 5 severity levels).

### GET `/api/v1/analytics/rules`

Top triggered detection rules with counts.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 10 | Number of top rules to return |
| `days` | int | - | Limit to last N days |

**Response:**

```json
{
  "top_rules": [
    {"rule_id": "MALWAR-PI-001", "count": 45},
    {"rule_id": "MALWAR-OBF-002", "count": 23}
  ]
}
```

### GET `/api/v1/analytics/layers`

Detection layer effectiveness statistics.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `days` | int (optional) | Limit to last N days |

**Response:**

```json
{
  "layers": [
    {"layer": "rule_engine", "findings_count": 340},
    {"layer": "url_crawler", "findings_count": 120},
    {"layer": "llm_analyzer", "findings_count": 85},
    {"layer": "threat_intel", "findings_count": 22}
  ]
}
```

## CLI Command

### `malwar analytics summary`

Displays a Rich-formatted analytics dashboard in the terminal with tables and sparklines.

```bash
# Show all-time analytics
malwar analytics summary

# Limit to last 30 days
malwar analytics summary --days 30
```

The dashboard includes:

- **Overview panel** with total scans, findings, average risk score, and verdict breakdown
- **Sparkline** showing daily scan volume
- **Verdict distribution** table with percentages
- **Top triggered rules** table
- **Detection layer effectiveness** table
- **Threat category breakdown** table
- **Week-over-week comparison** with change percentage
- **Anomaly alerts** if sudden spikes are detected

## Analytics Module Architecture

```
src/malwar/analytics/
    __init__.py          # Public API
    aggregator.py        # AnalyticsAggregator class
    trends.py            # TrendAnalyzer class
    heatmap.py           # HeatmapGenerator class
```

### AnalyticsAggregator

The `AnalyticsAggregator` is a pure in-memory aggregator. It accepts lists of `ScanRecord` and `FindingRecord` dataclasses and computes:

- Scan volume over time (hourly/daily/weekly/monthly buckets)
- Verdict distribution (pie chart data)
- Risk score distribution (histogram data)
- Top triggered rules (count by rule_id)
- Threat category breakdown
- Detection layer effectiveness (findings per layer)
- Average scan latency over time

### TrendAnalyzer

The `TrendAnalyzer` provides:

- **Moving averages** — configurable window over volume or risk metrics
- **Period-over-period comparison** — e.g. this week vs last week
- **Anomaly detection** — z-score based spike detection for scan volume and malicious scan rates

### HeatmapGenerator

The `HeatmapGenerator` produces:

- **Activity heatmap** — 7 x 24 grid of scan counts by day-of-week and hour-of-day
- **Severity heatmap** — 7 x 5 grid of finding counts by day-of-week and severity level

Both full grids (with zeros) and sparse representations (non-zero only) are available.

## Data Model

The analytics module operates on two lightweight dataclasses:

```python
@dataclass(frozen=True, slots=True)
class ScanRecord:
    scan_id: str
    verdict: str
    risk_score: int
    started_at: datetime
    duration_ms: int | None = None
    layers_executed: list[str] = field(default_factory=list)

@dataclass(frozen=True, slots=True)
class FindingRecord:
    finding_id: str
    scan_id: str
    rule_id: str
    category: str
    detector_layer: str
    severity: str
```

These are populated from the `scans` and `findings` database tables by the API layer.
