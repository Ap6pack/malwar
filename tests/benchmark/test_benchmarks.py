# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Performance benchmarks across the full fixture set.

Loads every .md fixture from tests/fixtures/skills/ and runs three scan
configurations, measuring latency (median of 3 runs) for each.  Prints a
formatted results table and asserts that rule_engine p95 stays under 100 ms.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from malwar import scan

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "skills"

# ---------------------------------------------------------------------------
# Scan configurations
# ---------------------------------------------------------------------------

CONFIGS: dict[str, dict] = {
    "rules_only": {
        "use_llm": False,
        "use_urls": False,
        "layers": ["rule_engine"],
    },
    "rules_and_intel": {
        "use_llm": False,
        "use_urls": False,
        "layers": ["rule_engine", "threat_intel"],
    },
    "full_no_network": {
        "use_llm": False,
        "use_urls": False,
        # No explicit layers -- sdk resolves to all non-network layers
        # (rule_engine + threat_intel when use_llm=False, use_urls=False)
    },
}

NUM_RUNS = 3  # runs per (fixture, config) pair; take median


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class BenchmarkRow:
    """Timing result for a single (fixture, config) combination."""

    fixture: str
    config: str
    median_ms: float
    min_ms: float
    max_ms: float
    verdict: str
    finding_count: int


@dataclass
class PercentileSummary:
    """p50 / p95 / p99 for a single config across all fixtures."""

    config: str
    p50: float
    p95: float
    p99: float
    count: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_fixtures() -> list[Path]:
    """Return all .md fixture files under the skills directory tree."""
    fixtures = sorted(FIXTURES_DIR.rglob("*.md"))
    assert fixtures, f"No .md fixtures found under {FIXTURES_DIR}"
    return fixtures


def _percentile(values: list[float], pct: float) -> float:
    """Compute a percentile from a sorted list of floats."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = f + 1
    if c >= len(sorted_vals):
        return sorted_vals[f]
    return sorted_vals[f] + (k - f) * (sorted_vals[c] - sorted_vals[f])


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestPerformanceBenchmarks:
    """Run latency benchmarks across all fixtures and scan configs."""

    async def test_scan_latency(self) -> None:
        fixtures = _collect_fixtures()

        rows: list[BenchmarkRow] = []

        for fixture_path in fixtures:
            content = fixture_path.read_text(encoding="utf-8")
            fixture_label = str(fixture_path.relative_to(FIXTURES_DIR))

            for config_name, config_kwargs in CONFIGS.items():
                timings: list[float] = []
                last_result = None

                for _ in range(NUM_RUNS):
                    t0 = time.perf_counter()
                    result = await scan(
                        content,
                        file_name=fixture_path.name,
                        **config_kwargs,
                    )
                    t1 = time.perf_counter()
                    timings.append((t1 - t0) * 1000.0)  # ms
                    last_result = result

                assert last_result is not None
                median_ms = statistics.median(timings)
                min_ms = min(timings)
                max_ms = max(timings)

                rows.append(
                    BenchmarkRow(
                        fixture=fixture_label,
                        config=config_name,
                        median_ms=round(median_ms, 2),
                        min_ms=round(min_ms, 2),
                        max_ms=round(max_ms, 2),
                        verdict=last_result.verdict,
                        finding_count=len(last_result.findings),
                    )
                )

        # ---------------------------------------------------------------
        # Compute per-config percentiles
        # ---------------------------------------------------------------
        summaries: list[PercentileSummary] = []
        for config_name in CONFIGS:
            medians = [r.median_ms for r in rows if r.config == config_name]
            summaries.append(
                PercentileSummary(
                    config=config_name,
                    p50=round(_percentile(medians, 50), 2),
                    p95=round(_percentile(medians, 95), 2),
                    p99=round(_percentile(medians, 99), 2),
                    count=len(medians),
                )
            )

        # ---------------------------------------------------------------
        # Print overall latency table
        # ---------------------------------------------------------------
        print("\n")  # noqa: T201
        print("=" * 72)  # noqa: T201
        print("  OVERALL LATENCY SUMMARY  (median of 3 runs per fixture)")  # noqa: T201
        print("=" * 72)  # noqa: T201
        hdr = f"{'Config':<22} {'Count':>6} {'p50 (ms)':>10} {'p95 (ms)':>10} {'p99 (ms)':>10}"
        print(hdr)  # noqa: T201
        print("-" * 72)  # noqa: T201
        for s in summaries:
            print(  # noqa: T201
                f"{s.config:<22} {s.count:>6} {s.p50:>10.2f} {s.p95:>10.2f} {s.p99:>10.2f}"
            )
        print("=" * 72)  # noqa: T201

        # ---------------------------------------------------------------
        # Print per-fixture breakdown
        # ---------------------------------------------------------------
        print("\n")  # noqa: T201
        print("=" * 110)  # noqa: T201
        print("  PER-FIXTURE BREAKDOWN")  # noqa: T201
        print("=" * 110)  # noqa: T201
        hdr2 = (
            f"{'Fixture':<45} {'Config':<22} "
            f"{'Median':>8} {'Min':>8} {'Max':>8} "
            f"{'Verdict':<12} {'Findings':>8}"
        )
        print(hdr2)  # noqa: T201
        print("-" * 110)  # noqa: T201
        for r in rows:
            fixture_short = r.fixture if len(r.fixture) <= 44 else "..." + r.fixture[-41:]
            print(  # noqa: T201
                f"{fixture_short:<45} {r.config:<22} "
                f"{r.median_ms:>8.2f} {r.min_ms:>8.2f} {r.max_ms:>8.2f} "
                f"{r.verdict:<12} {r.finding_count:>8}"
            )
        print("=" * 110)  # noqa: T201

        # ---------------------------------------------------------------
        # Assertion: rule_engine p95 must stay under 100 ms
        # ---------------------------------------------------------------
        rules_only_summary = next(s for s in summaries if s.config == "rules_only")
        assert rules_only_summary.p95 < 100.0, (
            f"rules_only p95 ({rules_only_summary.p95:.2f} ms) exceeds 100 ms threshold"
        )

        # Store on class for downstream consumers
        TestPerformanceBenchmarks._rows = rows
        TestPerformanceBenchmarks._summaries = summaries
