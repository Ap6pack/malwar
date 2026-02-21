# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI command: ``malwar analytics summary`` — Rich-formatted terminal dashboard."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Annotated

import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def summary(
    days: Annotated[
        int | None,
        typer.Option("--days", "-d", help="Limit to last N days"),
    ] = None,
) -> None:
    """Show a Rich-formatted analytics dashboard in the terminal."""
    asyncio.run(_async_summary(days))


async def _async_summary(days: int | None) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    from malwar.analytics.aggregator import (
        AnalyticsAggregator,
        FindingRecord,
        ScanRecord,
        TimeBucket,
    )
    from malwar.analytics.trends import TrendAnalyzer
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    db = await init_db(settings.db_path)
    console = Console()

    try:
        # Fetch scan data
        where = ""
        params: list[str] = []
        if days is not None:
            from datetime import timedelta

            cutoff_dt = datetime.now(UTC) - timedelta(days=days)
            cutoff = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%S")
            where = " WHERE started_at >= ?"
            params = [cutoff]

        cursor = await db.execute(
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
        if scan_ids:
            placeholders = ",".join("?" for _ in scan_ids)
            cursor = await db.execute(
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

        if not scans:
            console.print("[yellow]No scan data found.[/yellow]")
            return

        # Aggregator
        agg = AnalyticsAggregator(scans=scans, findings=findings)
        overview = agg.overview()

        # -- Overview Panel --
        verdict_colors = {
            "MALICIOUS": "red",
            "SUSPICIOUS": "yellow",
            "CAUTION": "cyan",
            "CLEAN": "green",
        }
        verdict_parts = []
        for v, c in sorted(overview.verdict_breakdown.items()):
            color = verdict_colors.get(v, "white")
            verdict_parts.append(f"[{color}]{v}: {c}[/{color}]")
        verdict_line = " | ".join(verdict_parts) if verdict_parts else "No data"

        overview_lines = [
            f"Total Scans:    {overview.total_scans}",
            f"Total Findings: {overview.total_findings}",
            f"Avg Risk Score: {overview.avg_risk_score}",
            f"Verdicts:       {verdict_line}",
        ]
        console.print(Panel("\n".join(overview_lines), title="Analytics Overview"))

        # -- Scan Volume Sparkline --
        volume = agg.scan_volume(bucket=TimeBucket.DAILY)
        if volume:
            spark_chars = " ▁▂▃▄▅▆▇█"
            counts = [int(v["count"]) for v in volume]  # type: ignore[call-overload]
            max_count = max(counts) if counts else 1
            sparkline = ""
            for c in counts:
                idx = int((c / max_count) * (len(spark_chars) - 1)) if max_count > 0 else 0
                sparkline += spark_chars[idx]
            console.print(f"\n[bold]Daily Scan Volume:[/bold] {sparkline}")
            console.print(
                f"  ({volume[0]['bucket']} .. {volume[-1]['bucket']}, "
                f"min={min(counts)}, max={max(counts)})"
            )

        # -- Verdict Distribution Table --
        verdict_dist = agg.verdict_distribution()
        if verdict_dist:
            vt = Table(title="Verdict Distribution")
            vt.add_column("Verdict", style="bold")
            vt.add_column("Count", justify="right")
            vt.add_column("Percent", justify="right")
            for entry in verdict_dist:
                pct = round(int(entry["count"]) / overview.total_scans * 100, 1)  # type: ignore[call-overload]
                vt.add_row(str(entry["verdict"]), str(entry["count"]), f"{pct}%")
            console.print(vt)

        # -- Top Triggered Rules --
        top_rules = agg.top_rules(limit=10)
        if top_rules:
            rt = Table(title="Top Triggered Rules")
            rt.add_column("Rule ID", style="cyan")
            rt.add_column("Count", justify="right")
            for r in top_rules:
                rt.add_row(str(r["rule_id"]), str(r["count"]))
            console.print(rt)

        # -- Layer Effectiveness --
        layers = agg.layer_effectiveness()
        if layers:
            lt = Table(title="Detection Layer Effectiveness")
            lt.add_column("Layer", style="bold")
            lt.add_column("Findings", justify="right")
            for le_entry in layers:
                lt.add_row(str(le_entry["layer"]), str(le_entry["findings_count"]))
            console.print(lt)

        # -- Category Breakdown --
        cats = agg.category_breakdown()
        if cats:
            ct = Table(title="Threat Category Breakdown")
            ct.add_column("Category", style="bold")
            ct.add_column("Count", justify="right")
            for cat in cats:
                ct.add_row(str(cat["category"]), str(cat["count"]))
            console.print(ct)

        # -- Trend Comparison --
        trend = TrendAnalyzer(scans=scans)
        comparison = trend.period_comparison()
        arrow = "[green]^" if comparison.change_absolute >= 0 else "[red]v"
        console.print(
            f"\n[bold]Week-over-Week:[/bold] "
            f"{comparison.previous_count} -> {comparison.current_count} "
            f"({arrow} {comparison.change_percent}%[/])"
        )

        # -- Anomalies --
        anomalies = trend.detect_anomalies()
        if anomalies:
            console.print("\n[bold red]Anomalies Detected:[/bold red]")
            for a in anomalies:
                console.print(f"  [red]! {a.message}[/red]")

    finally:
        await close_db()
