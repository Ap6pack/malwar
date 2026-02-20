# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI command: malwar test-rules — run rule test suite from a manifest."""

from __future__ import annotations

import asyncio
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(help="Run rule test suite")


class TestOutputFormat(StrEnum):
    TEXT = "text"
    JSON = "json"
    JUNIT = "junit"


DEFAULT_MANIFEST = Path("tests/rule_tests.yml")


@app.callback(invoke_without_command=True)
def test_rules(
    manifest: Annotated[
        Path,
        typer.Option("--manifest", "-m", help="Path to rule test manifest YAML"),
    ] = DEFAULT_MANIFEST,
    fmt: Annotated[
        TestOutputFormat,
        typer.Option("--format", "-f", help="Output format: text, json, or junit"),
    ] = TestOutputFormat.TEXT,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write results to file instead of stdout"),
    ] = None,
) -> None:
    """Run all rule tests from the manifest and report results."""
    asyncio.run(_async_test_rules(manifest, fmt, output))


async def _async_test_rules(
    manifest_path: Path,
    fmt: TestOutputFormat,
    output: Path | None,
) -> None:
    from malwar.testing.framework import RuleTestManifest, RuleTestRunner

    if not manifest_path.exists():
        typer.echo(f"Manifest not found: {manifest_path}", err=True)
        raise typer.Exit(1)

    manifest = RuleTestManifest.from_yaml(manifest_path)
    typer.echo(f"Running {len(manifest.test_cases)} rule tests...", err=True)

    report = await RuleTestRunner.run(manifest)

    if fmt == TestOutputFormat.TEXT:
        text = report.to_text()
    elif fmt == TestOutputFormat.JSON:
        text = report.to_json()
    elif fmt == TestOutputFormat.JUNIT:
        text = report.to_junit_xml()
    else:
        text = report.to_text()

    if output:
        output.write_text(text, encoding="utf-8")
        typer.echo(f"Results written to {output}", err=True)
    else:
        sys.stdout.write(text + "\n")

    if not report.all_passed:
        raise typer.Exit(1)
