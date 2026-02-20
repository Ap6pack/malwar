# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""End-to-end tests exercising the full scan flow through CLI internals."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from malwar.cli.app import OutputFormat, _output_result, _write_output
from malwar.core.config import get_settings
from malwar.detectors.rule_engine.detector import RuleEngineDetector
from malwar.detectors.threat_intel.detector import ThreatIntelDetector
from malwar.scanner.pipeline import ScanPipeline

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "skills"
BENIGN_DIR = FIXTURES_DIR / "benign"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"


def _build_pipeline() -> ScanPipeline:
    """Build a pipeline with rule_engine + threat_intel (no LLM, no URL crawl)."""
    settings = get_settings()
    pipeline = ScanPipeline(settings=settings)
    pipeline.register_detector(RuleEngineDetector())
    pipeline.register_detector(ThreatIntelDetector())
    return pipeline


# ---------------------------------------------------------------------------
# 1. scan_file() on a malicious fixture
# ---------------------------------------------------------------------------
class TestScanFileMalicious:
    """Scan a known-malicious fixture via pipeline.scan_file() and verify verdict."""

    async def test_malicious_base64_reverse_shell(self) -> None:
        pipeline = _build_pipeline()
        fixture_path = str(MALICIOUS_DIR / "base64_reverse_shell.md")

        result = await pipeline.scan_file(
            fixture_path, layers=["rule_engine", "threat_intel"]
        )

        assert result.status == "completed"
        assert result.verdict == "MALICIOUS"
        assert result.risk_score >= 75
        assert len(result.findings) > 0
        assert result.skill_sha256 != ""
        assert result.scan_id != ""
        assert "rule_engine" in result.layers_executed

    async def test_malicious_prompt_injection(self) -> None:
        pipeline = _build_pipeline()
        fixture_path = str(MALICIOUS_DIR / "prompt_injection_basic.md")

        result = await pipeline.scan_file(
            fixture_path, layers=["rule_engine", "threat_intel"]
        )

        assert result.verdict == "MALICIOUS"
        rule_ids = {f.rule_id for f in result.findings}
        assert "MALWAR-PI-001" in rule_ids


# ---------------------------------------------------------------------------
# 2. scan_file() on a benign fixture
# ---------------------------------------------------------------------------
class TestScanFileBenign:
    """Scan benign fixtures via pipeline.scan_file() and verify CLEAN verdict."""

    async def test_benign_hello_world(self) -> None:
        pipeline = _build_pipeline()
        fixture_path = str(BENIGN_DIR / "hello_world.md")

        result = await pipeline.scan_file(
            fixture_path, layers=["rule_engine", "threat_intel"]
        )

        assert result.status == "completed"
        assert result.verdict == "CLEAN"
        assert result.risk_score == 0
        assert len(result.findings) == 0
        assert result.skill_name == "Hello World"
        assert result.skill_author == "Jane Smith"

    async def test_benign_code_formatter(self) -> None:
        pipeline = _build_pipeline()
        fixture_path = str(BENIGN_DIR / "code_formatter.md")

        result = await pipeline.scan_file(
            fixture_path, layers=["rule_engine", "threat_intel"]
        )

        assert result.verdict == "CLEAN"
        assert result.risk_score == 0


# ---------------------------------------------------------------------------
# 3. _output_result with each format (console, json, sarif)
# ---------------------------------------------------------------------------
class TestOutputResult:
    """Test _output_result dispatches correctly to each formatter."""

    @pytest.fixture
    async def malicious_result(self):
        pipeline = _build_pipeline()
        fixture_path = str(MALICIOUS_DIR / "base64_reverse_shell.md")
        return await pipeline.scan_file(
            fixture_path, layers=["rule_engine", "threat_intel"]
        )

    @pytest.fixture
    async def clean_result(self):
        pipeline = _build_pipeline()
        fixture_path = str(BENIGN_DIR / "hello_world.md")
        return await pipeline.scan_file(
            fixture_path, layers=["rule_engine", "threat_intel"]
        )

    def test_console_format(self, malicious_result, capsys) -> None:
        """Console format prints to rich console (no exception)."""
        _output_result(malicious_result, OutputFormat.CONSOLE, None)
        # Console formatter uses Rich which writes to its own Console object,
        # so we just verify it completes without error.

    def test_json_format_to_stdout(self, malicious_result) -> None:
        """JSON format writes valid JSON to stdout."""
        buf = StringIO()
        with patch("sys.stdout", buf):
            _output_result(malicious_result, OutputFormat.JSON, None)

        output = buf.getvalue()
        data = json.loads(output)
        assert data["verdict"] == "MALICIOUS"
        assert data["risk_score"] >= 75
        assert "findings" in data

    def test_json_format_clean(self, clean_result) -> None:
        """JSON format on a clean result shows CLEAN verdict."""
        buf = StringIO()
        with patch("sys.stdout", buf):
            _output_result(clean_result, OutputFormat.JSON, None)

        output = buf.getvalue()
        data = json.loads(output)
        assert data["verdict"] == "CLEAN"
        assert data["risk_score"] == 0

    def test_sarif_format_to_stdout(self, malicious_result) -> None:
        """SARIF format writes valid SARIF JSON to stdout."""
        buf = StringIO()
        with patch("sys.stdout", buf):
            _output_result(malicious_result, OutputFormat.SARIF, None)

        output = buf.getvalue()
        sarif = json.loads(output)
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "malwar"
        assert len(sarif["runs"][0]["results"]) > 0

    def test_sarif_format_clean(self, clean_result) -> None:
        """SARIF format on a clean result has zero results."""
        buf = StringIO()
        with patch("sys.stdout", buf):
            _output_result(clean_result, OutputFormat.SARIF, None)

        output = buf.getvalue()
        sarif = json.loads(output)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0


# ---------------------------------------------------------------------------
# 4. _write_output with both file output and stdout
# ---------------------------------------------------------------------------
class TestWriteOutput:
    """Test _write_output writes to file or stdout correctly."""

    def test_write_to_file(self, tmp_path) -> None:
        """When output path is provided, text is written to file."""
        out_file = tmp_path / "report.json"
        text = '{"verdict": "CLEAN"}'

        _write_output(text, out_file)

        assert out_file.exists()
        assert out_file.read_text() == text

    def test_write_to_stdout(self) -> None:
        """When output is None, text is written to stdout."""
        buf = StringIO()
        text = '{"verdict": "MALICIOUS"}'

        with patch("sys.stdout", buf):
            _write_output(text, None)

        assert text in buf.getvalue()

    def test_write_to_file_overwrites(self, tmp_path) -> None:
        """Writing to an existing file overwrites the content."""
        out_file = tmp_path / "report.json"
        out_file.write_text("old content")

        new_text = '{"verdict": "SUSPICIOUS"}'
        _write_output(new_text, out_file)

        assert out_file.read_text() == new_text


# ---------------------------------------------------------------------------
# 5. Directory scanning
# ---------------------------------------------------------------------------
class TestDirectoryScanning:
    """Test scanning a directory of SKILL.md files through _async_scan."""

    async def test_scan_benign_directory(self) -> None:
        """Scan a directory of benign files; all should be CLEAN."""
        from malwar.cli.app import _async_scan

        buf = StringIO()
        with patch("sys.stdout", buf):
            await _async_scan(
                target=str(BENIGN_DIR),
                fmt=OutputFormat.JSON,
                output=None,
                no_llm=True,
                no_urls=True,
                layers_str="rule_engine,threat_intel",
            )

        output = buf.getvalue()
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) > 0

        for entry in data:
            assert entry["verdict"] == "CLEAN"

    async def test_scan_malicious_directory(self) -> None:
        """Scan a directory of malicious files; none should be CLEAN."""
        from malwar.cli.app import _async_scan

        buf = StringIO()
        with patch("sys.stdout", buf):
            await _async_scan(
                target=str(MALICIOUS_DIR),
                fmt=OutputFormat.JSON,
                output=None,
                no_llm=True,
                no_urls=True,
                layers_str="rule_engine,threat_intel",
            )

        output = buf.getvalue()
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) > 0

        for entry in data:
            assert entry["verdict"] != "CLEAN", (
                f"Expected non-CLEAN verdict for {entry['target']}, "
                f"got {entry['verdict']}"
            )

    async def test_scan_directory_to_file(self, tmp_path) -> None:
        """Scan a directory and write JSON output to a file."""
        from malwar.cli.app import _async_scan

        out_file = tmp_path / "results.json"

        await _async_scan(
            target=str(BENIGN_DIR),
            fmt=OutputFormat.JSON,
            output=out_file,
            no_llm=True,
            no_urls=True,
            layers_str="rule_engine,threat_intel",
        )

        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert isinstance(data, list)
        assert len(data) > 0

    async def test_scan_directory_sarif_format(self) -> None:
        """Scan a directory with SARIF output format."""
        from malwar.cli.app import _async_scan

        buf = StringIO()
        with patch("sys.stdout", buf):
            await _async_scan(
                target=str(BENIGN_DIR),
                fmt=OutputFormat.SARIF,
                output=None,
                no_llm=True,
                no_urls=True,
                layers_str="rule_engine,threat_intel",
            )

        output = buf.getvalue()
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) > 0
        # Each entry should be a valid SARIF object
        for entry in data:
            assert entry["version"] == "2.1.0"

    async def test_scan_empty_directory(self, tmp_path) -> None:
        """Scan a directory with no .md files raises typer.Exit."""
        from click.exceptions import Exit as ClickExit

        from malwar.cli.app import _async_scan

        with pytest.raises(ClickExit):
            await _async_scan(
                target=str(tmp_path),
                fmt=OutputFormat.CONSOLE,
                output=None,
                no_llm=True,
                no_urls=True,
                layers_str="rule_engine,threat_intel",
            )

    async def test_scan_nonexistent_target(self) -> None:
        """Scan a nonexistent target raises typer.Exit."""
        from click.exceptions import Exit as ClickExit

        from malwar.cli.app import _async_scan

        with pytest.raises(ClickExit):
            await _async_scan(
                target="/nonexistent/path/does_not_exist",
                fmt=OutputFormat.CONSOLE,
                output=None,
                no_llm=True,
                no_urls=True,
                layers_str="rule_engine,threat_intel",
            )
