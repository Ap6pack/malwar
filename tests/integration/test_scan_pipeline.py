# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests: full pipeline scan against all fixtures."""

import pytest
from pathlib import Path

from malwar.core.config import get_settings
from malwar.parsers.skill_parser import parse_skill_content
from malwar.scanner.pipeline import ScanPipeline
from malwar.detectors.rule_engine.detector import RuleEngineDetector
from malwar.detectors.threat_intel.detector import ThreatIntelDetector

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "skills"


def _build_pipeline() -> ScanPipeline:
    settings = get_settings()
    pipeline = ScanPipeline(settings=settings)
    pipeline.register_detector(RuleEngineDetector())
    pipeline.register_detector(ThreatIntelDetector())
    return pipeline


async def _scan_fixture(pipeline: ScanPipeline, subdir: str, name: str):
    path = FIXTURES_DIR / subdir / name
    content = path.read_text()
    skill = parse_skill_content(content, name)
    return await pipeline.scan(skill, layers=["rule_engine", "threat_intel"])


class TestMaliciousFixturesDetected:
    """Every malicious fixture must be flagged (not CLEAN)."""

    @pytest.fixture
    def pipeline(self):
        return _build_pipeline()

    async def test_clawhavoc_amos(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "clawhavoc_amos.md")
        assert result.verdict == "MALICIOUS"
        assert result.risk_score >= 75
        rule_ids = {f.rule_id for f in result.findings}
        assert "MALWAR-OBF-001" in rule_ids
        assert "MALWAR-MAL-001" in rule_ids

    async def test_base64_reverse_shell(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "base64_reverse_shell.md")
        assert result.verdict == "MALICIOUS"
        assert any(f.rule_id == "MALWAR-OBF-001" for f in result.findings)

    async def test_clickfix_fake_prereq(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "clickfix_fake_prereq.md")
        assert result.verdict != "CLEAN"
        assert any(f.category == "suspicious_command" or f.category == "social_engineering"
                    for f in result.findings)

    async def test_prompt_injection_basic(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "prompt_injection_basic.md")
        assert result.verdict == "MALICIOUS"
        assert any(f.rule_id == "MALWAR-PI-001" for f in result.findings)

    async def test_prompt_injection_unicode(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "prompt_injection_unicode.md")
        assert result.verdict != "CLEAN"
        assert any(f.category == "prompt_injection" for f in result.findings)

    async def test_credential_harvester(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "credential_harvester.md")
        assert result.verdict == "MALICIOUS"
        assert any(f.category == "credential_exposure" for f in result.findings)

    async def test_exfil_soul_md(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "exfil_soul_md.md")
        assert result.verdict == "MALICIOUS"
        assert any(f.rule_id == "MALWAR-EXFIL-001" for f in result.findings)

    async def test_typosquatted_package(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "typosquatted_package.md")
        assert result.verdict != "CLEAN"
        assert any(f.category == "typosquatting" for f in result.findings)

    async def test_obfuscated_curl(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "obfuscated_curl.md")
        assert result.verdict != "CLEAN"

    async def test_multi_stage_dropper(self, pipeline):
        result = await _scan_fixture(pipeline, "malicious", "multi_stage_dropper.md")
        assert result.verdict != "CLEAN"
        assert any(f.rule_id == "MALWAR-CMD-004" for f in result.findings)


class TestBenignFixturesClean:
    """Every benign fixture must pass as CLEAN."""

    @pytest.fixture
    def pipeline(self):
        return _build_pipeline()

    @pytest.mark.parametrize("name", [
        "hello_world.md",
        "code_formatter.md",
        "git_helper.md",
        "web_search.md",
        "legitimate_with_urls.md",
    ])
    async def test_benign_is_clean(self, pipeline, name):
        result = await _scan_fixture(pipeline, "benign", name)
        assert result.verdict == "CLEAN", (
            f"{name} should be CLEAN but got {result.verdict} "
            f"with findings: {[f.rule_id for f in result.findings]}"
        )
        assert result.risk_score == 0


class TestScanResultStructure:
    """Verify scan result model integrity."""

    async def test_result_has_all_fields(self):
        pipeline = _build_pipeline()
        result = await _scan_fixture(pipeline, "malicious", "clawhavoc_amos.md")

        assert result.scan_id
        assert result.target == "clawhavoc_amos.md"
        assert result.status == "completed"
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.duration_ms is not None and result.duration_ms >= 0
        assert result.skill_sha256
        assert result.skill_name == "Polymarket Trading Bot"
        assert result.skill_author == "Aslaep123"
        assert "rule_engine" in result.layers_executed
        assert result.finding_count_by_severity

    async def test_sarif_output(self):
        from malwar.cli.formatters.sarif import format_sarif, scan_result_to_sarif
        import json

        pipeline = _build_pipeline()
        result = await _scan_fixture(pipeline, "malicious", "clawhavoc_amos.md")
        sarif_str = format_sarif(result)
        sarif = json.loads(sarif_str)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "malwar"
        assert len(sarif["runs"][0]["results"]) > 0

    async def test_json_output(self):
        from malwar.cli.formatters.json_fmt import format_json
        import json

        pipeline = _build_pipeline()
        result = await _scan_fixture(pipeline, "malicious", "clawhavoc_amos.md")
        json_str = format_json(result)
        data = json.loads(json_str)

        assert data["verdict"] == "MALICIOUS"
        assert data["risk_score"] >= 75
