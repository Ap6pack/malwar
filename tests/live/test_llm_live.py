# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Live LLM layer tests using the real Anthropic API.

These tests require ``MALWAR_ANTHROPIC_API_KEY`` to be set in the environment.
They are skipped automatically when the key is absent.

Run with::

    MALWAR_ANTHROPIC_API_KEY=sk-ant-... pytest tests/live/test_llm_live.py -xvs
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from malwar import scan
from malwar.core.constants import DetectorLayer

# ---------------------------------------------------------------------------
# Skip entire module if no API key
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = os.environ.get("MALWAR_ANTHROPIC_API_KEY", "")
pytestmark = pytest.mark.skipif(
    not ANTHROPIC_API_KEY,
    reason="MALWAR_ANTHROPIC_API_KEY not set — skipping live LLM tests",
)

# ---------------------------------------------------------------------------
# Fixtures directory
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "skills"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"
BENIGN_DIR = FIXTURES_DIR / "benign"


def _read_fixture(name: str, subdir: str = "malicious") -> str:
    path = FIXTURES_DIR / subdir / name
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests: Malicious detection with LLM layer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLlmMaliciousDetection:
    """LLM layer should identify malicious content in known-bad fixtures."""

    async def test_clawhavoc_amos(self) -> None:
        """ClawHavoc AMOS infostealer should be flagged as MALICIOUS."""
        content = _read_fixture("clawhavoc_amos.md")
        result = await scan(content, file_name="clawhavoc_amos.md", use_urls=False)

        assert result.verdict == "MALICIOUS"
        llm_findings = [
            f for f in result.findings if f.detector_layer == DetectorLayer.LLM_ANALYZER
        ]
        assert len(llm_findings) > 0, "LLM should produce at least one finding"

    async def test_base64_reverse_shell(self) -> None:
        """Base64-encoded reverse shell should be caught."""
        content = _read_fixture("base64_reverse_shell.md")
        result = await scan(content, file_name="base64_reverse_shell.md", use_urls=False)

        assert result.verdict == "MALICIOUS"
        llm_findings = [
            f for f in result.findings if f.detector_layer == DetectorLayer.LLM_ANALYZER
        ]
        assert len(llm_findings) > 0

    async def test_credential_harvester(self) -> None:
        """Credential harvesting skill should be flagged."""
        content = _read_fixture("credential_harvester.md")
        result = await scan(content, file_name="credential_harvester.md", use_urls=False)

        assert result.verdict in ("MALICIOUS", "SUSPICIOUS")
        llm_findings = [
            f for f in result.findings if f.detector_layer == DetectorLayer.LLM_ANALYZER
        ]
        assert len(llm_findings) > 0

    async def test_prompt_injection_basic(self) -> None:
        """Prompt injection should be detected — LLM must not follow the injected instructions."""
        content = _read_fixture("prompt_injection_basic.md")
        result = await scan(content, file_name="prompt_injection_basic.md", use_urls=False)

        assert result.verdict != "CLEAN"
        llm_findings = [
            f for f in result.findings if f.detector_layer == DetectorLayer.LLM_ANALYZER
        ]
        assert len(llm_findings) > 0, "LLM should flag prompt injection, not obey it"

    async def test_exfil_soul_md(self) -> None:
        """Data exfiltration targeting SOUL.md should be detected."""
        content = _read_fixture("exfil_soul_md.md")
        result = await scan(content, file_name="exfil_soul_md.md", use_urls=False)

        assert result.verdict in ("MALICIOUS", "SUSPICIOUS")

    async def test_multi_stage_dropper(self) -> None:
        """Multi-stage malware dropper should be flagged."""
        content = _read_fixture("multi_stage_dropper.md")
        result = await scan(content, file_name="multi_stage_dropper.md", use_urls=False)

        assert result.verdict == "MALICIOUS"


# ---------------------------------------------------------------------------
# Tests: Benign content should stay clean
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLlmBenignDetection:
    """LLM layer should NOT produce false positives on clean fixtures."""

    async def test_hello_world_clean(self) -> None:
        """Simple hello world skill should remain CLEAN."""
        content = _read_fixture("hello_world.md", subdir="benign")
        result = await scan(content, file_name="hello_world.md", use_urls=False)

        assert result.verdict == "CLEAN"

    async def test_git_helper_clean(self) -> None:
        """Git helper skill should remain CLEAN."""
        content = _read_fixture("git_helper.md", subdir="benign")
        result = await scan(content, file_name="git_helper.md", use_urls=False)

        assert result.verdict == "CLEAN"

    async def test_code_formatter_clean(self) -> None:
        """Code formatter skill should remain CLEAN."""
        content = _read_fixture("code_formatter.md", subdir="benign")
        result = await scan(content, file_name="code_formatter.md", use_urls=False)

        assert result.verdict == "CLEAN"


# ---------------------------------------------------------------------------
# Tests: LLM response quality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLlmResponseQuality:
    """Verify the LLM returns well-structured, useful findings."""

    async def test_findings_have_evidence(self) -> None:
        """Every LLM finding should include evidence from the source content."""
        content = _read_fixture("clickfix_fake_prereq.md")
        result = await scan(content, file_name="clickfix_fake_prereq.md", use_urls=False)

        llm_findings = [
            f for f in result.findings if f.detector_layer == DetectorLayer.LLM_ANALYZER
        ]
        for finding in llm_findings:
            assert finding.evidence, f"Finding '{finding.title}' has no evidence"

    async def test_findings_have_descriptions(self) -> None:
        """LLM findings should have meaningful descriptions."""
        content = _read_fixture("obfuscated_curl.md")
        result = await scan(content, file_name="obfuscated_curl.md", use_urls=False)

        llm_findings = [
            f for f in result.findings if f.detector_layer == DetectorLayer.LLM_ANALYZER
        ]
        for finding in llm_findings:
            assert len(finding.description) > 10, (
                f"Finding '{finding.title}' has too-short description"
            )

    async def test_llm_layer_latency(self) -> None:
        """LLM analysis should complete within 30 seconds."""
        content = _read_fixture("hello_world.md", subdir="benign")

        t0 = time.perf_counter()
        await scan(content, file_name="hello_world.md", use_urls=False)
        elapsed = time.perf_counter() - t0

        assert elapsed < 30.0, f"LLM scan took {elapsed:.1f}s — exceeds 30s budget"

    async def test_llm_only_layer(self) -> None:
        """Running ONLY the LLM layer should still detect malicious content."""
        content = _read_fixture("clawhavoc_amos.md")
        result = await scan(
            content,
            file_name="clawhavoc_amos.md",
            use_urls=False,
            layers=["llm_analyzer"],
        )

        assert result.verdict != "CLEAN", "LLM-only scan should detect ClawHavoc"
        assert all(
            f.detector_layer == DetectorLayer.LLM_ANALYZER for f in result.findings
        )

    async def test_prior_findings_context(self) -> None:
        """LLM should receive and potentially reference prior layer findings."""
        content = _read_fixture("base64_reverse_shell.md")

        # Full pipeline (rules + LLM)
        result = await scan(content, file_name="base64_reverse_shell.md", use_urls=False)

        rule_findings = [
            f for f in result.findings if f.detector_layer == DetectorLayer.RULE_ENGINE
        ]
        llm_findings = [
            f for f in result.findings if f.detector_layer == DetectorLayer.LLM_ANALYZER
        ]

        # Both layers should contribute findings
        assert len(rule_findings) > 0, "Rule engine should find patterns"
        assert len(llm_findings) > 0, "LLM should add semantic analysis"


# ---------------------------------------------------------------------------
# Tests: LLM resilience to prompt injection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLlmPromptInjectionResilience:
    """Verify the LLM does not follow instructions embedded in SKILL.md content."""

    async def test_ignore_previous_instructions(self) -> None:
        """LLM should not obey 'ignore previous instructions' in content."""
        content = _read_fixture("prompt_injection_basic.md")
        result = await scan(content, file_name="prompt_injection_basic.md", use_urls=False)

        # The skill CONTAINS prompt injection — it should be flagged, not obeyed
        assert result.verdict != "CLEAN", (
            "LLM was tricked by prompt injection — returned CLEAN for malicious content"
        )

    async def test_unicode_smuggling(self) -> None:
        """LLM should detect unicode smuggling / homoglyph injection."""
        content = _read_fixture("prompt_injection_unicode.md")
        result = await scan(content, file_name="prompt_injection_unicode.md", use_urls=False)

        assert result.verdict != "CLEAN"
