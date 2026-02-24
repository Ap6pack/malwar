# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for the crawl CLI commands."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from malwar.cli.commands.crawl import app
from malwar.crawl.client import ClawHubError, SkillNotFoundError
from malwar.crawl.models import (
    ModerationInfo,
    OwnerInfo,
    SearchResult,
    SkillDetail,
    SkillStats,
    SkillSummary,
    VersionInfo,
)

runner = CliRunner()


def _make_summary(slug: str = "test-skill", name: str = "Test Skill") -> SkillSummary:
    return SkillSummary(
        slug=slug,
        displayName=name,
        summary="A test skill",
        tags={"latest": "1.0.0"},
        stats=SkillStats(
            downloads=100, stars=5, versions=1,
            comments=0, installsAllTime=0, installsCurrent=0,
        ),
        latestVersion=VersionInfo(version="1.0.0"),
    )


def _make_detail(slug: str = "test-skill") -> SkillDetail:
    return SkillDetail(
        slug=slug,
        displayName="Test Skill",
        summary="A test skill for testing",
        tags={"latest": "1.0.0"},
        stats=SkillStats(
            downloads=200, stars=10, versions=2,
            comments=0, installsAllTime=0, installsCurrent=0,
        ),
        latestVersion=VersionInfo(version="1.0.0"),
        owner=OwnerInfo(username="testauthor"),
        moderation=ModerationInfo(
            isSuspicious=False,
            isMalwareBlocked=False,
            isPendingScan=False,
            isHiddenByMod=False,
            isRemoved=False,
        ),
    )


def _mock_clawhub(**async_methods):
    """Create a MagicMock class that returns an instance with async methods."""
    instance = MagicMock()
    for name, return_value in async_methods.items():
        setattr(instance, name, AsyncMock(return_value=return_value))
    cls = MagicMock(return_value=instance)
    return cls, instance


def _clean_scan_result(target: str = "test"):
    from malwar.models.scan import ScanResult
    return ScanResult(
        scan_id="test-1",
        target=target,
        findings=[],
        skill_sha256="abc123",
        layers_executed=["rule_engine"],
    )


def _suspicious_scan_result():
    from malwar.models.finding import Finding
    from malwar.models.scan import ScanResult
    return ScanResult(
        scan_id="test-2",
        target="clawhub:sus/SKILL.md",
        findings=[
            Finding(
                id="MALWAR-TEST-001",
                rule_id="TEST-001",
                title="Test finding",
                description="A test finding for suspicious content",
                severity="high",
                confidence=0.9,
                category="prompt_injection",
                detector_layer="rule_engine",
            ),
        ],
        skill_sha256="def456",
        layers_executed=["rule_engine"],
    )


# ---------------------------------------------------------------------------
# crawl scan
# ---------------------------------------------------------------------------

class TestCrawlScan:
    """Tests for the crawl scan command."""

    def test_scan_clean_skill(self):
        cls, _ = _mock_clawhub(get_skill_file="# Safe Skill")

        with patch("malwar.crawl.client.ClawHubClient", cls), \
             patch("malwar.sdk.scan", new_callable=AsyncMock, return_value=_clean_scan_result()):
            result = runner.invoke(app, ["scan", "test-skill"])

        assert result.exit_code == 0

    def test_scan_suspicious_skill(self):
        cls, _ = _mock_clawhub(get_skill_file="# Suspicious")

        with patch("malwar.crawl.client.ClawHubClient", cls), \
             patch("malwar.sdk.scan", new_callable=AsyncMock, return_value=_suspicious_scan_result()):
            result = runner.invoke(app, ["scan", "sus-skill"])

        # Exit code 1 because risk_score >= 40
        assert result.exit_code == 1

    def test_scan_skill_not_found(self):
        cls, inst = _mock_clawhub()
        inst.get_skill_file = AsyncMock(
            side_effect=SkillNotFoundError("Skill not found", status_code=404),
        )

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["scan", "nonexistent"])

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_scan_with_version(self):
        cls, inst = _mock_clawhub(get_skill_file="# Versioned")

        with patch("malwar.crawl.client.ClawHubClient", cls), \
             patch("malwar.sdk.scan", new_callable=AsyncMock, return_value=_clean_scan_result()):
            result = runner.invoke(app, ["scan", "test-skill", "--version", "2.0.0"])

        assert result.exit_code == 0
        inst.get_skill_file.assert_called_once_with("test-skill", version="2.0.0")

    def test_scan_json_output(self):
        cls, _ = _mock_clawhub(get_skill_file="# Test")

        with patch("malwar.crawl.client.ClawHubClient", cls), \
             patch("malwar.sdk.scan", new_callable=AsyncMock, return_value=_clean_scan_result()):
            result = runner.invoke(app, ["scan", "test", "--format", "json"])

        assert result.exit_code == 0
        assert "scan_id" in result.output


# ---------------------------------------------------------------------------
# crawl search
# ---------------------------------------------------------------------------

class TestCrawlSearch:
    """Tests for the crawl search command."""

    def test_search_with_results(self):
        results = [
            SearchResult(
                score=9.5,
                slug="hello-world",
                displayName="Hello World",
                summary="A greeting skill",
                version="1.0.0",
            ),
        ]
        cls, _ = _mock_clawhub(search=results)

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["search", "hello"])

        assert result.exit_code == 0
        assert "hello-world" in result.output
        assert "Hello World" in result.output

    def test_search_no_results(self):
        cls, _ = _mock_clawhub(search=[])

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["search", "nonexistent"])

        assert result.exit_code == 0
        assert "No skills found" in result.output

    def test_search_api_error(self):
        cls, inst = _mock_clawhub()
        inst.search = AsyncMock(side_effect=ClawHubError("Server error", status_code=500))

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["search", "test"])

        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# crawl list
# ---------------------------------------------------------------------------

class TestCrawlList:
    """Tests for the crawl list command."""

    def test_list_skills(self):
        skills = [_make_summary("skill-a", "Skill A"), _make_summary("skill-b", "Skill B")]
        cls, _ = _mock_clawhub(list_skills=(skills, "next-cursor"))

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["list"])

        assert result.exit_code == 0
        assert "skill-a" in result.output
        assert "skill-b" in result.output
        assert "Next page" in result.output

    def test_list_no_next_page(self):
        skills = [_make_summary()]
        cls, _ = _mock_clawhub(list_skills=(skills, None))

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["list"])

        assert result.exit_code == 0
        assert "Next page" not in result.output

    def test_list_empty(self):
        cls, _ = _mock_clawhub(list_skills=([], None))

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["list"])

        assert result.exit_code == 0
        assert "No skills found" in result.output


# ---------------------------------------------------------------------------
# crawl info
# ---------------------------------------------------------------------------

class TestCrawlInfo:
    """Tests for the crawl info command."""

    def test_info_clean_skill(self):
        detail = _make_detail()
        cls, _ = _mock_clawhub(get_skill=detail)

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["info", "test-skill"])

        assert result.exit_code == 0
        assert "test-skill" in result.output
        assert "testauthor" in result.output
        assert "No flags" in result.output

    def test_info_suspicious_skill(self):
        detail = _make_detail()
        detail.moderation = ModerationInfo(
            isSuspicious=True,
            isMalwareBlocked=False,
            isPendingScan=False,
            isHiddenByMod=False,
            isRemoved=False,
        )
        cls, _ = _mock_clawhub(get_skill=detail)

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["info", "test-skill"])

        assert result.exit_code == 0
        assert "SUSPICIOUS" in result.output

    def test_info_malware_blocked_skill(self):
        detail = _make_detail()
        detail.moderation = ModerationInfo(
            isSuspicious=False,
            isMalwareBlocked=True,
            isPendingScan=False,
            isHiddenByMod=False,
            isRemoved=False,
        )
        cls, _ = _mock_clawhub(get_skill=detail)

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["info", "test-skill"])

        assert result.exit_code == 0
        assert "BLOCKED" in result.output

    def test_info_not_found(self):
        cls, inst = _mock_clawhub()
        inst.get_skill = AsyncMock(
            side_effect=SkillNotFoundError("Not found", status_code=404),
        )

        with patch("malwar.crawl.client.ClawHubClient", cls):
            result = runner.invoke(app, ["info", "nonexistent"])

        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# crawl url
# ---------------------------------------------------------------------------

class TestCrawlUrl:
    """Tests for the crawl url command."""

    def test_url_clean_skill(self):
        with patch("malwar.crawl.client.fetch_url", new_callable=AsyncMock, return_value="# Remote Skill"), \
             patch("malwar.sdk.scan", new_callable=AsyncMock, return_value=_clean_scan_result()):
            result = runner.invoke(app, ["url", "https://example.com/SKILL.md"])

        assert result.exit_code == 0

    def test_url_fetch_error(self):
        with patch(
            "malwar.crawl.client.fetch_url",
            new_callable=AsyncMock,
            side_effect=ClawHubError("HTTP 404", status_code=404),
        ):
            result = runner.invoke(app, ["url", "https://example.com/missing.md"])

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_url_network_error(self):
        with patch(
            "malwar.crawl.client.fetch_url",
            new_callable=AsyncMock,
            side_effect=ConnectionError("Connection refused"),
        ):
            result = runner.invoke(app, ["url", "https://example.com/SKILL.md"])

        assert result.exit_code == 1
        assert "Error" in result.output
