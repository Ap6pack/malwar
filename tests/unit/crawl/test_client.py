# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for the ClawHub API client."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from malwar.crawl.client import (
    ClawHubClient,
    ClawHubError,
    RateLimitError,
    SkillBlockedError,
    SkillNotFoundError,
    fetch_url,
)

_REQUEST = httpx.Request("GET", "https://clawhub.ai/api/v1/test")


def _json_response(data, status_code: int = 200) -> httpx.Response:
    """Build a mock httpx.Response with JSON body."""
    return httpx.Response(
        status_code=status_code,
        content=json.dumps(data).encode(),
        headers={"content-type": "application/json"},
        request=_REQUEST,
    )


def _text_response(text: str, status_code: int = 200) -> httpx.Response:
    """Build a mock httpx.Response with text body."""
    return httpx.Response(
        status_code=status_code,
        content=text.encode(),
        headers={"content-type": "text/plain"},
        request=_REQUEST,
    )


def _mock_client(response: httpx.Response) -> AsyncMock:
    """Create a mock async client that returns the given response."""
    mc = AsyncMock()
    mc.get = AsyncMock(return_value=response)
    mc.__aenter__ = AsyncMock(return_value=mc)
    mc.__aexit__ = AsyncMock(return_value=False)
    return mc


class TestListSkills:
    """Tests for ClawHubClient.list_skills()."""

    @pytest.mark.asyncio
    async def test_returns_skills_and_cursor(self):
        api_data = {
            "items": [
                {
                    "slug": "hello-world",
                    "displayName": "Hello World",
                    "summary": "A greeting skill",
                    "tags": {"latest": "1.0.0"},
                    "stats": {"downloads": 100, "stars": 5, "versions": 1,
                              "comments": 0, "installsAllTime": 0, "installsCurrent": 0},
                    "createdAt": 1700000000000,
                    "updatedAt": 1700000000000,
                    "latestVersion": {"version": "1.0.0", "createdAt": 1700000000000},
                },
            ],
            "nextCursor": "abc123",
        }

        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(_json_response(api_data))):
            skills, cursor = await client.list_skills(limit=10)

        assert len(skills) == 1
        assert skills[0].slug == "hello-world"
        assert skills[0].display_name == "Hello World"
        assert skills[0].stats.downloads == 100
        assert cursor == "abc123"

    @pytest.mark.asyncio
    async def test_empty_list(self):
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(
            _json_response({"items": [], "nextCursor": None})
        )):
            skills, cursor = await client.list_skills()

        assert skills == []
        assert cursor is None


class TestSearch:
    """Tests for ClawHubClient.search()."""

    @pytest.mark.asyncio
    async def test_returns_search_results(self):
        api_data = {
            "results": [
                {
                    "score": 9.5,
                    "slug": "hello-world",
                    "displayName": "Hello World",
                    "summary": "A greeting skill",
                    "version": "1.0.0",
                    "updatedAt": 1700000000000,
                },
            ],
        }

        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(_json_response(api_data))):
            results = await client.search("hello")

        assert len(results) == 1
        assert results[0].slug == "hello-world"
        assert results[0].score == 9.5

    @pytest.mark.asyncio
    async def test_empty_search(self):
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(
            _json_response({"results": []})
        )):
            results = await client.search("nonexistent")

        assert results == []


class TestGetSkill:
    """Tests for ClawHubClient.get_skill()."""

    @pytest.mark.asyncio
    async def test_returns_skill_detail(self):
        api_data = {
            "skill": {
                "slug": "beszel-check",
                "displayName": "Beszel Check",
                "summary": "Monitor servers via Beszel",
                "tags": {"latest": "1.0.0"},
                "stats": {"downloads": 865, "stars": 0, "versions": 1,
                          "comments": 0, "installsAllTime": 0, "installsCurrent": 0},
                "createdAt": 1700000000000,
                "updatedAt": 1700000000000,
            },
            "latestVersion": {"version": "1.0.0", "createdAt": 1700000000000},
            "owner": {"username": "testuser"},
            "moderation": {"isSuspicious": True, "isMalwareBlocked": False,
                           "isPendingScan": False, "isHiddenByMod": False,
                           "isRemoved": False},
        }

        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(_json_response(api_data))):
            detail = await client.get_skill("beszel-check")

        assert detail.slug == "beszel-check"
        assert detail.owner is not None
        assert detail.owner.username == "testuser"
        assert detail.moderation is not None
        assert detail.moderation.is_suspicious is True
        assert detail.moderation.is_malware_blocked is False
        assert detail.latest_version is not None
        assert detail.latest_version.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_skill_not_found(self):
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(
            _text_response("Skill not found", 404)
        )), pytest.raises(SkillNotFoundError):
            await client.get_skill("nonexistent")


class TestGetSkillFile:
    """Tests for ClawHubClient.get_skill_file()."""

    @pytest.mark.asyncio
    async def test_returns_file_content(self):
        skill_content = "---\nname: test-skill\n---\n# Test Skill\nDo something useful."

        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(
            _text_response(skill_content)
        )):
            content = await client.get_skill_file("test-skill")

        assert "# Test Skill" in content
        assert "name: test-skill" in content

    @pytest.mark.asyncio
    async def test_with_version(self):
        mc = _mock_client(_text_response("versioned content"))

        client = ClawHubClient()
        with patch.object(client, "_client", return_value=mc):
            content = await client.get_skill_file("test-skill", version="2.0.0")

        assert content == "versioned content"
        call_args = mc.get.call_args
        assert call_args[1]["params"]["version"] == "2.0.0"

    @pytest.mark.asyncio
    async def test_blocked_skill(self):
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(
            _text_response("Blocked for malware", 403)
        )), pytest.raises(SkillBlockedError):
            await client.get_skill_file("malicious-skill")


class TestErrorHandling:
    """Tests for error handling across the client."""

    @pytest.mark.asyncio
    async def test_rate_limit_error(self):
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(
            _text_response("Too Many Requests", 429)
        )):
            with pytest.raises(RateLimitError) as exc_info:
                await client.list_skills()
            assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_pending_scan_blocked(self):
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(
            _text_response("Pending security scan", 423)
        )):
            with pytest.raises(SkillBlockedError) as exc_info:
                await client.get_skill_file("pending-skill")
            assert exc_info.value.status_code == 423

    @pytest.mark.asyncio
    async def test_generic_server_error(self):
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(
            _text_response("Internal Server Error", 500)
        )):
            with pytest.raises(ClawHubError) as exc_info:
                await client.search("test")
            assert exc_info.value.status_code == 500


class TestFetchUrl:
    """Tests for the generic fetch_url function."""

    @pytest.mark.asyncio
    async def test_fetches_content(self):
        skill_content = "# My Skill\nDo things."
        mc = _mock_client(_text_response(skill_content))

        with patch("malwar.crawl.client.httpx.AsyncClient", return_value=mc):
            content = await fetch_url("https://example.com/SKILL.md")

        assert content == skill_content

    @pytest.mark.asyncio
    async def test_http_error(self):
        mc = _mock_client(_text_response("Not Found", 404))

        with patch("malwar.crawl.client.httpx.AsyncClient", return_value=mc), \
             pytest.raises(ClawHubError):
            await fetch_url("https://example.com/missing.md")
