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

    @pytest.mark.asyncio
    async def test_null_summary_and_display_name_are_tolerated(self):
        # Root cause of the enumeration-truncation bug: the live registry
        # sends "summary": null for some entries. Pydantic rejects None
        # against `str` even with a "" default (the default only applies when
        # the key is absent), so this used to raise and drop the whole page.
        api_data = {
            "items": [
                {"slug": "a", "displayName": "A", "summary": None},
                {"slug": "b", "displayName": None, "summary": None},
            ],
            "nextCursor": None,
        }
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(_json_response(api_data))):
            skills, _ = await client.list_skills()

        assert len(skills) == 2
        assert skills[0].summary == ""
        assert skills[1].display_name == "" and skills[1].summary == ""

    @pytest.mark.asyncio
    async def test_one_malformed_item_does_not_drop_the_whole_page(self):
        # A record that's still invalid after the null-tolerance fix (e.g.
        # missing the required "slug") must be skipped, not abort parsing of
        # the other 249 (or however many) valid items on the same page.
        api_data = {
            "items": [
                {"slug": "good1", "displayName": "Good 1"},
                {"displayName": "Missing slug"},  # slug is required -> invalid
                {"slug": "good2", "displayName": "Good 2"},
            ],
            "nextCursor": None,
        }
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(_json_response(api_data))):
            skills, _cursor = await client.list_skills()

        assert [s.slug for s in skills] == ["good1", "good2"]


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

    @pytest.mark.asyncio
    async def test_null_text_fields_and_malformed_item_handled(self):
        api_data = {
            "results": [
                {"slug": "a", "displayName": None, "summary": None},
                {"displayName": "Missing slug"},  # invalid, must be skipped
                {"slug": "b", "displayName": "B", "summary": "ok"},
            ],
        }
        client = ClawHubClient()
        with patch.object(client, "_client", return_value=_mock_client(_json_response(api_data))):
            results = await client.search("q")

        assert [r.slug for r in results] == ["a", "b"]
        assert results[0].display_name == "" and results[0].summary == ""


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


class TestConnectionResilience:
    """The client retries transient connection failures at the transport level."""

    def test_defaults_to_retrying_transport(self):
        client = ClawHubClient()
        assert client.retries == 3
        # _client() wires the retrying transport without error.
        real = client._client()
        assert isinstance(real, httpx.AsyncClient)

    def test_retries_configurable(self):
        assert ClawHubClient(retries=0).retries == 0
        assert ClawHubClient(retries=5).retries == 5


class TestGetSkillRealResponseShape:
    """Pin the layout the registry actually returns, not the one we assumed.

    The pre-existing test for get_skill asserts an owner shaped
    ``{"username": ...}``. The live endpoint returns ``{"handle": ...}``, and
    because pydantic ignores unknown keys, validating one against the other
    succeeds and yields an empty username. That is why a full sweep attributed
    992 skills to nobody while every test passed. This response body is copied
    from an actual API reply.
    """

    LIVE_RESPONSE = {
        "skill": {
            "slug": "accountant",
            "displayName": "Accountant",
            "summary": "a summary",
            "icon": None,
            "description": "a description",
            "tags": {"latest": "1.0.0"},
            "stats": {"comments": 0, "downloads": 12, "installs": 0,
                      "stars": 0, "versions": 1},
            "createdAt": 1700000000000,
            "updatedAt": 1700000000000,
        },
        "latestVersion": {"version": "1.0.0", "createdAt": 1700000000000,
                          "changelog": "", "license": "MIT"},
        "metadata": {"setup": [], "os": ["linux", "darwin", "win32"], "systems": None},
        "owner": {
            "handle": "ivangdavila",
            "userId": "s178jdk12x4qj3gs2se3etxf3h83h7ft",
            "displayName": "Iván",
            "image": "https://avatars.githubusercontent.com/u/81719670?v=4",
        },
        # Present as a key, but null. Absence of a moderation block is not the
        # platform saying a skill is fine.
        "moderation": None,
    }

    @pytest.mark.asyncio
    async def test_owner_handle_is_read_as_the_publisher(self):
        client = ClawHubClient()
        with patch.object(
            client, "_client",
            return_value=_mock_client(_json_response(self.LIVE_RESPONSE)),
        ):
            detail = await client.get_skill("accountant")

        assert detail.owner is not None
        assert detail.owner.username == "ivangdavila"
        assert detail.owner.user_id == "s178jdk12x4qj3gs2se3etxf3h83h7ft"
        assert detail.owner.display_name == "Iván"

    @pytest.mark.asyncio
    async def test_null_moderation_stays_none(self):
        client = ClawHubClient()
        with patch.object(
            client, "_client",
            return_value=_mock_client(_json_response(self.LIVE_RESPONSE)),
        ):
            detail = await client.get_skill("accountant")

        # Not a ModerationInfo with everything False, which would read as a
        # clean bill of health from a platform that told us nothing.
        assert detail.moderation is None
