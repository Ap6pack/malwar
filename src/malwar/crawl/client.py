# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Async HTTP client for the ClawHub skill registry API."""

from __future__ import annotations

import logging

import httpx

from malwar import __version__
from malwar.crawl.models import (
    ModerationInfo,
    SearchResult,
    SkillDetail,
    SkillSummary,
)

logger = logging.getLogger("malwar.crawl.client")

BASE_URL = "https://clawhub.ai/api/v1"
_TIMEOUT = 15.0
_USER_AGENT = f"malwar/{__version__}"


class ClawHubError(Exception):
    """Base error for ClawHub API failures."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class SkillNotFoundError(ClawHubError):
    """Raised when a skill slug does not exist."""


class SkillBlockedError(ClawHubError):
    """Raised when a skill is blocked by moderation."""


class RateLimitError(ClawHubError):
    """Raised when the API returns 429 Too Many Requests."""


def _check_response(resp: httpx.Response, context: str = "") -> None:
    """Raise a typed error for non-2xx responses."""
    if resp.is_success:
        return
    msg = f"{context}: HTTP {resp.status_code}" if context else f"HTTP {resp.status_code}"
    try:
        body = resp.text[:200]
        if body:
            msg = f"{msg} — {body}"
    except Exception:
        pass
    if resp.status_code == 404:
        raise SkillNotFoundError(msg, status_code=404)
    if resp.status_code == 429:
        raise RateLimitError(msg, status_code=429)
    if resp.status_code in (403, 410, 423):
        raise SkillBlockedError(msg, status_code=resp.status_code)
    raise ClawHubError(msg, status_code=resp.status_code)


class ClawHubClient:
    """Async client for the ClawHub public API.

    Parameters
    ----------
    base_url:
        Override the API base URL (useful for testing).
    timeout:
        HTTP timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = BASE_URL,
        timeout: float = _TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            headers={"User-Agent": _USER_AGENT},
        )

    async def list_skills(
        self,
        limit: int = 20,
        cursor: str | None = None,
    ) -> tuple[list[SkillSummary], str | None]:
        """List skills from the registry.

        Returns a tuple of (skills, next_cursor).
        """
        params: dict[str, str | int] = {"limit": limit}
        if cursor:
            params["cursor"] = cursor

        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/skills", params=params)

        _check_response(resp, "list skills")
        data = resp.json()

        items = []
        for item in data.get("items", []):
            # The list endpoint wraps each item — skill data may be at top level
            # or nested under a "skill" key depending on the response shape.
            skill_data = item.get("skill", item) if isinstance(item, dict) else item
            if isinstance(item, dict) and "latestVersion" in item and "latestVersion" not in skill_data:
                skill_data["latestVersion"] = item["latestVersion"]
            items.append(SkillSummary.model_validate(skill_data))

        return items, data.get("nextCursor")

    async def search(
        self,
        query: str,
        limit: int = 20,
    ) -> list[SearchResult]:
        """Search for skills by keyword."""
        async with self._client() as client:
            resp = await client.get(
                f"{self.base_url}/search",
                params={"q": query, "limit": limit},
            )

        _check_response(resp, f"search '{query}'")
        data = resp.json()

        return [
            SearchResult.model_validate(r)
            for r in data.get("results", [])
        ]

    async def get_skill(self, slug: str) -> SkillDetail:
        """Get full details for a skill by slug."""
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/skills/{slug}")

        _check_response(resp, f"get skill '{slug}'")
        data = resp.json()

        # The response nests the skill under a "skill" key
        skill_data = data.get("skill", data)
        detail = SkillDetail.model_validate(skill_data)

        # Attach additional top-level fields
        if owner_data := data.get("owner"):
            from malwar.crawl.models import OwnerInfo
            detail.owner = OwnerInfo.model_validate(owner_data)
        if mod_data := data.get("moderation"):
            detail.moderation = ModerationInfo.model_validate(mod_data)
        if data.get("latestVersion") and detail.latest_version is None:
            from malwar.crawl.models import VersionInfo
            detail.latest_version = VersionInfo.model_validate(data["latestVersion"])

        return detail

    async def get_skill_file(
        self,
        slug: str,
        path: str = "SKILL.md",
        version: str | None = None,
    ) -> str:
        """Fetch the raw content of a file from a skill.

        Parameters
        ----------
        slug:
            Skill identifier.
        path:
            File path within the skill (default: SKILL.md).
        version:
            Specific version string; defaults to latest.

        Returns
        -------
        str
            Raw file content.
        """
        params: dict[str, str] = {"path": path}
        if version:
            params["version"] = version

        async with self._client() as client:
            resp = await client.get(
                f"{self.base_url}/skills/{slug}/file",
                params=params,
            )

        _check_response(resp, f"get file '{path}' from '{slug}'")
        return resp.text


async def fetch_url(url: str, request_timeout: float = _TIMEOUT) -> str:
    """Fetch raw content from any URL.

    Used by the ``crawl url`` command to scan SKILL.md files
    hosted on arbitrary sites.
    """
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(request_timeout),
        headers={"User-Agent": _USER_AGENT},
        follow_redirects=True,
    ) as client:
        resp = await client.get(url)

    if not resp.is_success:
        raise ClawHubError(
            f"Failed to fetch {url}: HTTP {resp.status_code}",
            status_code=resp.status_code,
        )
    return resp.text
