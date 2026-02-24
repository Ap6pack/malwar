# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Pydantic models for ClawHub API responses."""

from __future__ import annotations

from pydantic import BaseModel, Field


class VersionInfo(BaseModel):
    """Skill version metadata."""

    version: str
    created_at: int | None = Field(default=None, alias="createdAt")
    changelog: str | None = None


class SkillStats(BaseModel):
    """Skill usage statistics."""

    comments: int = 0
    downloads: int = 0
    installs_all_time: int = Field(default=0, alias="installsAllTime")
    installs_current: int = Field(default=0, alias="installsCurrent")
    stars: int = 0
    versions: int = 0


class SkillSummary(BaseModel):
    """Skill summary returned by the list endpoint."""

    slug: str
    display_name: str = Field(alias="displayName")
    summary: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    stats: SkillStats = Field(default_factory=SkillStats)
    created_at: int | None = Field(default=None, alias="createdAt")
    updated_at: int | None = Field(default=None, alias="updatedAt")
    latest_version: VersionInfo | None = Field(default=None, alias="latestVersion")

    model_config = {"populate_by_name": True}


class ModerationInfo(BaseModel):
    """Moderation flags from ClawHub's security scanning."""

    is_pending_scan: bool = Field(default=False, alias="isPendingScan")
    is_malware_blocked: bool = Field(default=False, alias="isMalwareBlocked")
    is_suspicious: bool = Field(default=False, alias="isSuspicious")
    is_hidden_by_mod: bool = Field(default=False, alias="isHiddenByMod")
    is_removed: bool = Field(default=False, alias="isRemoved")
    reason: str | None = None

    model_config = {"populate_by_name": True}


class OwnerInfo(BaseModel):
    """Skill owner/publisher info."""

    username: str = ""


class SkillDetail(BaseModel):
    """Full skill detail returned by the get-by-slug endpoint."""

    slug: str
    display_name: str = Field(alias="displayName")
    summary: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    stats: SkillStats = Field(default_factory=SkillStats)
    created_at: int | None = Field(default=None, alias="createdAt")
    updated_at: int | None = Field(default=None, alias="updatedAt")
    latest_version: VersionInfo | None = Field(default=None, alias="latestVersion")
    owner: OwnerInfo | None = None
    moderation: ModerationInfo | None = None

    model_config = {"populate_by_name": True}


class SearchResult(BaseModel):
    """Single search result from the search endpoint."""

    score: float = 0.0
    slug: str
    display_name: str = Field(alias="displayName")
    summary: str = ""
    version: str = ""
    updated_at: int | None = Field(default=None, alias="updatedAt")

    model_config = {"populate_by_name": True}
