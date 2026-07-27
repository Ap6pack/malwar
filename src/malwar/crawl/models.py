"""Pydantic models for ClawHub API responses."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


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

    @field_validator("display_name", "summary", mode="before")
    @classmethod
    def _none_to_empty_string(cls, v: object) -> object:
        """Some registry entries send these text fields as explicit ``null``.

        A field default (e.g. ``summary: str = ""``) only applies when the key
        is *absent*; when the API sends the key with value ``null``, Pydantic
        still validates against the annotated type and rejects it. That single
        bad record used to abort parsing of the entire listing page (up to 250
        skills) since items were validated without per-item error handling —
        see the enumeration-truncation root cause in the monitor sweep.
        """
        return "" if v is None else v


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
    version: str | None = None
    updated_at: int | None = Field(default=None, alias="updatedAt")

    model_config = {"populate_by_name": True}

    @field_validator("display_name", "summary", mode="before")
    @classmethod
    def _none_to_empty_string(cls, v: object) -> object:
        """See SkillSummary._none_to_empty_string: the registry sends these
        text fields as explicit null often enough that this must be tolerated.
        """
        return "" if v is None else v
