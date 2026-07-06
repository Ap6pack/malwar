"""Models for registry snapshots and snapshot diffs."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

# Verdicts considered a security concern when a skill lands on them.
FLAGGED_VERDICTS: frozenset[str] = frozenset({"MALICIOUS", "SUSPICIOUS", "CAUTION"})

# Ordering used to decide whether a verdict change is a regression (worse) or
# an improvement (better).
_VERDICT_RANK: dict[str, int] = {
    "CLEAN": 0,
    "UNKNOWN": 0,
    "CAUTION": 1,
    "SUSPICIOUS": 2,
    "MALICIOUS": 3,
}


def verdict_rank(verdict: str) -> int:
    """Return an ordinal severity rank for a verdict string (higher = worse)."""
    return _VERDICT_RANK.get(verdict.upper().strip(), 0)


class SkillRecord(BaseModel):
    """A single skill's scanned state at snapshot time.

    Keyed by ``slug`` in a :class:`RegistrySnapshot`. Everything needed to
    detect a meaningful change day-over-day lives here: the published version,
    a content hash of the SKILL.md, and the scan verdict.
    """

    slug: str
    display_name: str = ""
    publisher: str = ""
    version: str | None = None
    updated_at: int | None = None
    content_sha256: str | None = None
    verdict: str = "UNKNOWN"
    risk_score: int = 0
    finding_rule_ids: list[str] = Field(default_factory=list)
    installs: int = 0
    llm_escalated: bool = False
    moderation_blocked: bool = False
    moderation_suspicious: bool = False
    scanned_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    error: str | None = None

    @property
    def is_flagged(self) -> bool:
        return self.verdict.upper().strip() in FLAGGED_VERDICTS


class RegistrySnapshot(BaseModel):
    """A point-in-time scan of every skill in the registry."""

    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    registry: str = ""
    skills: dict[str, SkillRecord] = Field(default_factory=dict)
    # Slugs the crawl knew about but failed to fetch/scan, for transparency.
    errors: dict[str, str] = Field(default_factory=dict)
    # How this snapshot was built: skills actually fetched + scanned this run
    # vs. carried forward unchanged from the previous snapshot (incremental).
    scanned_count: int = 0
    reused_count: int = 0

    @property
    def skill_count(self) -> int:
        return len(self.skills)

    @property
    def flagged_count(self) -> int:
        return sum(1 for r in self.skills.values() if r.is_flagged)


class SkillChange(BaseModel):
    """A single detected change between two snapshots."""

    slug: str
    kind: str  # "modified" | "verdict_changed"
    detail: str
    old: SkillRecord | None = None
    new: SkillRecord | None = None


class SnapshotDiff(BaseModel):
    """The security-relevant delta between a previous and current snapshot."""

    previous_created_at: str | None = None
    current_created_at: str = ""
    added: list[SkillRecord] = Field(default_factory=list)
    removed: list[SkillRecord] = Field(default_factory=list)
    modified: list[SkillChange] = Field(default_factory=list)
    verdict_changed: list[SkillChange] = Field(default_factory=list)
    # The headline list: skills that became flagged (new or regressed).
    newly_malicious: list[SkillRecord] = Field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added
            or self.removed
            or self.modified
            or self.verdict_changed
        )

    @property
    def is_first_run(self) -> bool:
        return self.previous_created_at is None
