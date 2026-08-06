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
    # The registry's immutable account id. Handles can be renamed by their
    # owner, so clustering a campaign on the handle alone can split one operator
    # in two or merge two that reused a name.
    publisher_id: str = ""
    version: str | None = None
    updated_at: int | None = None
    content_sha256: str | None = None
    verdict: str = "UNKNOWN"
    risk_score: int = 0
    finding_rule_ids: list[str] = Field(default_factory=list)
    installs: int = 0
    # ML anomaly probability [0,1] from the first (rules) pass — a cheap signal
    # for "looks clean but off" skills that drives targeted escalation.
    ml_risk_score: float | None = None
    llm_escalated: bool = False
    # Targeted escalation outcome (see monitor.escalation). Which second-opinion
    # backend ran on this skill, its verdict, and its confidence — empty when the
    # skill wasn't in the ambiguous band or escalation was disabled.
    escalation_backend: str = ""
    escalation_verdict: str = ""
    escalation_score: float | None = None
    # ClawHub's own moderation state, fetched for flagged skills only (see the
    # enrichment phase in monitor.snapshot). Lets us compare our verdict against
    # the platform's: a skill we verify malicious that the platform has not
    # blocked is a gap in *their* screening, and distinguishing "scanned and not
    # blocked" from "not scanned yet" needs the pending flag as well.
    moderation_blocked: bool = False
    moderation_suspicious: bool = False
    moderation_pending: bool = False
    # The registry's own verdict string (e.g. "clean"). Authoritative: the
    # booleans above are derived from it, and reading them instead means
    # inferring a verdict from flags that default False.
    moderation_verdict: str = ""
    # Which screening engine produced that verdict and when. A skill cleared by
    # an engine several versions old is a different claim from one cleared
    # today, and neither is visible from the verdict alone.
    moderation_engine: str = ""
    moderation_scanned_at: int | None = None
    # True once the detail response actually carried a moderation block, so an
    # unenriched record is never mistaken for "platform says it is fine". A
    # successful fetch that omits moderation leaves this False: every flag
    # defaults False, so treating the absence of data as the absence of a flag
    # turns silence into a clean bill of health.
    moderation_checked: bool = False
    # True once the detail endpoint was fetched at all, whatever it returned.
    # Kept separate from moderation_checked so the backfill can tell "not asked
    # yet" from "asked, got nothing useful" — without it, a registry that never
    # returns moderation data would re-request the same skills every run.
    detail_fetched: bool = False
    scanned_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    error: str | None = None
    # True when this record's verdict was carried forward from a prior scan
    # because the current run's budget couldn't reach it (e.g. a full re-scan
    # of a registry too large to cover in one run). The verdict is real — it
    # came from an actual scan — but it may now be outdated, and the skill is
    # due for a fresh look on a subsequent run. Kept distinct from verdict
    # "UNKNOWN" so a previously-confirmed MALICIOUS finding is never silently
    # dropped just because this run didn't get to it.
    stale: bool = False

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
    # vs. carried forward unchanged from the previous snapshot (incremental)
    # vs. deferred to a later run because a per-run scan budget was hit
    # (recorded as UNKNOWN placeholders so the next run picks them up).
    scanned_count: int = 0
    reused_count: int = 0
    pending_count: int = 0
    # Skills sent to a second-opinion escalation backend this run.
    escalated_count: int = 0
    # Fragile single-rule MALICIOUS verdicts downgraded to SUSPICIOUS this run
    # because no authoritative second opinion confirmed them.
    downgraded_count: int = 0
    # Registry enumeration health. ``enumerated_count`` is how many skills the
    # listing returned this run; ``enumeration_complete`` is False when paging
    # aborted early (e.g. a rate-limit/5xx mid-listing). On an incomplete
    # enumeration, previously-known skills are carried forward instead of being
    # dropped, so a transient listing failure can't silently shrink the baseline.
    enumerated_count: int = 0
    enumeration_complete: bool = True
    carried_forward_count: int = 0

    @property
    def skill_count(self) -> int:
        return len(self.skills)

    @property
    def flagged_count(self) -> int:
        return sum(1 for r in self.skills.values() if r.is_flagged)

    @property
    def stale_count(self) -> int:
        """Skills whose verdict is carried forward and due for a fresh scan."""
        return sum(1 for r in self.skills.values() if r.stale)

    @property
    def attributed_count(self) -> int:
        """Skills whose publisher and platform moderation state we have fetched."""
        return sum(1 for r in self.skills.values() if r.moderation_checked)

    @property
    def unblocked_malicious_count(self) -> int:
        """Skills we verified malicious that the platform screened and called clean.

        Requires the registry's own ``verdict`` to actually say "clean". That is
        the authoritative field; the boolean flags are derived from it and all
        default False, so a record we never checked, or one whose response
        carried no moderation block, would otherwise be counted as the platform
        vouching for a skill it never looked at. Anything the platform flagged
        at all -- blocked, suspicious, or still pending -- is not a miss.
        """
        return sum(
            1
            for r in self.skills.values()
            if r.verdict == "MALICIOUS"
            and r.moderation_checked
            and r.moderation_verdict.lower() == "clean"
            and not r.moderation_blocked
            and not r.moderation_pending
            and not r.moderation_suspicious
        )

    @property
    def unscreened_malicious_count(self) -> int:
        """Skills we verified malicious that carry no moderation record at all.

        Distinct from the gap above: the platform did not clear these, it has
        no screening result for them. Only counts skills we actually fetched,
        so "we never asked" never masquerades as "they never screened".
        """
        return sum(
            1
            for r in self.skills.values()
            if r.verdict == "MALICIOUS" and r.detail_fetched and not r.moderation_checked
        )


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
