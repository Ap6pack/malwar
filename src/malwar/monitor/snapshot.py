"""Crawl the whole registry, scan every skill, and persist the result.

The sweep is deliberately cheap by default: every skill is scanned with the
rule engine + threat intel only (fast, free, deterministic). A skill is only
escalated to the (paid, slower) LLM analyzer when the fast pass already flags
it — so cost scales with the number of *suspicious* skills, not the size of
the registry.

It is also **incremental**: given the previous snapshot, a skill is only
re-fetched and re-scanned when the registry reports a new ``version`` or
``updated_at`` for it; unchanged skills are carried forward untouched. The
first run (or an explicit ``force_rescan``) scans everything; day-to-day runs
only pay for what actually changed.

Incremental detection trusts the registry's version/updated_at metadata, so a
*silent* same-version content swap would be missed — run a periodic full sweep
(``force_rescan=True``) to defend against that.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from malwar.crawl.client import ClawHubClient
from malwar.monitor.escalation import (
    EscalationBackend,
    EscalationPolicy,
    NoneBackend,
    is_fragile_detection,
    select_candidates,
)
from malwar.monitor.models import RegistrySnapshot, SkillRecord
from malwar.sdk import scan

logger = logging.getLogger("malwar.monitor")

# Risk score assigned when a fragile MALICIOUS verdict is downgraded: kept in the
# SUSPICIOUS band (40-74) and just under the MALICIOUS line so it still reads as
# high-suspicion, pending verification.
_FRAGILE_DOWNGRADE_RISK = 74

# Seed terms used to enumerate the registry when the /skills list endpoint
# returns empty (the same fallback the `crawl list` command relies on). Single
# letters + digits fan the search out across the catalog.
_SEED_TERMS: tuple[str, ...] = tuple("abcdefghijklmnopqrstuvwxyz0123456789")

ProgressCallback = Callable[[int, int, str], None]


class SkillMeta(NamedTuple):
    """Per-skill metadata harvested from the cheap list/search endpoints.

    Carrying this through means the sweep never needs a separate per-skill
    detail request: it decides whether a skill changed from ``version`` /
    ``updated_at``, and populates the record's display fields directly — so a
    scanned skill costs a single request (the file) instead of two.
    """

    slug: str
    version: str | None
    updated_at: int | None
    display_name: str = ""
    installs: int = 0


# Enumerating the full ~66k-skill registry is ~1,300 listing requests. The
# registry throttles sustained listing, so firing those pages as fast as
# possible trips the limit partway and truncates the enumeration. We therefore
# (a) pace the pages to stay under the throttle, and (b) retry a page that still
# fails, with a backoff long enough to outlast a throttle window.
#
# _PAGE_DELAY paces successive pages (~2 req/s, matching the registry's observed
# limit); the full listing then costs ~11 min, well within the run's time box.
_PAGE_DELAY = 0.5
# How many times to retry a single failed listing page before giving up.
_PAGE_RETRIES = 6
# Backoff (seconds) between page retries — extends past a typical throttle
# window so a rate-limited page recovers instead of aborting the sweep.
_PAGE_BACKOFF = (2, 5, 10, 20, 40, 60)


async def _enumerate_skills(
    client: ClawHubClient,
    *,
    max_skills: int | None,
    page_size: int,
) -> tuple[list[SkillMeta], bool]:
    """Return ``(skills, complete)`` for the registry listing.

    Pages through the list endpoint, retrying each page across transient
    failures (the registry rate-limits, so a long sweep will hit a 429/5xx
    mid-listing). ``complete`` is True only when paging reached the natural end
    with every page succeeding; it is False when a page still failed after
    retries, so the caller knows the list is partial and must not treat absent
    skills as removed. If the listing yields nothing at all, falls back to
    fanning search queries across seed terms (best-effort, always ``complete``
    False since it can't guarantee coverage).
    """
    metas: list[SkillMeta] = []
    seen: set[str] = set()

    cursor: str | None = None
    while True:
        items = None
        for attempt in range(_PAGE_RETRIES):
            try:
                items, cursor = await client.list_skills(limit=page_size, cursor=cursor)
                break
            except Exception as exc:  # ClawHubError, httpx timeouts after retries, etc.
                logger.warning(
                    "list_skills page failed (attempt %d/%d): %s",
                    attempt + 1,
                    _PAGE_RETRIES,
                    exc,
                )
                if attempt + 1 < _PAGE_RETRIES:
                    await asyncio.sleep(_PAGE_BACKOFF[min(attempt, len(_PAGE_BACKOFF) - 1)])
        if items is None:
            # Page still failing after retries: stop, but report the list as
            # PARTIAL so the caller preserves the baseline instead of dropping
            # everything we couldn't re-list this run.
            logger.error(
                "enumeration aborted after %d failed attempts on one page; "
                "returning a PARTIAL list of %d skills (baseline will be "
                "carried forward)",
                _PAGE_RETRIES,
                len(metas),
            )
            return metas, False
        for item in items:
            if item.slug not in seen:
                seen.add(item.slug)
                version = item.latest_version.version if item.latest_version else None
                metas.append(
                    SkillMeta(
                        slug=item.slug,
                        version=version,
                        updated_at=item.updated_at,
                        display_name=item.display_name,
                        installs=item.stats.installs_all_time,
                    )
                )
        if max_skills is not None and len(metas) >= max_skills:
            return metas[:max_skills], True
        if not cursor:
            return metas, True  # reached the natural end with every page ok
        # Pace the next page so sustained listing stays under the throttle.
        if _PAGE_DELAY:
            await asyncio.sleep(_PAGE_DELAY)

    # (unreachable: every branch above returns)


async def _enumerate_via_search(
    client: ClawHubClient,
    *,
    max_skills: int | None,
    page_size: int,
    seen: set[str],
) -> list[SkillMeta]:
    """Best-effort fallback: fan search queries across seed terms, de-duplicated."""
    metas: list[SkillMeta] = []
    for term in _SEED_TERMS:
        try:
            results = await client.search(term, limit=page_size)
        except Exception as exc:  # ClawHubError, httpx timeouts after retries, etc.
            logger.warning("search %r failed: %s", term, exc)
            continue
        for r in results:
            if r.slug not in seen:
                seen.add(r.slug)
                metas.append(
                    SkillMeta(
                        slug=r.slug,
                        version=r.version,
                        updated_at=r.updated_at,
                        display_name=r.display_name,
                    )
                )
        if max_skills is not None and len(metas) >= max_skills:
            return metas[:max_skills]
    return metas


def _is_unchanged(prev: SkillRecord | None, version: str | None, updated_at: int | None) -> bool:
    """True when a prior, cleanly-scanned record still matches the registry.

    A previously errored/unknown/stale record is treated as changed so it gets
    retried; otherwise we skip re-scanning when both version and updated_at
    match what the registry now reports. ``stale`` (a verdict carried forward
    because a prior run's budget couldn't reach it) must keep failing this
    check even though version/updated_at match — otherwise it would be
    mistaken for "confirmed unchanged" without ever having actually been
    re-scanned, and never converge to a fresh result.
    """
    if prev is None or prev.error is not None or prev.verdict == "UNKNOWN" or prev.stale:
        return False
    return prev.version == version and prev.updated_at == updated_at


async def _scan_slug(
    client: ClawHubClient, meta: SkillMeta
) -> tuple[SkillRecord, str | None]:
    """Fetch and rule-scan a single skill (the fast, free first pass).

    Metadata (version, updated_at, display name, installs) comes from the
    enumeration listing, so this makes just one request per skill — the file.
    Returns the record and the fetched content (or ``None`` on error) so a
    later escalation pass can re-analyze without re-fetching. Escalation itself
    is a separate, targeted phase (see :mod:`malwar.monitor.escalation`).
    """
    record = SkillRecord(
        slug=meta.slug,
        display_name=meta.display_name,
        version=meta.version,
        updated_at=meta.updated_at,
        installs=meta.installs,
    )

    try:
        content = await client.get_skill_file(meta.slug)
    except Exception as exc:  # ClawHubError, httpx timeouts, etc.
        record.error = f"file: {exc}"
        return record, None

    record.content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

    file_name = f"{meta.slug}/SKILL.md"
    try:
        result = await scan(content, file_name=file_name, use_llm=False, use_urls=False)
    except Exception as exc:  # a single bad skill must not kill the whole sweep
        record.error = f"scan: {exc}"
        return record, None

    record.verdict = result.verdict
    record.risk_score = result.risk_score
    record.ml_risk_score = result.ml_risk_score
    record.finding_rule_ids = sorted({f.rule_id for f in result.findings})
    return record, content


def _pending_record(meta: SkillMeta, *, prior: SkillRecord | None = None) -> SkillRecord:
    """A placeholder for a skill deferred to a later run.

    When ``prior`` holds a real prior scan result, it is carried forward
    (marked ``stale=True``) instead of being replaced with an UNKNOWN
    placeholder. This matters most for a full re-scan (``force_rescan``) on a
    registry too large to cover in one run's budget: without this, every skill
    outside this run's budget slice would have its last-known verdict wiped to
    UNKNOWN — silently erasing, for example, a previously-confirmed MALICIOUS
    finding just because a weekly full sweep didn't reach it yet. With no
    prior (first time seeing this skill), the placeholder is metadata-only
    with verdict UNKNOWN, as before.

    Either way ``_is_unchanged`` returns False for this record (verdict
    UNKNOWN, or the stale flag), so a later run re-scans it for real — this is
    how a budgeted baseline converges over successive runs without regressing
    in between.
    """
    if prior is not None:
        record = prior.model_copy(deep=True)
        record.display_name = meta.display_name
        record.version = meta.version
        record.updated_at = meta.updated_at
        record.installs = meta.installs
        record.stale = True
        return record
    return SkillRecord(
        slug=meta.slug,
        display_name=meta.display_name,
        version=meta.version,
        updated_at=meta.updated_at,
        installs=meta.installs,
        verdict="UNKNOWN",
    )


async def build_snapshot(
    client: ClawHubClient | None = None,
    *,
    previous: RegistrySnapshot | None = None,
    force_rescan: bool = False,
    max_skills: int | None = None,
    scan_budget: int | None = None,
    escalation: EscalationBackend | None = None,
    escalation_policy: EscalationPolicy | None = None,
    concurrency: int = 8,
    page_size: int = 50,
    on_progress: ProgressCallback | None = None,
) -> RegistrySnapshot:
    """Crawl and scan the registry into a :class:`RegistrySnapshot`.

    The sweep has two phases. Phase 1 rule-scans every (changed) skill — fast,
    free, one request each. Phase 2 gives a *targeted* second opinion: an
    :class:`~malwar.monitor.escalation.EscalationPolicy` picks only the skills in
    the ambiguous band (rules unsure, or rule-clean but ML-anomalous), and the
    ``escalation`` backend re-analyzes just those — so deep (paid) analysis is
    spent where it can change the verdict, not on every flagged skill.

    Parameters
    ----------
    client:
        A :class:`ClawHubClient`; a default one is created if omitted.
    previous:
        The last snapshot. When supplied (and ``force_rescan`` is False), skills
        whose version/updated_at are unchanged are carried forward without being
        re-fetched or re-scanned — so a daily run only pays for what changed.
    force_rescan:
        Ignore the "unchanged, skip re-scanning" fast path and attempt every
        skill (a full sweep). Use this on a periodic cadence to catch silent
        same-version content swaps. On a registry too large to fully re-scan
        within one run's ``scan_budget``, the skills it can't reach keep their
        last-known verdict (marked ``stale``, see ``scan_budget`` below)
        rather than losing it — a full sweep never regresses what's already
        known, it just may take several runs to fully refresh.
    max_skills:
        Cap the number of skills enumerated (for testing / partial runs).
    scan_budget:
        Cap how many skills are actually fetched + scanned this run. Any excess
        is deferred to a later run: a skill scanned before keeps its last-known
        verdict (``stale=True``, still counted as flagged if it was) instead of
        being reset to UNKNOWN; a skill never scanned before gets an UNKNOWN
        placeholder. Either way it's picked up again on a subsequent run — so a
        registry too large to sweep within one run's time limit builds up (and
        stays current) over successive runs rather than being lost to, or
        wiped by, an all-or-nothing timeout.
    escalation:
        Second-opinion backend for the ambiguous band (``None`` / ``NoneBackend``
        disables phase 2). See :func:`malwar.monitor.escalation.make_backend`.
    escalation_policy:
        Which first-pass records qualify for escalation; defaults to
        :class:`~malwar.monitor.escalation.EscalationPolicy`.
    concurrency:
        Maximum number of skills scanned in parallel.
    on_progress:
        Optional callback ``(done, total, slug)`` for progress reporting.
    """
    client = client or ClawHubClient()
    metas, complete = await _enumerate_skills(client, max_skills=max_skills, page_size=page_size)
    if not metas:
        # Listing returned nothing at all — try the search fan-out (best-effort,
        # cannot guarantee coverage, so the result stays "incomplete").
        metas = await _enumerate_via_search(
            client, max_skills=max_skills, page_size=page_size, seen=set()
        )
        complete = False

    snapshot = RegistrySnapshot(registry=client.base_url)
    snapshot.enumerated_count = len(metas)
    snapshot.enumeration_complete = complete

    # Carry-forward guard: when the listing is incomplete, a previously-known
    # skill that simply wasn't re-listed this run must NOT be treated as removed.
    # Preserve its last record so one transient listing failure can't shrink the
    # baseline (this is the bug that collapsed 66k -> a few hundred after 07-06).
    enumerated_slugs = {m.slug for m in metas}
    if previous is not None and not complete:
        carried = 0
        for slug, rec in previous.skills.items():
            if slug not in enumerated_slugs:
                snapshot.skills[slug] = rec.model_copy(deep=True)
                carried += 1
        snapshot.carried_forward_count = carried
        if carried:
            logger.warning(
                "enumeration INCOMPLETE (%d listed vs %d previously known): "
                "carried forward %d skills to protect the baseline",
                len(metas),
                len(previous.skills),
                carried,
            )

    total = len(metas)
    if total == 0:
        # Nothing listed; any carried-forward baseline above still stands.
        return snapshot

    # last_known_skills is the true prior state regardless of force_rescan —
    # used only to seed deferred/pending placeholders (see _pending_record) so
    # a full re-scan's budget cap can never erase what we already knew about a
    # skill it didn't reach this run. prev_skills (below) governs the separate
    # "skip re-scanning, it's unchanged" fast path, which force_rescan is
    # meant to bypass — those two purposes must not share one dict.
    last_known_skills = previous.skills if previous is not None else {}
    prev_skills = previous.skills if (previous is not None and not force_rescan) else {}

    # Split the registry into "carry forward unchanged" and "must re-scan".
    to_scan: list[SkillMeta] = []
    for meta in metas:
        prev = prev_skills.get(meta.slug)
        if _is_unchanged(prev, meta.version, meta.updated_at):
            snapshot.skills[meta.slug] = prev.model_copy(deep=True)  # type: ignore[union-attr]
        else:
            to_scan.append(meta)

    # Enforce the per-run scan budget: defer the overflow to a later run.
    pending: list[SkillMeta] = []
    if scan_budget is not None and len(to_scan) > scan_budget:
        to_scan, pending = to_scan[:scan_budget], to_scan[scan_budget:]
        for meta in pending:
            snapshot.skills[meta.slug] = _pending_record(
                meta, prior=last_known_skills.get(meta.slug)
            )

    snapshot.reused_count = total - len(to_scan) - len(pending)
    snapshot.scanned_count = len(to_scan)
    snapshot.pending_count = len(pending)
    logger.info(
        "sweep: %d listed (complete=%s), %d to scan, %d reused unchanged, "
        "%d deferred (budget), %d carried forward",
        total,
        complete,
        snapshot.scanned_count,
        snapshot.reused_count,
        snapshot.pending_count,
        snapshot.carried_forward_count,
    )

    backend = escalation or NoneBackend()
    keep_content = not isinstance(backend, NoneBackend)
    contents: dict[str, str] = {}

    # --- Phase 1: rule-scan every skill (fast, free, one request each) ---
    semaphore = asyncio.Semaphore(max(1, concurrency))
    done = len(snapshot.skills)
    lock = asyncio.Lock()

    async def _worker(meta: SkillMeta) -> None:
        nonlocal done
        async with semaphore:
            try:
                record, content = await _scan_slug(client, meta)
            except Exception as exc:  # last-resort guard; never abort the sweep
                record = SkillRecord(slug=meta.slug, verdict="UNKNOWN", error=f"worker: {exc}")
                content = None
        async with lock:
            snapshot.skills[meta.slug] = record
            if record.error:
                snapshot.errors[meta.slug] = record.error
            if keep_content and content is not None:
                contents[meta.slug] = content
            done += 1
            if on_progress is not None:
                on_progress(done, total, meta.slug)

    await asyncio.gather(*(_worker(meta) for meta in to_scan))

    # --- Phase 2: targeted second opinion on the ambiguous band ---
    if keep_content and contents:
        policy = escalation_policy or EscalationPolicy()
        scanned = {slug: snapshot.skills[slug] for slug in contents}
        candidates = select_candidates(scanned, policy)
        snapshot.escalated_count = len(candidates)
        logger.info(
            "escalation: %d of %d scanned skills sent to '%s' backend",
            len(candidates),
            len(contents),
            backend.name,
        )

        esc_sem = asyncio.Semaphore(max(1, concurrency))

        async def _escalate(slug: str) -> None:
            async with esc_sem:
                try:
                    res = await backend.assess(contents[slug], file_name=f"{slug}/SKILL.md")
                except Exception as exc:  # a bad escalation must not abort the sweep
                    logger.warning("escalation failed for %s: %s", slug, exc)
                    return
            rec = snapshot.skills[slug]
            rec.escalation_backend = res.backend
            rec.escalation_verdict = res.verdict
            rec.escalation_score = res.score
            rec.llm_escalated = res.authoritative
            # A full-pipeline second opinion is authoritative — adopt its
            # verdict (it may raise a sneaky-clean, or clear a false positive).
            if res.authoritative and res.verdict:
                rec.verdict = res.verdict
                if res.score is not None:
                    rec.risk_score = round(res.score * 100)

        await asyncio.gather(*(_escalate(slug) for slug in candidates))

    # --- Fail-safe: downgrade unverified fragile-MALICIOUS verdicts ---
    # A MALICIOUS verdict resting on a single high-false-positive rule (see
    # is_fragile_malicious) is only kept if an authoritative second opinion
    # confirmed it. Otherwise — no backend ran, the backend was non-authoritative,
    # or it didn't reach this skill — we downgrade to SUSPICIOUS rather than
    # publish a conviction we cannot stand behind. This always runs, including
    # when escalation is disabled, so a rules-only sweep never over-convicts.
    downgraded = 0
    for meta in to_scan:
        record = snapshot.skills.get(meta.slug)
        if record is None or not is_fragile_detection(record):
            continue
        # Only ever downgrade: never touch a record that is already at or below
        # the fragile ceiling. Without this, a second opinion that
        # authoritatively *cleared* a skill (verdict CLEAN) would be dragged
        # back up to SUSPICIOUS here, since clearing it also means it was never
        # "confirmed MALICIOUS".
        if record.verdict != "MALICIOUS":
            continue
        confirmed = record.llm_escalated and record.escalation_verdict == "MALICIOUS"
        if not confirmed:
            record.verdict = "SUSPICIOUS"
            record.risk_score = min(record.risk_score, _FRAGILE_DOWNGRADE_RISK)
            downgraded += 1
    if downgraded:
        logger.info(
            "downgraded %d unverified single-rule MALICIOUS verdicts to SUSPICIOUS",
            downgraded,
        )
    snapshot.downgraded_count = downgraded

    return snapshot


class SnapshotStore:
    """Persists registry snapshots to a directory as JSON.

    ``latest.json`` always holds the most recent snapshot (the diff baseline);
    each run is also archived as ``snapshot-<date>.json`` so history is
    auditable — and, when the directory lives in the repo, ``git diff`` shows
    exactly what changed day over day.
    """

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    @property
    def latest_path(self) -> Path:
        return self.directory / "latest.json"

    def load_latest(self) -> RegistrySnapshot | None:
        """Load the previous snapshot, or ``None`` if this is the first run."""
        if not self.latest_path.exists():
            return None
        data = json.loads(self.latest_path.read_text(encoding="utf-8"))
        return RegistrySnapshot.model_validate(data)

    def save(self, snapshot: RegistrySnapshot, *, archive_date: str | None = None) -> Path:
        """Write ``latest.json`` plus a dated archive; return the archive path."""
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(snapshot.model_dump(), indent=2, sort_keys=True)

        self.latest_path.write_text(payload + "\n", encoding="utf-8")

        date = archive_date or snapshot.created_at[:10]
        archive_path = self.directory / f"snapshot-{date}.json"
        archive_path.write_text(payload + "\n", encoding="utf-8")
        return archive_path
