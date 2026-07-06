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
from malwar.monitor.models import RegistrySnapshot, SkillRecord
from malwar.sdk import scan

logger = logging.getLogger("malwar.monitor")

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


async def _enumerate_skills(
    client: ClawHubClient,
    *,
    max_skills: int | None,
    page_size: int,
) -> list[SkillMeta]:
    """Return :class:`SkillMeta` for every skill in the registry.

    Pages through the list endpoint; if that yields nothing (the endpoint is
    known to return empty at times), falls back to fanning search queries out
    across seed terms and de-duplicating. The metadata comes free with the
    listing, so change detection and record population need no per-skill fetch.
    """
    metas: list[SkillMeta] = []
    seen: set[str] = set()

    cursor: str | None = None
    while True:
        try:
            items, cursor = await client.list_skills(limit=page_size, cursor=cursor)
        except Exception as exc:  # ClawHubError, httpx timeouts after retries, etc.
            logger.warning("list_skills failed: %s", exc)
            break
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
            return metas[:max_skills]
        if not cursor:
            break

    if metas:
        return metas

    # Fallback: broad search fan-out (search results carry no install stats).
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

    A previously errored/unknown record is treated as changed so it gets
    retried; otherwise we skip re-scanning when both version and updated_at
    match what the registry now reports.
    """
    if prev is None or prev.error is not None or prev.verdict == "UNKNOWN":
        return False
    return prev.version == version and prev.updated_at == updated_at


async def _scan_slug(client: ClawHubClient, meta: SkillMeta, *, escalate: bool) -> SkillRecord:
    """Fetch and scan a single skill, escalating to the LLM only if flagged.

    Metadata (version, updated_at, display name, installs) comes from the
    enumeration listing, so this makes just one request per skill — the file.
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
        return record

    record.content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

    file_name = f"{meta.slug}/SKILL.md"
    try:
        result = await scan(content, file_name=file_name, use_llm=False, use_urls=False)
        if escalate and result.verdict != "CLEAN":
            result = await scan(content, file_name=file_name, use_llm=True, use_urls=True)
            record.llm_escalated = True
    except Exception as exc:  # a single bad skill must not kill the whole sweep
        record.error = f"scan: {exc}"
        return record

    record.verdict = result.verdict
    record.risk_score = result.risk_score
    record.finding_rule_ids = sorted({f.rule_id for f in result.findings})
    return record


def _pending_record(meta: SkillMeta) -> SkillRecord:
    """A metadata-only placeholder for a skill deferred to a later run.

    Verdict is UNKNOWN with no error, so ``_is_unchanged`` returns False and the
    next run re-scans it — this is how a budgeted baseline converges over
    successive runs.
    """
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
    escalate: bool = True,
    concurrency: int = 8,
    page_size: int = 50,
    on_progress: ProgressCallback | None = None,
) -> RegistrySnapshot:
    """Crawl and scan the registry into a :class:`RegistrySnapshot`.

    Parameters
    ----------
    client:
        A :class:`ClawHubClient`; a default one is created if omitted.
    previous:
        The last snapshot. When supplied (and ``force_rescan`` is False), skills
        whose version/updated_at are unchanged are carried forward without being
        re-fetched or re-scanned — so a daily run only pays for what changed.
    force_rescan:
        Ignore ``previous`` and re-scan every skill (a full sweep). Use this on
        a periodic cadence to catch silent same-version content swaps.
    max_skills:
        Cap the number of skills enumerated (for testing / partial runs).
    scan_budget:
        Cap how many skills are actually fetched + scanned this run. Any excess
        is recorded as an UNKNOWN placeholder and picked up on the next run, so a
        registry too large to sweep within one run's time limit is built up over
        successive runs rather than lost to an all-or-nothing timeout.
    escalate:
        Re-scan flagged skills with the full LLM + URL pipeline.
    concurrency:
        Maximum number of skills scanned in parallel.
    on_progress:
        Optional callback ``(done, total, slug)`` for progress reporting.
    """
    client = client or ClawHubClient()
    metas = await _enumerate_skills(client, max_skills=max_skills, page_size=page_size)

    snapshot = RegistrySnapshot(registry=client.base_url)
    total = len(metas)
    if total == 0:
        return snapshot

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
            snapshot.skills[meta.slug] = _pending_record(meta)

    snapshot.reused_count = total - len(to_scan) - len(pending)
    snapshot.scanned_count = len(to_scan)
    snapshot.pending_count = len(pending)
    logger.info(
        "sweep: %d skills total, %d to scan, %d reused unchanged, %d deferred (budget)",
        total,
        snapshot.scanned_count,
        snapshot.reused_count,
        snapshot.pending_count,
    )

    semaphore = asyncio.Semaphore(max(1, concurrency))
    done = len(snapshot.skills)
    lock = asyncio.Lock()

    async def _worker(meta: SkillMeta) -> None:
        nonlocal done
        async with semaphore:
            try:
                record = await _scan_slug(client, meta, escalate=escalate)
            except Exception as exc:  # last-resort guard; never abort the sweep
                record = SkillRecord(slug=meta.slug, verdict="UNKNOWN", error=f"worker: {exc}")
        async with lock:
            snapshot.skills[meta.slug] = record
            if record.error:
                snapshot.errors[meta.slug] = record.error
            done += 1
            if on_progress is not None:
                on_progress(done, total, meta.slug)

    await asyncio.gather(*(_worker(meta) for meta in to_scan))
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
