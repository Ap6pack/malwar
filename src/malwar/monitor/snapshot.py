"""Crawl the whole registry, scan every skill, and persist the result.

The sweep is deliberately cheap by default: every skill is scanned with the
rule engine + threat intel only (fast, free, deterministic). A skill is only
escalated to the (paid, slower) LLM analyzer when the fast pass already flags
it — so cost scales with the number of *suspicious* skills, not the size of
the registry.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Callable
from pathlib import Path

from malwar.crawl.client import ClawHubClient, ClawHubError
from malwar.monitor.models import RegistrySnapshot, SkillRecord
from malwar.sdk import scan

logger = logging.getLogger("malwar.monitor")

# Seed terms used to enumerate the registry when the /skills list endpoint
# returns empty (the same fallback the `crawl list` command relies on). Single
# letters + digits fan the search out across the catalog.
_SEED_TERMS: tuple[str, ...] = tuple("abcdefghijklmnopqrstuvwxyz0123456789")

ProgressCallback = Callable[[int, int, str], None]


async def _enumerate_slugs(
    client: ClawHubClient,
    *,
    max_skills: int | None,
    page_size: int,
) -> list[str]:
    """Return the full set of skill slugs known to the registry.

    Pages through the list endpoint; if that yields nothing (the endpoint is
    known to return empty at times), falls back to fanning search queries out
    across seed terms and de-duplicating.
    """
    slugs: list[str] = []
    seen: set[str] = set()

    cursor: str | None = None
    while True:
        try:
            items, cursor = await client.list_skills(limit=page_size, cursor=cursor)
        except ClawHubError as exc:
            logger.warning("list_skills failed: %s", exc)
            break
        for item in items:
            if item.slug not in seen:
                seen.add(item.slug)
                slugs.append(item.slug)
        if max_skills is not None and len(slugs) >= max_skills:
            return slugs[:max_skills]
        if not cursor:
            break

    if slugs:
        return slugs

    # Fallback: broad search fan-out.
    for term in _SEED_TERMS:
        try:
            results = await client.search(term, limit=page_size)
        except ClawHubError as exc:
            logger.warning("search %r failed: %s", term, exc)
            continue
        for r in results:
            if r.slug not in seen:
                seen.add(r.slug)
                slugs.append(r.slug)
        if max_skills is not None and len(slugs) >= max_skills:
            return slugs[:max_skills]

    return slugs


async def _scan_slug(client: ClawHubClient, slug: str, *, escalate: bool) -> SkillRecord:
    """Fetch and scan a single skill, escalating to the LLM only if flagged."""
    try:
        detail = await client.get_skill(slug)
    except ClawHubError as exc:
        return SkillRecord(slug=slug, verdict="UNKNOWN", error=f"detail: {exc}")

    record = SkillRecord(
        slug=slug,
        display_name=detail.display_name,
        publisher=detail.owner.username if detail.owner else "",
        version=detail.latest_version.version if detail.latest_version else None,
        updated_at=detail.updated_at,
        installs=detail.stats.installs_all_time,
        moderation_blocked=bool(detail.moderation and detail.moderation.is_malware_blocked),
        moderation_suspicious=bool(detail.moderation and detail.moderation.is_suspicious),
    )

    try:
        content = await client.get_skill_file(slug)
    except ClawHubError as exc:
        record.error = f"file: {exc}"
        return record

    record.content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

    file_name = f"{slug}/SKILL.md"
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


async def build_snapshot(
    client: ClawHubClient | None = None,
    *,
    max_skills: int | None = None,
    escalate: bool = True,
    concurrency: int = 8,
    page_size: int = 50,
    on_progress: ProgressCallback | None = None,
) -> RegistrySnapshot:
    """Crawl and scan the entire registry into a :class:`RegistrySnapshot`.

    Parameters
    ----------
    client:
        A :class:`ClawHubClient`; a default one is created if omitted.
    max_skills:
        Cap the number of skills scanned (for testing / partial runs).
    escalate:
        Re-scan flagged skills with the full LLM + URL pipeline.
    concurrency:
        Maximum number of skills scanned in parallel.
    on_progress:
        Optional callback ``(done, total, slug)`` for progress reporting.
    """
    client = client or ClawHubClient()
    slugs = await _enumerate_slugs(client, max_skills=max_skills, page_size=page_size)

    snapshot = RegistrySnapshot(registry=client.base_url)
    total = len(slugs)
    if total == 0:
        return snapshot

    semaphore = asyncio.Semaphore(max(1, concurrency))
    done = 0
    lock = asyncio.Lock()

    async def _worker(slug: str) -> None:
        nonlocal done
        async with semaphore:
            record = await _scan_slug(client, slug, escalate=escalate)
        async with lock:
            snapshot.skills[slug] = record
            if record.error:
                snapshot.errors[slug] = record.error
            done += 1
            if on_progress is not None:
                on_progress(done, total, slug)

    await asyncio.gather(*(_worker(slug) for slug in slugs))
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
