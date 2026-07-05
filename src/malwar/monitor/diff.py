"""Diff two registry snapshots to surface security-relevant changes.

The daily monitor keeps yesterday's snapshot and today's; the diff is what a
human (or an alert) actually reads. We care about four things:

  * **added**   — skills that appeared since the last snapshot
  * **removed** — skills that disappeared (taken down, hidden, or unpublished)
  * **modified**— existing skills whose content or version changed (re-scanned)
  * **verdict_changed** — skills whose scan verdict moved, in either direction

and one headline rollup, **newly_malicious**: skills that became flagged
(MALICIOUS / SUSPICIOUS / CAUTION) — whether brand new or a regression on an
existing skill. That list is the reason the job exists.
"""

from __future__ import annotations

from malwar.monitor.models import (
    RegistrySnapshot,
    SkillChange,
    SkillRecord,
    SnapshotDiff,
    verdict_rank,
)


def _content_changed(old: SkillRecord, new: SkillRecord) -> str | None:
    """Return a human description if the skill's content/version changed."""
    if old.content_sha256 and new.content_sha256 and old.content_sha256 != new.content_sha256:
        if old.version != new.version:
            return f"version {old.version} → {new.version}, content changed"
        return "content changed (same version — silent update)"
    if old.version != new.version:
        return f"version {old.version} → {new.version}"
    return None


def diff_snapshots(
    previous: RegistrySnapshot | None,
    current: RegistrySnapshot,
) -> SnapshotDiff:
    """Compute the security-relevant delta between two snapshots.

    ``previous`` may be ``None`` (the very first run). In that case every
    currently-flagged skill is reported as ``newly_malicious`` so the first
    run still produces a useful baseline alert.
    """
    diff = SnapshotDiff(
        previous_created_at=previous.created_at if previous else None,
        current_created_at=current.created_at,
    )

    if previous is None:
        diff.newly_malicious = [r for r in current.skills.values() if r.is_flagged]
        return diff

    prev_slugs = set(previous.skills)
    curr_slugs = set(current.skills)

    # Added / removed.
    for slug in sorted(curr_slugs - prev_slugs):
        rec = current.skills[slug]
        diff.added.append(rec)
        if rec.is_flagged:
            diff.newly_malicious.append(rec)

    for slug in sorted(prev_slugs - curr_slugs):
        diff.removed.append(previous.skills[slug])

    # Changed (present in both).
    for slug in sorted(curr_slugs & prev_slugs):
        old = previous.skills[slug]
        new = current.skills[slug]

        change_detail = _content_changed(old, new)
        if change_detail is not None:
            diff.modified.append(
                SkillChange(slug=slug, kind="modified", detail=change_detail, old=old, new=new)
            )

        old_v = old.verdict.upper().strip()
        new_v = new.verdict.upper().strip()
        if old_v != new_v:
            direction = "regressed" if verdict_rank(new_v) > verdict_rank(old_v) else "improved"
            diff.verdict_changed.append(
                SkillChange(
                    slug=slug,
                    kind="verdict_changed",
                    detail=f"{old_v} → {new_v} ({direction})",
                    old=old,
                    new=new,
                )
            )
            # A regression onto a flagged verdict is a newly-malicious event.
            if new.is_flagged and verdict_rank(new_v) > verdict_rank(old_v):
                diff.newly_malicious.append(new)

    # De-duplicate newly_malicious by slug, preserving order.
    seen: set[str] = set()
    deduped: list[SkillRecord] = []
    for rec in diff.newly_malicious:
        if rec.slug not in seen:
            seen.add(rec.slug)
            deduped.append(rec)
    diff.newly_malicious = deduped

    return diff
