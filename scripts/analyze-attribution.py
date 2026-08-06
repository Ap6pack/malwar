#!/usr/bin/env python3
"""Report on publisher attribution and the platform detection gap.

Two questions the snapshot could not answer until flagged skills carried an
owner and ClawHub's own moderation state:

1. **Who publishes the bad skills?** Every campaign hypothesis this project has
   tested was built from slug prefixes, and every one collapsed when checked:
   a shared prefix is a naming convention, not an operator. An account is an
   operator. Clustering on ``publisher`` is the first version of this question
   that can actually be answered.

2. **What does the platform say about the skills we call malicious?** ClawHub
   screens uploads and exposes the result. Holding our verdict and theirs on the
   same skill is the only way to measure, from outside, how much gets through.

Both reports refuse to count what was never checked. ``moderation_blocked``
defaults to False on an unenriched record, so treating "not blocked" as the
platform's opinion would silently convert unenriched skills into evidence of a
gap. Every denominator here is the *checked* population, and the uncovered
remainder is printed rather than dropped.

Usage:
    analyze-attribution.py <snapshot.json> [--min-cluster N] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

FLAGGED = {"MALICIOUS", "SUSPICIOUS", "CAUTION"}


def load_skills(path: Path) -> dict[str, dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        snapshot = json.load(fh)
    skills = snapshot.get("skills", {})
    if not isinstance(skills, dict):
        raise SystemExit(f"{path}: 'skills' is not an object")
    return skills


def detection_gap(skills: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Compare our verdicts against ClawHub's moderation state.

    Only skills we actually asked about are counted. A skill we verified
    malicious that the platform has scanned and left unblocked is the finding;
    one still pending its scan is not, and one we never enriched is neither.
    """
    malicious = [s for s in skills.values() if s.get("verdict") == "MALICIOUS"]
    checked = [s for s in malicious if s.get("moderation_checked")]
    # Fetched but the response carried no moderation block. Reported separately
    # because "we asked and the registry told us nothing" is a broken pipeline,
    # not a platform that has cleared the skill, and the two look identical if
    # you only count what is missing.
    no_data = [
        s for s in malicious if s.get("detail_fetched") and not s.get("moderation_checked")
    ]

    blocked = [s for s in checked if s.get("moderation_blocked")]
    pending = [s for s in checked if s.get("moderation_pending") and not s.get("moderation_blocked")]
    suspicious = [
        s
        for s in checked
        if s.get("moderation_suspicious")
        and not s.get("moderation_blocked")
        and not s.get("moderation_pending")
    ]
    # Screened, not pending, and the platform is not flagging it: the gap.
    unflagged = [
        s
        for s in checked
        if not s.get("moderation_blocked")
        and not s.get("moderation_pending")
        and not s.get("moderation_suspicious")
    ]

    return {
        "malicious_total": len(malicious),
        "malicious_checked": len(checked),
        "malicious_unchecked": len(malicious) - len(checked) - len(no_data),
        "malicious_fetched_no_moderation_data": len(no_data),
        "platform_blocked": len(blocked),
        "platform_suspicious": len(suspicious),
        "platform_pending_scan": len(pending),
        "platform_no_flag": len(unflagged),
        "gap_rate": (len(unflagged) / len(checked)) if checked else None,
        "examples": sorted(s["slug"] for s in unflagged)[:25],
    }


def publisher_clusters(
    skills: dict[str, dict[str, Any]], min_cluster: int
) -> list[dict[str, Any]]:
    """Group flagged skills by the account that published them.

    A cluster is reported with its full published footprint, not just its
    flagged members: an account with 3 malicious skills out of 4 is a very
    different claim from 3 out of 300, and only the first is worth calling a
    campaign.
    """
    # Keyed on the immutable account id where we have it, because a handle can
    # be renamed and would then split one operator across two clusters.
    by_publisher: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for skill in skills.values():
        key = skill.get("publisher_id") or skill.get("publisher") or ""
        if key:
            by_publisher[key].append(skill)

    clusters = []
    for key, members in by_publisher.items():
        publisher = next(
            (m.get("publisher") for m in members if m.get("publisher")), key
        )
        flagged = [s for s in members if s.get("verdict") in FLAGGED]
        malicious = [s for s in flagged if s.get("verdict") == "MALICIOUS"]
        if len(malicious) < min_cluster:
            continue
        rules: Counter[str] = Counter()
        for s in malicious:
            rules.update(s.get("finding_rule_ids") or [])
        clusters.append(
            {
                "publisher": publisher,
                # Attributed skills only. We enrich the flagged tail, so this is
                # not the account's total output and must not be read as such.
                "attributed_skills": len(members),
                "flagged": len(flagged),
                "malicious": len(malicious),
                "shared_rules": [r for r, n in rules.most_common(5) if n >= 2],
                "slugs": sorted(s["slug"] for s in malicious)[:20],
            }
        )
    clusters.sort(key=lambda c: (-c["malicious"], c["publisher"]))
    return clusters


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument(
        "--min-cluster",
        type=int,
        default=2,
        help="Minimum malicious skills for a publisher to be reported (default 2)",
    )
    parser.add_argument("--json", type=Path, help="Write the full report here")
    args = parser.parse_args()

    skills = load_skills(args.snapshot)
    gap = detection_gap(skills)
    clusters = publisher_clusters(skills, args.min_cluster)

    attributed = sum(1 for s in skills.values() if s.get("publisher"))
    flagged_total = sum(1 for s in skills.values() if s.get("verdict") in FLAGGED)

    print(f"snapshot:            {args.snapshot}")
    print(f"skills:              {len(skills):,}")
    print(f"flagged:             {flagged_total:,}")
    print(f"attributed:          {attributed:,}")
    print()

    print("== platform detection gap ==")
    print(f"we verified malicious:      {gap['malicious_total']:,}")
    print(f"  of which we checked:      {gap['malicious_checked']:,}")
    print(f"  not yet asked:            {gap['malicious_unchecked']:,}")
    if gap["malicious_fetched_no_moderation_data"]:
        print(
            f"  asked, no data returned:  "
            f"{gap['malicious_fetched_no_moderation_data']:,}  "
            f"<-- registry returned no moderation block; not a gap"
        )
    if gap["malicious_checked"]:
        print(f"  platform blocked:         {gap['platform_blocked']:,}")
        print(f"  platform marked suspect:  {gap['platform_suspicious']:,}")
        print(f"  platform scan pending:    {gap['platform_pending_scan']:,}")
        print(f"  platform no flag at all:  {gap['platform_no_flag']:,}")
        print(f"  gap rate:                 {gap['gap_rate']:.1%} of checked")
        if gap["examples"]:
            print("  examples: " + ", ".join(gap["examples"][:10]))
    else:
        print("  nothing enriched yet; run a sweep with enrichment enabled")
    print()

    print(f"== publisher clusters (>= {args.min_cluster} malicious) ==")
    if not clusters:
        print("  none")
    for c in clusters[:25]:
        rules = ", ".join(c["shared_rules"]) or "no shared rule"
        print(
            f"  {c['publisher']:<28} {c['malicious']:>4} malicious "
            f"/ {c['flagged']:>4} flagged / {c['attributed_skills']:>4} attributed  [{rules}]"
        )
    if len(clusters) > 25:
        print(f"  ... and {len(clusters) - 25} more")

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "snapshot": str(args.snapshot),
                    "skills": len(skills),
                    "flagged": flagged_total,
                    "attributed": attributed,
                    "detection_gap": gap,
                    "publisher_clusters": clusters,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
