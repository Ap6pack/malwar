#!/usr/bin/env python3
"""Re-verify a cohort of skills from a snapshot with the full LLM pipeline.

The registry sweep deliberately does *not* escalate confident-MALICIOUS skills:
a second opinion cannot change a verdict that is already corroborated, so
spending on it is waste. That is the right default for monitoring, but it means
a cohort selected *after* the fact (say, "every malicious skill whose name
markets it as a security tool") arrives mostly rules-only.

Publishing a claim about such a cohort on rules alone repeats the mistake this
project has already made once: an uncorroborated count that shrinks when you
check it. This re-scans each member with the LLM layer on and reports what
survives, so a finding can be stated as verified rather than as flagged.

Usage:
    verify-cohort.py <snapshot.json> --slug-pattern REGEX [options]

Selection is deliberately explicit so a published cohort is reproducible from
the snapshot alone.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

# Rules that fire on a skill *discussing* a technique rather than performing it
# (a genuine prompt-injection guard quotes injection phrases). A cohort claim
# resting only on these is about vocabulary, not behaviour.
DISCUSSION_RULES = {
    "MALWAR-PI-001",
    "MALWAR-PI-002",
    "MALWAR-PI-003",
    "MALWAR-HIJACK-001",
}


def select(snapshot: dict, pattern: str, verdict: str, require_behavioural: bool) -> list[str]:
    """Return slugs matching the cohort definition, sorted for stable output."""
    rx = re.compile(pattern, re.IGNORECASE)
    out = []
    for slug, rec in snapshot.get("skills", {}).items():
        if rec.get("verdict") != verdict or not rx.search(slug):
            continue
        rules = set(rec.get("finding_rule_ids") or [])
        if require_behavioural and not (rules - DISCUSSION_RULES):
            continue
        out.append(slug)
    return sorted(out)


async def verify(slugs: list[str], concurrency: int) -> list[dict]:
    from malwar.crawl.client import ClawHubClient
    from malwar.sdk import scan

    client = ClawHubClient()
    sem = asyncio.Semaphore(max(1, concurrency))
    results: list[dict] = []

    async def one(slug: str) -> None:
        async with sem:
            try:
                content = await client.get_skill_file(slug)
            except Exception as exc:
                results.append({"slug": slug, "verdict": "ERROR", "detail": f"fetch: {exc}"})
                return
            try:
                # use_llm=True is the whole point; URL crawling stays off for
                # the same latency/flakiness reasons as the sweep.
                res = await scan(content, file_name=f"{slug}/SKILL.md", use_llm=True, use_urls=False)
            except Exception as exc:
                results.append({"slug": slug, "verdict": "ERROR", "detail": f"scan: {exc}"})
                return
            results.append({
                "slug": slug,
                "verdict": res.verdict,
                "risk_score": res.risk_score,
                "rules": sorted({f.rule_id for f in res.findings if not f.suppressed}),
                "suppressed": sorted({f.rule_id for f in res.findings if f.suppressed}),
            })

    await asyncio.gather(*(one(s) for s in slugs))
    return sorted(results, key=lambda r: r["slug"])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("snapshot", type=Path)
    ap.add_argument("--slug-pattern", required=True, help="regex the slug must match")
    ap.add_argument("--verdict", default="MALICIOUS", help="snapshot verdict to select")
    ap.add_argument(
        "--require-behavioural",
        action="store_true",
        help="drop members whose only evidence is a discussion-based rule",
    )
    ap.add_argument("--limit", type=int, default=0, help="cap cohort size (0 = no cap)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--output", type=Path, help="write full JSON results here")
    args = ap.parse_args()

    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    slugs = select(snapshot, args.slug_pattern, args.verdict, args.require_behavioural)
    if args.limit:
        slugs = slugs[: args.limit]
    if not slugs:
        print("Cohort is empty; nothing to verify.", file=sys.stderr)
        sys.exit(1)

    print(f"Cohort: {len(slugs)} skills matching /{args.slug_pattern}/ "
          f"with snapshot verdict {args.verdict}"
          f"{' (behavioural evidence required)' if args.require_behavioural else ''}",
          file=sys.stderr)

    results = asyncio.run(verify(slugs, args.concurrency))

    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    confirmed = counts.get("MALICIOUS", 0)
    checked = sum(v for k, v in counts.items() if k != "ERROR")

    print("\n=== LLM-verified outcome ===", file=sys.stderr)
    for verdict, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {verdict:11} {n}", file=sys.stderr)
    if checked:
        print(f"\n  confirmed malicious: {confirmed}/{checked} "
              f"({confirmed / checked * 100:.1f}% of those the LLM could read)", file=sys.stderr)

    payload = {"cohort_size": len(slugs), "counts": counts, "results": results}
    if args.output:
        args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    else:
        print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
