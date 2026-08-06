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


def is_platform_cleared(rec: dict) -> bool:
    """True when the registry screened this skill and returned a clean verdict.

    Requires the verdict string itself. Every boolean in the moderation block
    is derived from it and defaults False, so a record we never enriched, or
    one the registry holds no screening result for, would otherwise look
    identical to one the platform actively cleared.
    """
    return (
        bool(rec.get("moderation_checked"))
        and str(rec.get("moderation_verdict", "")).lower() == "clean"
        and not rec.get("moderation_blocked")
        and not rec.get("moderation_pending")
        and not rec.get("moderation_suspicious")
    )


def select(
    snapshot: dict,
    pattern: str,
    verdict: str,
    require_behavioural: bool,
    platform_cleared: bool = False,
) -> list[str]:
    """Return slugs matching the cohort definition, sorted for stable output."""
    rx = re.compile(pattern, re.IGNORECASE) if pattern else None
    out = []
    for slug, rec in snapshot.get("skills", {}).items():
        if rec.get("verdict") != verdict:
            continue
        if rx is not None and not rx.search(slug):
            continue
        # The disagreement cohort: we call it malicious, the registry screened
        # it and called it clean. Publishing that disagreement as a platform
        # failure means assuming our side is right, which is the assumption
        # this whole script exists to test.
        if platform_cleared and not is_platform_cleared(rec):
            continue
        rules = set(rec.get("finding_rule_ids") or [])
        if require_behavioural and not (rules - DISCUSSION_RULES):
            continue
        out.append(slug)
    return sorted(out)


# Infrastructure worth correlating across a cohort. A shared C2 host, endpoint
# or literal payload across several skills is what separates "these all tripped
# the same rule" from "these are the same operator".
_URL_RE = re.compile(r"https?://[^\s'\"`)>\]]+")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def extract_iocs(content: str) -> dict[str, list[str]]:
    """Pull the indicators worth comparing between members of a cohort."""
    from urllib.parse import urlparse

    urls = _URL_RE.findall(content)
    hosts = sorted({(urlparse(u).hostname or "").lower() for u in urls} - {""})
    return {
        "hosts": hosts,
        "urls": sorted(set(urls)),
        "ips": sorted(set(_IPV4_RE.findall(content))),
        "b64_blobs": sorted(set(_B64_RE.findall(content))),
    }


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
                "iocs": extract_iocs(content),
            })

    await asyncio.gather(*(one(s) for s in slugs))
    return sorted(results, key=lambda r: r["slug"])


def correlate(results: list[dict]) -> dict[str, dict[str, list[str]]]:
    """Indicators appearing in more than one cohort member, by kind.

    This is the campaign test. Members tripping the same rule proves only that
    they share a behaviour; members pointing at the same host, endpoint or
    literal blob is evidence they share an operator.
    """
    shared: dict[str, dict[str, list[str]]] = {}
    for kind in ("hosts", "urls", "ips", "b64_blobs"):
        seen: dict[str, list[str]] = {}
        for r in results:
            for val in (r.get("iocs") or {}).get(kind, []):
                seen.setdefault(val, []).append(r["slug"])
        multi = {v: sorted(s) for v, s in seen.items() if len(set(s)) > 1}
        if multi:
            shared[kind] = dict(sorted(multi.items(), key=lambda kv: -len(kv[1])))
    return shared


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("snapshot", type=Path)
    ap.add_argument(
        "--slugs",
        help="comma-separated slugs; bypasses snapshot selection entirely "
             "(for a cohort defined by behaviour over time rather than by name)",
    )
    ap.add_argument("--slug-pattern", help="regex the slug must match")
    ap.add_argument("--verdict", default="MALICIOUS", help="snapshot verdict to select")
    ap.add_argument(
        "--require-behavioural",
        action="store_true",
        help="drop members whose only evidence is a discussion-based rule",
    )
    ap.add_argument(
        "--platform-cleared",
        action="store_true",
        help="restrict to skills the registry screened and called clean "
        "(the disagreement cohort); requires an enriched snapshot",
    )
    ap.add_argument("--limit", type=int, default=0, help="cap cohort size (0 = no cap)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--output", type=Path, help="write full JSON results here")
    args = ap.parse_args()

    if args.slugs:
        slugs = [s.strip() for s in args.slugs.split(",") if s.strip()]
    else:
        if not args.slug_pattern and not args.platform_cleared:
            ap.error("provide --slugs, --slug-pattern, or --platform-cleared")
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
        slugs = select(
            snapshot,
            args.slug_pattern or "",
            args.verdict,
            args.require_behavioural,
            platform_cleared=args.platform_cleared,
        )
    if args.limit:
        slugs = slugs[: args.limit]
    if not slugs:
        print("Cohort is empty; nothing to verify.", file=sys.stderr)
        sys.exit(1)

    scope = f"matching /{args.slug_pattern}/ " if args.slug_pattern else ""
    if args.platform_cleared:
        scope += "that the registry screened and called clean "
    print(f"Cohort: {len(slugs)} skills {scope}"
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

    shared = correlate(results)
    print("\n=== shared infrastructure across the cohort ===", file=sys.stderr)
    if not shared:
        print("  none. Members share a behaviour, not an operator:\n"
              "  no host, URL, IP or literal blob appears in more than one skill.",
              file=sys.stderr)
    else:
        for kind, vals in shared.items():
            print(f"  {kind}:", file=sys.stderr)
            for val, owners in list(vals.items())[:10]:
                print(f"    {len(owners):3} skills  {val[:88]}", file=sys.stderr)

    payload = {"cohort_size": len(slugs), "counts": counts,
               "shared_infrastructure": shared, "results": results}
    if args.output:
        args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    else:
        print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
