#!/usr/bin/env python3
"""Check two properties of the registry that a per-skill scan cannot see.

Both exist to close caveats on a claim, not to find malware.

**ambiguity** -- 1,614 slugs in the snapshot returned HTTP 409
``AMBIGUOUS_SKILL_SLUG``: more than one publisher owns the name, and the API
refuses to resolve it. Those 1,614 are the skills this project has *no verdict
for at all*, and they are not a random 2% -- they are specifically the contested
names. This fetches the full match list the stored error truncates, so the
number of owners per slug and their handles can be counted.

**clones** -- 4,619 skills (5.9%) share a ``content_sha256`` with another skill.
That hash covers ``SKILL.md`` only. Two skills with identical documentation can
still ship different code, and if they do, "byte-identical duplicate" is the
wrong description and any claim about takedown blast radius built on it is
wrong too. This fetches each clone's referenced files and compares them.

Neither mode convicts anything. Both report structure.

Usage:
    registry-integrity.py <snapshot.json> --mode ambiguity [--sample N]
    registry-integrity.py <snapshot.json> --mode clones [--clusters N] [--members M]
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from malwar.research.references import extract

BASE_URL = "https://clawhub.ai/api/v1"

# Paced to stay inside the registry's ~120 req/min limit.
_DELAY = 0.55


async def _get(client: Any, slug: str, path: str) -> tuple[int, str]:
    resp = await client.get(f"{BASE_URL}/skills/{slug}/file", params={"path": path})
    return resp.status_code, resp.text


# ---------------------------------------------------------------------------
# ambiguity
# ---------------------------------------------------------------------------


async def check_ambiguity(slugs: list[str]) -> list[dict[str, Any]]:
    import httpx

    out: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        for i, slug in enumerate(slugs, 1):
            try:
                status, body = await _get(client, slug, "SKILL.md")
            except Exception as exc:
                out.append({"slug": slug, "error": f"{type(exc).__name__}: {exc}"})
                await asyncio.sleep(_DELAY)
                continue
            await asyncio.sleep(_DELAY)

            if status != 409:
                # No longer ambiguous: one side was removed or renamed since the
                # snapshot. Worth recording -- it is the churn rate on contested
                # names.
                out.append({"slug": slug, "status": status, "resolved": True})
                continue
            try:
                payload = json.loads(body)
            except ValueError:
                out.append({"slug": slug, "status": 409, "unparsed": body[:200]})
                continue
            matches = payload.get("matches") or []
            out.append({
                "slug": slug,
                "status": 409,
                "owner_count": len(matches),
                "owners": [m.get("ownerHandle", "") for m in matches],
            })
            if i % 20 == 0:
                print(f"  ...{i}/{len(slugs)}", flush=True)
    return out


def report_ambiguity(results: list[dict[str, Any]]) -> None:
    still = [r for r in results if r.get("status") == 409 and "owner_count" in r]
    resolved = [r for r in results if r.get("resolved")]
    errors = [r for r in results if "error" in r or "unparsed" in r]

    print(f"\nsampled:                     {len(results):,}")
    print(f"  still ambiguous:           {len(still):,}")
    print(f"  no longer ambiguous:       {len(resolved):,}")
    print(f"  errors:                    {len(errors):,}")

    if still:
        counts = Counter(r["owner_count"] for r in still)
        print("\nowners per contested slug:")
        for n in sorted(counts):
            print(f"  {n} owners   {counts[n]:,} slugs")
        total_claims = sum(r["owner_count"] for r in still)
        print(f"\ndistinct publishers involved: "
              f"{len({o for r in still for o in r['owners']}):,}")
        print(f"total competing claims:       {total_claims:,}")

        # A handle appearing across many contested names is the shape worth
        # looking at: one publisher claiming lots of names other people also use.
        who = Counter(o for r in still for o in r["owners"])
        print("\npublishers appearing in the most contested slugs:")
        for handle, n in who.most_common(15):
            print(f"  {handle[:36]:<36} {n}")

        print("\nwidest contests:")
        for r in sorted(still, key=lambda x: -x["owner_count"])[:15]:
            print(f"  {r['slug'][:38]:<38} {r['owner_count']} owners: "
                  f"{', '.join(r['owners'][:6])}")


# ---------------------------------------------------------------------------
# clones
# ---------------------------------------------------------------------------


async def check_clones(
    clusters: list[tuple[str, list[str]]], members: int
) -> list[dict[str, Any]]:
    """For each cluster, fetch every member's referenced files and hash them."""
    import httpx

    out: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        for cid, (chash, slugs) in enumerate(clusters, 1):
            picked = slugs[:members]
            print(f"  cluster {cid}/{len(clusters)} {chash[:12]} "
                  f"({len(picked)} of {len(slugs)} members)", flush=True)
            per_slug: dict[str, dict[str, str]] = {}
            doc_ok = 0
            for slug in picked:
                try:
                    status, doc = await _get(client, slug, "SKILL.md")
                except Exception:
                    await asyncio.sleep(_DELAY)
                    continue
                await asyncio.sleep(_DELAY)
                if status != 200:
                    continue
                # Confirm the snapshot's hash still describes this file.
                if hashlib.sha256(doc.encode("utf-8")).hexdigest() == chash:
                    doc_ok += 1
                files: dict[str, str] = {}
                for path in extract(doc):
                    try:
                        st, body = await _get(client, slug, path)
                    except Exception:
                        await asyncio.sleep(_DELAY)
                        continue
                    await asyncio.sleep(_DELAY)
                    files[path] = (
                        hashlib.sha256(body.encode("utf-8")).hexdigest()
                        if st == 200 else f"HTTP{st}"
                    )
                per_slug[slug] = files
            out.append({
                "hash": chash,
                "members_total": len(slugs),
                "members_checked": len(per_slug),
                "doc_hash_confirmed": doc_ok,
                "files": per_slug,
            })
    return out


def report_clones(results: list[dict[str, Any]]) -> None:
    print(f"\nclusters checked: {len(results)}")
    identical = divergent = no_refs = unreachable = 0

    for r in results:
        per = r["files"]
        if not per:
            # Every member failed to fetch. Reported, never folded into a
            # "nothing found" total: a check that answers the same way whether
            # the registry was reachable or not is worse than no check.
            unreachable += 1
            print(f"\n  {r['hash'][:12]}  NO DATA -- 0 of "
                  f"{r['members_total']} members fetched")
            continue
        paths = {p for f in per.values() for p in f}
        if not paths:
            no_refs += 1
            verdict = "no referenced files (SKILL.md is the whole package)"
        else:
            # Same set of paths AND same hash for every path, across all members?
            sig = {slug: tuple(sorted(f.items())) for slug, f in per.items()}
            same = len(set(sig.values())) == 1
            verdict = "identical packages" if same else "PACKAGES DIFFER"
            identical += same
            divergent += not same

        print(f"\n  {r['hash'][:12]}  members {r['members_checked']}/{r['members_total']}"
              f"  doc-hash confirmed {r['doc_hash_confirmed']}/{r['members_checked']}")
        print(f"    {len(paths)} distinct referenced path(s) -> {verdict}")
        if paths and verdict == "PACKAGES DIFFER":
            for path in sorted(paths):
                seen = Counter(f.get(path, "(absent)")[:12] for f in per.values())
                if len(seen) > 1:
                    print(f"      {path[:40]:<40} {dict(seen)}")

    print(f"\nsummary: {identical} identical, {divergent} divergent, "
          f"{no_refs} with no referenced files, {unreachable} unreachable")
    if unreachable == len(results):
        print("\nEvery cluster failed to fetch. This says nothing about the")
        print("registry -- it says the run had no network reach. Not a result.")
        return
    if divergent:
        print("\nA divergent cluster means identical SKILL.md but different shipped")
        print("code. 'Byte-identical duplicate' would be the wrong description for")
        print("those, and any blast-radius claim must be scoped to the doc alone.")


# ---------------------------------------------------------------------------


def load_clusters(snapshot: Path, count: int) -> list[tuple[str, list[str]]]:
    skills = json.loads(snapshot.read_text(encoding="utf-8")).get("skills", {})
    by_hash: dict[str, list[str]] = defaultdict(list)
    for slug, rec in skills.items():
        h = rec.get("content_sha256") or ""
        if h:
            by_hash[h].append(slug)
    dupes = [(h, sorted(s)) for h, s in by_hash.items() if len(s) > 1]
    dupes.sort(key=lambda kv: -len(kv[1]))
    return dupes[:count]


def load_ambiguous(snapshot: Path) -> list[str]:
    skills = json.loads(snapshot.read_text(encoding="utf-8")).get("skills", {})
    return sorted(
        slug for slug, rec in skills.items()
        if "AMBIGUOUS_SKILL_SLUG" in (rec.get("error") or "")
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("snapshot", type=Path)
    ap.add_argument("--mode", choices=["ambiguity", "clones"], required=True)
    ap.add_argument("--sample", type=int, default=150, help="ambiguity: slugs to check")
    ap.add_argument("--clusters", type=int, default=8, help="clones: clusters to check")
    ap.add_argument("--members", type=int, default=5, help="clones: members per cluster")
    ap.add_argument("--seed", type=int, default=20260816)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    if args.mode == "ambiguity":
        slugs = load_ambiguous(args.snapshot)
        print(f"ambiguous slugs in snapshot: {len(slugs):,}")
        # Reproducible sampling, not cryptography: the seed is published so
        # anyone can redraw the same sample.
        rng = random.Random(args.seed)  # noqa: S311
        chosen = rng.sample(slugs, min(args.sample, len(slugs)))
        print(f"checking {len(chosen)} (seed {args.seed})\n")
        results = asyncio.run(check_ambiguity(chosen))
        report_ambiguity(results)
    else:
        clusters = load_clusters(args.snapshot, args.clusters)
        print(f"checking {len(clusters)} largest clone clusters, "
              f"up to {args.members} members each\n")
        results = asyncio.run(check_clones(clusters, args.members))
        report_clones(results)

    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
