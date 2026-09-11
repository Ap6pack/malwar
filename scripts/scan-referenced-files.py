#!/usr/bin/env python3
"""Scan the files a skill ships, and report where they disagree with its docs.

Step one measured the surface: 47% of a 290-skill sample name files no scan has
ever read, 182 of them executable. This reads them.

The output that matters is the **divergence set**: skills whose SKILL.md is
clean but whose referenced code is not. That set is hidden behaviour by
construction -- the documentation a reviewer or user would read says one thing,
the code that actually runs says another -- and it is the only shape of finding
worth publishing as malicious.

Two things this deliberately does not do:

* It does not convict. The rule engine is tuned for SKILL.md prose; run against
  JavaScript and Python it has an unmeasured false-positive profile, and this
  project has already published one inflated number by assuming otherwise.
  Findings here are leads to read by hand, and the report says so.
* It does not treat a 404 as absence of code. A referenced path that fails to
  fetch is counted separately, because "the skill names a script we could not
  retrieve" and "the skill ships nothing" are different facts.

Usage:
    scan-referenced-files.py <snapshot.json> --sample N [--json out.json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from malwar.research.references import extract, is_executable

BASE_URL = "https://clawhub.ai/api/v1"

# Paced to stay inside the registry's ~120 req/min limit.
_DELAY = 0.55


async def _get(client: Any, slug: str, path: str) -> tuple[int, str]:
    resp = await client.get(
        f"{BASE_URL}/skills/{slug}/file", params={"path": path}
    )
    return resp.status_code, resp.text


async def scan_skill(client: Any, slug: str) -> dict[str, Any] | None:
    """Fetch a skill's SKILL.md and everything it names, scanning each."""
    from malwar.sdk import scan

    try:
        status, skill_md = await _get(client, slug, "SKILL.md")
    except Exception as exc:
        return {"slug": slug, "error": f"{type(exc).__name__}: {exc}"}
    if status != 200:
        return None
    await asyncio.sleep(_DELAY)

    doc = await scan(skill_md, file_name=f"{slug}/SKILL.md", use_llm=False, use_urls=False)
    refs = extract(skill_md)

    files: list[dict[str, Any]] = []
    for path in refs:
        try:
            status, body = await _get(client, slug, path)
        except Exception as exc:
            files.append({"path": path, "status": "error", "detail": str(exc)[:120]})
            await asyncio.sleep(_DELAY)
            continue
        await asyncio.sleep(_DELAY)
        if status != 200:
            # Named but not retrievable. Recorded, never counted as clean.
            files.append({"path": path, "status": status})
            continue
        res = await scan(body, file_name=f"{slug}/{path}", use_llm=False, use_urls=False)
        files.append({
            "path": path,
            "status": 200,
            "kind": refs[path],
            "executable": is_executable(path),
            "verdict": res.verdict,
            "risk": res.risk_score,
            "rules": sorted({f.rule_id for f in res.findings if not f.suppressed}),
            "bytes": len(body),
        })

    return {
        "slug": slug,
        "doc_verdict": doc.verdict,
        "doc_risk": doc.risk_score,
        "doc_rules": sorted({f.rule_id for f in doc.findings if not f.suppressed}),
        "referenced": files,
    }


async def run(slugs: list[str]) -> list[dict[str, Any]]:
    import httpx

    out: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        for i, slug in enumerate(slugs, 1):
            result = await scan_skill(client, slug)
            if result:
                out.append(result)
            if i % 10 == 0:
                print(f"  ...{i}/{len(slugs)} skills", flush=True)
    return out


def report(results: list[dict[str, Any]]) -> None:
    fetched = [r for r in results if "referenced" in r]
    with_refs = [r for r in fetched if r["referenced"]]
    all_files = [f for r in with_refs for f in r["referenced"]]
    ok = [f for f in all_files if f.get("status") == 200]
    unreachable = [f for f in all_files if f.get("status") != 200]

    print(f"\nskills scanned:              {len(fetched):,}")
    print(f"  naming referenced files:   {len(with_refs):,}")
    print(f"referenced paths tried:      {len(all_files):,}")
    print(f"  fetched:                   {len(ok):,}")
    print(f"  unreachable (named, 404):  {len(unreachable):,}")

    if ok:
        print("\nverdicts on referenced files:")
        for v, n in Counter(f["verdict"] for f in ok).most_common():
            print(f"  {v:<12} {n:,}")

    # The divergence set: clean docs, flagged code.
    divergent = [
        (r, f)
        for r in with_refs
        if r["doc_verdict"] in ("CLEAN", "UNKNOWN")
        for f in r["referenced"]
        if f.get("status") == 200 and f.get("verdict") not in ("CLEAN", "UNKNOWN")
    ]
    print(f"\n{'=' * 62}")
    print(f"DIVERGENCE  (SKILL.md clean, referenced file flagged): {len(divergent)}")
    print(f"{'=' * 62}")
    if not divergent:
        print("  none in this sample.")
        print("  A clean result here is a real result: it says the unread")
        print("  surface is large and, in this sample, not hiding anything.")
    for r, f in divergent[:40]:
        rules = ", ".join(x.replace("MALWAR-", "") for x in f["rules"])
        print(f"  {r['slug'][:34]:<34} {f['path'][:30]:<30} "
              f"{f['verdict']:<11} risk={f['risk']:<4} [{rules}]")

    print("\nThese are leads, not verdicts: the rule engine is calibrated for")
    print("SKILL.md prose and its false-positive profile on code is unmeasured.")
    print("Every one needs reading by hand before it is called anything.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("snapshot", type=Path)
    ap.add_argument("--sample", type=int, default=60)
    ap.add_argument("--seed", type=int, default=20260816)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    skills = json.loads(args.snapshot.read_text(encoding="utf-8")).get("skills", {})
    # Reproducible sampling, not cryptography: the seed is published so anyone
    # can redraw the same sample and check the result.
    rng = random.Random(args.seed)  # noqa: S311
    chosen = rng.sample(sorted(skills), min(args.sample, len(skills)))
    print(f"sampling {len(chosen)} skills (seed {args.seed})\n")

    results = asyncio.run(run(chosen))
    report(results)

    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
