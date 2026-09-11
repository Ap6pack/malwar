#!/usr/bin/env python3
"""Find the files a skill ships that no scan has ever read.

Every sweep this project has run fetches exactly one file per skill::

    content = await client.get_skill_file(meta.slug)   # path defaults to SKILL.md

So all 74,158 verdicts are verdicts on the documentation. The registry serves
the rest of the tree happily -- ``scripts/buddy-algorithm.js`` and
``scripts/generate-image.ts`` both return real content -- which means a skill
whose SKILL.md is clean and whose script beacons to a C2 is invisible to us, to
a reviewer skimming the listing, and to the user. That is the definition of
hidden behaviour, and it is the only place worth hunting for real malware.

This is step one: extract the paths each SKILL.md references, so the size of
the unread surface can be measured before anything is fetched.

Deliberately conservative. A path is only reported when the skill *names* it in
a way that implies execution or inclusion. Guessing at conventional layouts
would inflate the count with files that do not exist, and an inflated
denominator is how you end up reporting a blind spot larger than the one you
have.

Usage:
    extract-referenced-files.py <snapshot.json> [--json out.json] [--limit N]
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

async def sample_registry(slugs: list[str]) -> dict[str, str]:
    """Fetch SKILL.md for each slug. Requires network reach to the registry."""
    import httpx

    out: dict[str, str] = {}
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        for i, slug in enumerate(slugs, 1):
            try:
                resp = await client.get(
                    f"{BASE_URL}/skills/{slug}/file", params={"path": "SKILL.md"}
                )
                if resp.status_code == 200:
                    out[slug] = resp.text
            except Exception as exc:
                print(f"  {slug}: {type(exc).__name__}: {exc}", flush=True)
            if i % 50 == 0:
                print(f"  ...fetched {i}/{len(slugs)}", flush=True)
            await asyncio.sleep(0.55)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("snapshot", type=Path)
    ap.add_argument("--json", type=Path, help="write {slug: {path: kind}} here")
    ap.add_argument("--limit", type=int, default=0, help="cap skills examined")
    ap.add_argument(
        "--sample",
        type=int,
        default=0,
        help="fetch this many random SKILL.md from the registry (needs network)",
    )
    ap.add_argument("--seed", type=int, default=20260816, help="sampling seed")
    args = ap.parse_args()

    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    skills: dict[str, Any] = snapshot.get("skills", {})

    # The snapshot records verdicts and hashes, not content, so the text has to
    # come from the registry. Sampling is honest about that: it reports the
    # fraction over skills actually fetched rather than extrapolating silently.
    if args.sample:
        # Reproducible sampling, not cryptography: the seed is published so
        # anyone can draw the same sample and check the number.
        rng = random.Random(args.seed)  # noqa: S311
        chosen = rng.sample(sorted(skills), min(args.sample, len(skills)))
        texts = asyncio.run(sample_registry(chosen))
        items = [(s, {"__text__": t}) for s, t in texts.items()]
        print(f"\nfetched {len(texts)}/{len(chosen)} sampled SKILL.md\n")
    else:
        items = list(skills.items())
    if args.limit:
        items = items[: args.limit]

    with_text = 0
    no_text = 0
    refs: dict[str, dict[str, str]] = {}
    kinds: Counter[str] = Counter()
    exts: Counter[str] = Counter()

    for slug, rec in items:
        text = rec.get("__text__") or rec.get("description") or ""
        if not text:
            no_text += 1
            continue
        with_text += 1
        found = extract(text)
        if found:
            refs[slug] = found
            for path, kind in found.items():
                kinds[kind] += 1
                exts[Path(path).suffix.lower()] += 1

    total_paths = sum(len(v) for v in refs.values())
    print(f"snapshot:                     {args.snapshot}")
    print(f"skills in snapshot:           {len(skills):,}")
    print(f"  with SKILL.md text held:    {with_text:,}")
    print(f"  text not held (cannot say): {no_text:,}")
    print()
    print(f"skills referencing files we never scan: {len(refs):,}"
          + (f"  ({len(refs)/with_text:.1%} of those readable)" if with_text else ""))
    print(f"distinct referenced paths:              {total_paths:,}")
    print()
    print("how they are referenced:")
    for kind, n in kinds.most_common():
        print(f"  {kind:<18} {n:,}")
    print()
    print("by extension:")
    for ext, n in exts.most_common(12):
        print(f"  {ext or '(none)':<10} {n:,}")

    executable = sum(1 for v in refs.values() for p in v if is_executable(p))
    print()
    print(f"of those, executable code:              {executable:,}")

    if args.json:
        args.json.write_text(json.dumps(refs, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
