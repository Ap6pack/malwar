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
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

BASE_URL = "https://clawhub.ai/api/v1"

# Interpreters and runners whose argument is a file the skill expects to run.
_RUNNERS = r"(?:node|python3?|bun|deno|ts-node|tsx|bash|sh|zsh|ruby|perl|php|Rscript)"

# Ways a SKILL.md names a file it ships. Each must capture the path in group 1.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Executed by an interpreter: `node scripts/foo.js`, `python3 ./bin/x.py`.
    # ${SKILL_DIR}/ and ./ prefixes are stripped by _clean.
    (
        re.compile(
            rf"\b{_RUNNERS}\s+(?:\$\{{SKILL_DIR\}}/|\./)?"
            r"([\w./-]+\.(?:js|mjs|cjs|ts|tsx|py|sh|bash|rb|pl|php|R))\b"
        ),
        "executed",
    ),
    # Explicit "Read `path`" instructions, which the agent will follow.
    (
        re.compile(r"\b(?:Read|read|Load|load|See|see)\s+`([\w./-]+\.[\w]+)`"),
        "read-instruction",
    ),
    # Markdown link or bare mention of a repo-relative source/doc file.
    (
        re.compile(
            r"[\(\[`\s](?:\./)?"
            r"((?:scripts|bin|lib|src|tools|references|assets|specs)/[\w./-]+"
            r"\.(?:js|mjs|cjs|ts|tsx|py|sh|bash|rb|pl|php|R|md|json|ya?ml|toml))"
        ),
        "referenced",
    ),
]

# Paths that are not part of the skill: the file we already scan, and things
# that belong to the user's project rather than the package.
_SKIP = re.compile(
    r"^(?:SKILL\.md|README\.md|package(?:-lock)?\.json|tsconfig\.json"
    r"|\.env(?:\.example)?|node_modules/.*|\.\./.*)$",
    re.IGNORECASE,
)


def _clean(path: str) -> str | None:
    """Normalise a captured path, or return None if it is not skill-local."""
    path = path.strip().strip("`'\"")
    path = re.sub(r"^\$\{SKILL_DIR\}/", "", path)
    path = re.sub(r"^\./", "", path)
    if not path or path.startswith(("/", "~", "http")) or ".." in path:
        return None
    if _SKIP.match(path):
        return None
    # A bare filename with no directory and no extension we recognise is more
    # likely prose than a shipped file.
    if "." not in path:
        return None
    return path


def extract(text: str) -> dict[str, str]:
    """Return {path: how it was referenced} for one SKILL.md."""
    found: dict[str, str] = {}
    for pattern, kind in _PATTERNS:
        for match in pattern.finditer(text):
            cleaned = _clean(match.group(1))
            if cleaned and cleaned not in found:
                found[cleaned] = kind
    return found


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

    executable = sum(
        1 for v in refs.values()
        for p in v if Path(p).suffix.lower() in
        {".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".sh", ".bash", ".rb", ".pl", ".php"}
    )
    print()
    print(f"of those, executable code:              {executable:,}")

    if args.json:
        args.json.write_text(json.dumps(refs, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
