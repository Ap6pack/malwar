#!/usr/bin/env python3
"""Print the *shape* of the skill-detail API response.

The parser reads ``owner`` and ``moderation`` from the top level of the detail
response, while the skill itself is nested under a ``skill`` key. The only test
covering that is a hand-authored mock asserting the same assumption, so it
passes whether or not the assumption holds. On the first live run, 992 detail
fetches succeeded and produced zero owners and zero moderation flags, which
says the assumption is wrong somewhere but not where.

This reports where those keys actually live. It prints structure — key names,
types, and the small set of moderation/owner values — not skill content, so the
output is safe to paste into an issue.

Must run somewhere that can reach the registry (e.g. CI); the dev sandbox
cannot.

Usage:
    inspect-detail-shape.py <slug> [<slug> ...]
"""

from __future__ import annotations

import asyncio
import json
import sys

import httpx

BASE_URL = "https://clawhub.ai/api/v1"
# Keys worth locating wherever they turn up in the tree.
INTERESTING = {
    "owner", "moderation", "author", "user", "publisher", "username",
    "isMalwareBlocked", "isPendingScan", "isSuspicious", "isHiddenByMod",
    "isRemoved", "createdBy", "ownerId", "userId",
}


def walk(node: object, path: str = "") -> list[tuple[str, str, object]]:
    """Yield (path, type, value-or-summary) for every key in the response."""
    out: list[tuple[str, str, object]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            if isinstance(value, dict):
                out.append((here, "object", f"{len(value)} keys"))
                out.extend(walk(value, here))
            elif isinstance(value, list):
                out.append((here, "array", f"{len(value)} items"))
                if value and isinstance(value[0], dict):
                    out.extend(walk(value[0], f"{here}[0]"))
            else:
                # Values are only printed for the keys we are chasing; anything
                # else is reported as a type so skill content never leaks in.
                shown = value if key in INTERESTING else type(value).__name__
                out.append((here, type(value).__name__, shown))
    return out


async def inspect(slug: str) -> None:
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(f"{BASE_URL}/skills/{slug}")
    print(f"\n{'=' * 70}\n{slug}  ->  HTTP {resp.status_code}\n{'=' * 70}")
    if resp.status_code != 200:
        print(resp.text[:400])
        return

    data = resp.json()
    print(f"top-level keys: {sorted(data.keys())}")
    if isinstance(data.get("skill"), dict):
        print(f"skill.* keys:   {sorted(data['skill'].keys())}")

    print("\nfull key tree:")
    for path, kind, value in walk(data):
        marker = "  <<<" if path.split(".")[-1] in INTERESTING else ""
        print(f"  {path:<46} {kind:<8} {value}{marker}")

    # The specific question: does the current extraction find anything?
    print("\nwhat the current parser would extract:")
    print(f"  data['owner']            -> {json.dumps(data.get('owner'))}")
    print(f"  data['moderation']       -> {json.dumps(data.get('moderation'))}")
    skill = data.get("skill", {})
    if isinstance(skill, dict):
        print(f"  data['skill']['owner']      -> {json.dumps(skill.get('owner'))}")
        print(f"  data['skill']['moderation'] -> {json.dumps(skill.get('moderation'))}")


async def survey(slugs: list[str]) -> None:
    """Report how often owner and moderation are actually populated.

    The first inspection found ``moderation`` present as a key but ``null`` on
    every skill looked at. Three skills cannot tell you whether the field is
    never populated or merely rare, and the difference decides whether the
    platform comparison is measurable at all. This counts it over a sample and
    prints any skill where moderation is non-null, since one example is enough
    to prove the field can carry data.
    """
    owners = mods = ok = 0
    populated: list[str] = []
    for slug in slugs:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(f"{BASE_URL}/skills/{slug}")
            if resp.status_code != 200:
                continue
            data = resp.json()
            ok += 1
            if data.get("owner"):
                owners += 1
            if data.get("moderation") is not None:
                mods += 1
                populated.append(f"{slug}: {json.dumps(data['moderation'])}")
        except Exception as exc:
            print(f"  {slug}: {type(exc).__name__}: {exc}")
        await asyncio.sleep(0.55)

    print(f"\n{'=' * 70}\nSURVEY over {len(slugs)} slugs ({ok} returned 200)\n{'=' * 70}")
    print(f"  owner populated:      {owners}/{ok}")
    print(f"  moderation non-null:  {mods}/{ok}")
    if populated:
        print("\n  skills carrying moderation data:")
        for line in populated[:20]:
            print(f"    {line}")
    else:
        print(
            "\n  moderation was null on every skill sampled. On this evidence the\n"
            "  platform's screening state is not exposed here, so the comparison\n"
            "  cannot be made from this endpoint -- null must NOT be read as\n"
            "  'the platform cleared it'."
        )


async def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--survey":
        await survey(args[1:])
        return 0

    slugs = args
    if not slugs:
        print(__doc__)
        return 2
    for slug in slugs:
        try:
            await inspect(slug)
        except Exception as exc:
            print(f"\n{slug}: FAILED {type(exc).__name__}: {exc}")
        await asyncio.sleep(0.6)  # stay well inside the 120 req/min limit
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
