"""Extract the files a SKILL.md names, so the rest of the package can be read.

The sweep scans one file per skill. A skill whose SKILL.md is clean and whose
``scripts/*.js`` beacons out is invisible to that scan, to a reviewer skimming
the listing, and to the user -- which is the definition of hidden behaviour and
the only place a real supply-chain payload would sit.

Extraction is deliberately conservative: a path is reported only when the skill
*names* it. Guessing at conventional layouts (``scripts/*``, ``bin/*``) would
produce a larger figure built partly on files that do not exist, and an
inflated denominator is how you publish a blind spot bigger than the one you
have.
"""

from __future__ import annotations

import re

# Interpreters and runners whose argument is a file the skill expects to run.
_RUNNERS = r"(?:node|python3?|bun|deno|ts-node|tsx|bash|sh|zsh|ruby|perl|php|Rscript)"

# Extensions that are executable code, as opposed to prose or config.
EXECUTABLE_SUFFIXES: frozenset[str] = frozenset(
    {".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".sh", ".bash", ".rb", ".pl", ".php", ".r"}
)

# How a SKILL.md names a file it ships. Each pattern captures the path in
# group 1. Order matters: the first match wins, so the strongest label (a file
# the agent is told to execute) is checked before the weakest (a mention).
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            rf"\b{_RUNNERS}\s+(?:\$\{{SKILL_DIR\}}/|\./)?"
            r"([\w./-]+\.(?:js|mjs|cjs|ts|tsx|py|sh|bash|rb|pl|php|R))\b"
        ),
        "executed",
    ),
    (
        re.compile(r"\b(?:Read|read|Load|load|See|see)\s+`([\w./-]+\.[\w]+)`"),
        "read-instruction",
    ),
    (
        re.compile(
            r"[\(\[`\s](?:\./)?"
            r"((?:scripts|bin|lib|src|tools|references|assets|specs)/[\w./-]+"
            r"\.(?:js|mjs|cjs|ts|tsx|py|sh|bash|rb|pl|php|R|md|json|ya?ml|toml))"
        ),
        "referenced",
    ),
]

# Not part of the skill package: the file already scanned, and files belonging
# to the user's own project rather than to the skill.
_SKIP = re.compile(
    r"^(?:SKILL\.md|README\.md|package(?:-lock)?\.json|tsconfig\.json"
    r"|\.env(?:\.example)?|node_modules/.*)$",
    re.IGNORECASE,
)


def clean_path(path: str) -> str | None:
    """Normalise a captured path, or return None when it is not skill-local.

    Anything absolute, user-home-relative, remote, or escaping the package with
    ``..`` is rejected: those are not files the registry would serve for this
    skill, and counting them would inflate the surface with paths that cannot
    be fetched.
    """
    path = path.strip().strip("`'\"")
    path = re.sub(r"^\$\{SKILL_DIR\}/", "", path)
    path = re.sub(r"^\./", "", path)
    if not path or path.startswith(("/", "~", "http")) or ".." in path:
        return None
    if _SKIP.match(path):
        return None
    if "." not in path:
        return None
    return path


def extract(text: str) -> dict[str, str]:
    """Return ``{path: how it was referenced}`` for one SKILL.md."""
    found: dict[str, str] = {}
    for pattern, kind in _PATTERNS:
        for match in pattern.finditer(text):
            cleaned = clean_path(match.group(1))
            if cleaned and cleaned not in found:
                found[cleaned] = kind
    return found


def is_executable(path: str) -> bool:
    """True when the path looks like code rather than prose or config."""
    dot = path.rfind(".")
    return dot != -1 and path[dot:].lower() in EXECUTABLE_SUFFIXES
