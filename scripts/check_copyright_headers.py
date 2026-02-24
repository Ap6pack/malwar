#!/usr/bin/env python3
# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Check that all source files contain the required copyright header.

Exits 0 if all files pass, 1 if any are missing.
With --add, inserts the header into non-compliant files and exits 0.
"""

import argparse
import re
import sys
from pathlib import Path

# Matches: Copyright (c) <4-digit year> Veritas Aequitas Holdings LLC
PATTERN = re.compile(r"Copyright\s+\(c\)\s+\d{4}\s+Veritas Aequitas Holdings LLC")

HEADERS = {
    ".py": "# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.\n",
    ".ts": "// Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.\n",
    ".tsx": "// Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.\n",
    ".css": "/* Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. */\n",
    ".html": "<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->\n",
    ".md": "<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->\n",
    ".yml": "# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.\n",
    ".yaml": "# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.\n",
    ".sh": "# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.\n",
}


def has_header(path: Path) -> bool:
    """Return True if the first 10 lines contain the copyright pattern."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return True  # skip unreadable files
    head = "\n".join(text.splitlines()[:10])
    return bool(PATTERN.search(head))


def add_header(path: Path) -> bool:
    """Prepend the copyright header. Returns True if modified."""
    ext = path.suffix
    if ext not in HEADERS:
        return False
    text = path.read_text(encoding="utf-8")
    if PATTERN.search("\n".join(text.splitlines()[:10])):
        return False
    path.write_text(HEADERS[ext] + text, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Check copyright headers.")
    parser.add_argument("files", nargs="*", help="Files to check")
    parser.add_argument("--add", action="store_true", help="Add missing headers")
    args = parser.parse_args()

    missing = [Path(f) for f in args.files if not has_header(Path(f))]

    if args.add:
        added = [f for f in missing if add_header(f)]
        if added:
            print(f"Added copyright headers to {len(added)} files:")
            for f in added:
                print(f"  {f}")
        else:
            print("All files have copyright headers.")
        return 0

    if missing:
        print(f"Missing copyright headers in {len(missing)} files:")
        for f in missing:
            print(f"  {f}")
        return 1

    print("All files have copyright headers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
