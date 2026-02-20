# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Extract structured elements from a markdown body."""

from __future__ import annotations

import re

from malwar.models.skill import CodeBlock, MarkdownSection

# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

# Matches markdown links: [text](url)
_MD_LINK_RE = re.compile(r"\[(?:[^\[\]]*)\]\((https?://[^\s\)]+)\)")

# Matches bare URLs (https:// or http://) not already inside a markdown link
_BARE_URL_RE = re.compile(r"(?<!\()(https?://[^\s\)\]>\"'`]+)")


def extract_urls(content: str) -> list[str]:
    """Return a de-duplicated, order-preserving list of all URLs found in *content*.

    Captures:
    * Markdown links  ``[text](url)``
    * Bare ``https?://`` URLs
    * URLs inside fenced code blocks
    """
    seen: set[str] = set()
    result: list[str] = []

    for match in _MD_LINK_RE.finditer(content):
        url = match.group(1)
        if url not in seen:
            seen.add(url)
            result.append(url)

    for match in _BARE_URL_RE.finditer(content):
        url = match.group(1)
        # Strip common trailing punctuation that is not part of the URL
        url = url.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            result.append(url)

    return result


# ---------------------------------------------------------------------------
# Code block extraction
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(
    r"^(?P<fence>`{3,}|~{3,})(?P<lang>\w*)[^\n]*\n(?P<body>.*?)^(?P=fence)\s*$",
    re.MULTILINE | re.DOTALL,
)


def extract_code_blocks(content: str) -> list[CodeBlock]:
    """Return all fenced code blocks with language, content and line numbers."""
    blocks: list[CodeBlock] = []
    for match in _FENCE_RE.finditer(content):
        lang = match.group("lang").strip() or None
        body = match.group("body")
        # Compute 1-based line numbers within *content*
        start = content[: match.start()].count("\n") + 1
        end = start + match.group(0).count("\n")
        blocks.append(
            CodeBlock(
                language=lang,
                content=body,
                line_start=start,
                line_end=end,
            )
        )
    return blocks


# ---------------------------------------------------------------------------
# Section extraction
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$", re.MULTILINE)


def extract_sections(content: str) -> list[MarkdownSection]:
    """Split *content* into heading-delimited sections.

    Each section runs from its heading to the line before the next heading of
    equal or higher level (or end-of-content).
    """
    headings = list(_HEADING_RE.finditer(content))
    if not headings:
        return []

    lines = content.split("\n")
    sections: list[MarkdownSection] = []

    for idx, match in enumerate(headings):
        level = len(match.group(1))
        heading_text = match.group(2).strip()
        line_start = content[: match.start()].count("\n") + 1

        # Determine where this section ends
        if idx + 1 < len(headings):
            next_start = content[: headings[idx + 1].start()].count("\n") + 1
            line_end = next_start - 1
        else:
            line_end = len(lines)

        # Section body is everything after the heading line up to line_end
        body_lines = lines[line_start : line_end]  # line_start is 1-based heading line
        section_content = "\n".join(body_lines).strip()

        sections.append(
            MarkdownSection(
                heading=heading_text,
                level=level,
                content=section_content,
                line_start=line_start,
                line_end=line_end,
            )
        )

    return sections
