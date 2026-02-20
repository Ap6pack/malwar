# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Extract and normalize all URLs from SKILL.md content."""

from __future__ import annotations

import re
from urllib.parse import urldefrag, urlparse

from malwar.models.skill import SkillContent

# Markdown link pattern: [text](url)
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]*)\]\((\s*https?://[^\s\)]+)\)")

# Bare URL pattern: https?://...
_BARE_URL_RE = re.compile(r"https?://[^\s<>\)\]\"'`]+")

# Fenced code block boundaries
_CODE_FENCE_RE = re.compile(r"^(`{3,}|~{3,})", re.MULTILINE)


def _normalize_url(url: str) -> str:
    """Normalize a URL by stripping fragments and trailing punctuation."""
    url = url.strip()
    # Strip trailing punctuation that is unlikely to be part of the URL
    while url and url[-1] in (".", ",", ";", ":", "!", "?"):
        url = url[:-1]
    # Strip trailing parentheses only if unbalanced
    while url.endswith(")") and url.count(")") > url.count("("):
        url = url[:-1]
    # Remove fragment
    url, _ = urldefrag(url)
    return url


def _is_valid_url(url: str) -> bool:
    """Check if a URL is syntactically valid."""
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme in ("http", "https") and parsed.netloc)
    except Exception:
        return False


def _find_code_block_ranges(text: str) -> list[tuple[int, int]]:
    """Return (start_offset, end_offset) pairs for fenced code blocks."""
    ranges: list[tuple[int, int]] = []
    fence_iter = _CODE_FENCE_RE.finditer(text)
    open_fence: re.Match[str] | None = None
    open_marker: str = ""

    for match in fence_iter:
        marker = match.group(1)
        if open_fence is None:
            open_fence = match
            open_marker = marker[0]  # ` or ~
        elif marker[0] == open_marker and len(marker) >= len(open_fence.group(1)):
            ranges.append((open_fence.start(), match.end()))
            open_fence = None
            open_marker = ""

    return ranges


def _offset_in_code_block(offset: int, ranges: list[tuple[int, int]]) -> bool:
    """Check whether a character offset falls within any code block range."""
    return any(start <= offset <= end for start, end in ranges)


def extract_urls(skill: SkillContent) -> list[str]:
    """Extract and deduplicate all URLs from a skill.

    Sources checked:
    - Frontmatter fields (source_url, author_url)
    - Markdown links ``[text](url)``
    - Bare URLs in prose and code blocks
    """
    seen: set[str] = set()
    result: list[str] = []

    def _add(url: str) -> None:
        normalized = _normalize_url(url)
        if normalized and _is_valid_url(normalized) and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)

    # 1. Frontmatter URLs
    if skill.metadata.source_url:
        _add(skill.metadata.source_url)
    if skill.metadata.author_url:
        _add(skill.metadata.author_url)

    # Also scan raw_frontmatter for any other URL-bearing fields
    for _key, value in skill.metadata.raw_frontmatter.items():
        if isinstance(value, str) and re.match(r"https?://", value):
            _add(value)

    # 2. Body markdown URLs
    body = skill.body_markdown or skill.raw_content

    # 2a. Markdown links
    for match in _MARKDOWN_LINK_RE.finditer(body):
        _add(match.group(2).strip())

    # 2b. Bare URLs (covers both prose and code blocks)
    for match in _BARE_URL_RE.finditer(body):
        _add(match.group(0))

    # 3. Code block contents (ensure URLs inside code blocks are captured)
    for block in skill.code_blocks:
        for match in _BARE_URL_RE.finditer(block.content):
            _add(match.group(0))

    return result
