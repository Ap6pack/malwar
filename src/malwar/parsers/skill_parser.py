"""Parse SKILL.md files into SkillContent objects."""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

import aiofiles
import frontmatter

from malwar.core.exceptions import ParseError
from malwar.models.skill import CodeBlock, MarkdownSection, SkillContent, SkillMetadata
from malwar.parsers.markdown_parser import extract_code_blocks, extract_sections, extract_urls

logger = logging.getLogger("malwar.parsers.skill")

# A leading `---` ... `---` block, i.e. the frontmatter fence, even when what is
# inside it is not valid YAML.
_FRONTMATTER_FENCE = re.compile(r"\A﻿?\s*---\s*\n.*?\n---\s*(?:\n|\Z)", re.DOTALL)


def _strip_unparseable_frontmatter(raw_content: str) -> str:
    """Return the body of a skill whose frontmatter fence will not parse as YAML.

    Drops a leading ``---`` fenced block if present so header keys are not
    mistaken for body prose; if no complete fence is found the content is
    returned untouched, because scanning too much is safe and scanning nothing
    is not.
    """
    return _FRONTMATTER_FENCE.sub("", raw_content, count=1)


def _str_or_none(val: object) -> str | None:
    """Coerce a frontmatter value to str or None."""
    return str(val) if val is not None else None


def _build_metadata(fm_data: dict[str, object]) -> SkillMetadata:
    """Build a SkillMetadata from frontmatter dict, tolerating missing keys."""
    tags_raw = fm_data.get("tags", [])
    if isinstance(tags_raw, str):
        tags_raw = [t.strip() for t in tags_raw.split(",") if t.strip()]
    elif not isinstance(tags_raw, list):
        tags_raw = []

    tools_raw = fm_data.get("tools", [])
    if isinstance(tools_raw, str):
        tools_raw = [t.strip() for t in tools_raw.split(",") if t.strip()]
    elif not isinstance(tools_raw, list):
        tools_raw = []

    return SkillMetadata(
        name=_str_or_none(fm_data.get("name")),
        description=_str_or_none(fm_data.get("description")),
        version=str(fm_data["version"]) if "version" in fm_data else None,
        author=_str_or_none(fm_data.get("author")),
        author_url=_str_or_none(fm_data.get("author_url")),
        source_url=_str_or_none(fm_data.get("source_url")),
        tags=[str(t) for t in tags_raw],
        icon=_str_or_none(fm_data.get("icon")),
        tools=[str(t) for t in tools_raw],
        raw_frontmatter=fm_data,
    )


def parse_skill_content(raw_content: str, file_path: str = "<stdin>") -> SkillContent:
    """Parse raw SKILL.md content into a SkillContent object.

    Parameters
    ----------
    raw_content:
        The full text of the SKILL.md file (including frontmatter fences).
    file_path:
        An identifier for the source; defaults to ``<stdin>`` for ad-hoc input.

    Returns
    -------
    SkillContent with all fields populated.

    Raises
    ------
    ParseError
        If the content cannot be processed at all (e.g. binary junk).
    """
    try:
        post = frontmatter.loads(raw_content)
        fm_data: dict[str, object] = dict(post.metadata) if post.metadata else {}
        body: str = post.content
    except Exception as exc:
        # Unparseable frontmatter must NOT stop the scan. Refusing to analyse a
        # file whose YAML header is malformed is a working evasion: the payload
        # lives in the body, so an attacker only has to break the header (a
        # stray colon is enough) to skip detection entirely. Fall back to
        # scanning the raw text, minus any leading fenced header, so every
        # content rule still runs.
        logger.warning(
            "Frontmatter in %s did not parse (%s); scanning raw content instead "
            "so a malformed header cannot be used to evade detection.",
            file_path,
            exc,
        )
        fm_data = {}
        body = _strip_unparseable_frontmatter(raw_content)

    metadata = _build_metadata(fm_data)
    sha256 = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()

    code_blocks: list[CodeBlock] = extract_code_blocks(body)
    urls: list[str] = extract_urls(body)
    sections: list[MarkdownSection] = extract_sections(body)

    return SkillContent(
        file_path=file_path,
        raw_content=raw_content,
        metadata=metadata,
        body_markdown=body,
        code_blocks=code_blocks,
        urls=urls,
        sections=sections,
        file_size_bytes=len(raw_content.encode("utf-8")),
        sha256_hash=sha256,
    )


async def parse_skill_file(file_path: str) -> SkillContent:
    """Read a SKILL.md from disk and parse it.

    Parameters
    ----------
    file_path:
        Filesystem path to the SKILL.md file.

    Returns
    -------
    SkillContent with ``file_path`` set to the resolved absolute path.

    Raises
    ------
    ParseError
        If the file cannot be read or parsed.
    """
    resolved = str(Path(file_path).resolve())
    try:
        async with aiofiles.open(resolved, encoding="utf-8") as fh:
            raw_content = await fh.read()
    except OSError as exc:
        raise ParseError(f"Cannot read {resolved}: {exc}") from exc

    return parse_skill_content(raw_content, file_path=resolved)
