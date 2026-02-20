# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Skill file and metadata models."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class SkillMetadata(BaseModel):
    """Parsed frontmatter from a SKILL.md file."""

    name: str | None = None
    description: str | None = None
    version: str | None = None
    author: str | None = None
    author_url: str | None = None
    source_url: str | None = None
    tags: list[str] = Field(default_factory=list)
    icon: str | None = None
    tools: list[str] = Field(default_factory=list)
    raw_frontmatter: dict[str, object] = Field(default_factory=dict)


class CodeBlock(BaseModel):
    """A fenced code block extracted from markdown."""

    language: str | None = None
    content: str
    line_start: int
    line_end: int


class MarkdownSection(BaseModel):
    """A heading-delimited section of the markdown body."""

    heading: str
    level: int
    content: str
    line_start: int
    line_end: int


class SkillContent(BaseModel):
    """Fully parsed SKILL.md content."""

    file_path: str
    raw_content: str
    metadata: SkillMetadata = Field(default_factory=SkillMetadata)
    body_markdown: str = ""
    code_blocks: list[CodeBlock] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    sections: list[MarkdownSection] = Field(default_factory=list)
    file_size_bytes: int = 0
    sha256_hash: str = ""
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
