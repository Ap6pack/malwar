# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for the SKILL.md skill parser."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from malwar.core.exceptions import ParseError
from malwar.parsers.skill_parser import parse_skill_content, parse_skill_file

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "skills"
BENIGN_DIR = FIXTURES_DIR / "benign"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_SKILL = """\
---
name: Test Skill
description: A test skill.
author: Tester
---

# Test Skill

Hello, world!
"""


# ---------------------------------------------------------------------------
# Basic parsing
# ---------------------------------------------------------------------------


class TestParseSkillContent:
    """Tests for parse_skill_content (synchronous, string input)."""

    def test_full_frontmatter(self) -> None:
        raw = """\
---
name: My Skill
description: Does things.
version: "2.0"
author: Alice
author_url: https://alice.dev
source_url: https://github.com/alice/skill
tags:
  - util
  - demo
icon: wrench
tools:
  - bash
  - python
---

# Body

Some markdown here.
"""
        result = parse_skill_content(raw)

        assert result.metadata.name == "My Skill"
        assert result.metadata.description == "Does things."
        assert result.metadata.version == "2.0"
        assert result.metadata.author == "Alice"
        assert result.metadata.author_url == "https://alice.dev"
        assert result.metadata.source_url == "https://github.com/alice/skill"
        assert result.metadata.tags == ["util", "demo"]
        assert result.metadata.icon == "wrench"
        assert result.metadata.tools == ["bash", "python"]
        assert "# Body" in result.body_markdown
        assert result.file_path == "<stdin>"

    def test_missing_frontmatter(self) -> None:
        raw = "# No Frontmatter\n\nJust some text."
        result = parse_skill_content(raw)

        assert result.metadata.name is None
        assert result.metadata.author is None
        assert result.metadata.tags == []
        assert "Just some text." in result.body_markdown

    def test_partial_frontmatter(self) -> None:
        raw = """\
---
name: Partial
---

Content here.
"""
        result = parse_skill_content(raw)

        assert result.metadata.name == "Partial"
        assert result.metadata.description is None
        assert result.metadata.author is None
        assert result.metadata.version is None

    def test_empty_frontmatter(self) -> None:
        raw = """\
---
---

Body only.
"""
        result = parse_skill_content(raw)

        assert result.metadata.name is None
        assert "Body only." in result.body_markdown

    def test_sha256_hash(self) -> None:
        raw = MINIMAL_SKILL
        expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        result = parse_skill_content(raw)

        assert result.sha256_hash == expected

    def test_file_size_bytes(self) -> None:
        raw = MINIMAL_SKILL
        result = parse_skill_content(raw)

        assert result.file_size_bytes == len(raw.encode("utf-8"))

    def test_file_path_default(self) -> None:
        result = parse_skill_content(MINIMAL_SKILL)
        assert result.file_path == "<stdin>"

    def test_file_path_custom(self) -> None:
        result = parse_skill_content(MINIMAL_SKILL, file_path="/tmp/test.md")
        assert result.file_path == "/tmp/test.md"

    def test_raw_content_preserved(self) -> None:
        result = parse_skill_content(MINIMAL_SKILL)
        assert result.raw_content == MINIMAL_SKILL

    def test_tags_as_csv_string(self) -> None:
        raw = """\
---
name: CSV Tags
tags: "one, two, three"
---

Content.
"""
        result = parse_skill_content(raw)
        assert result.metadata.tags == ["one", "two", "three"]

    def test_version_as_number(self) -> None:
        raw = """\
---
name: Numeric Version
version: 2
---

Content.
"""
        result = parse_skill_content(raw)
        assert result.metadata.version == "2"


# ---------------------------------------------------------------------------
# Async file-based parsing
# ---------------------------------------------------------------------------


class TestParseSkillFile:
    """Tests for parse_skill_file (async, file-path input)."""

    async def test_parse_benign_hello_world(self) -> None:
        path = str(BENIGN_DIR / "hello_world.md")
        result = await parse_skill_file(path)

        assert result.metadata.name == "Hello World"
        assert result.metadata.author == "Jane Smith"
        assert result.file_size_bytes > 0
        assert result.sha256_hash

    async def test_parse_benign_code_formatter(self) -> None:
        path = str(BENIGN_DIR / "code_formatter.md")
        result = await parse_skill_file(path)

        assert result.metadata.name == "Code Formatter"
        assert "prettier" in result.metadata.tags
        assert len(result.code_blocks) >= 3
        assert len(result.urls) >= 1

    async def test_parse_benign_git_helper(self) -> None:
        path = str(BENIGN_DIR / "git_helper.md")
        result = await parse_skill_file(path)

        assert result.metadata.name == "Git Helper"
        assert len(result.code_blocks) >= 4

    async def test_parse_benign_web_search(self) -> None:
        path = str(BENIGN_DIR / "web_search.md")
        result = await parse_skill_file(path)

        assert result.metadata.name == "Web Search"
        assert any("search.brave.com" in u for u in result.urls)

    async def test_parse_benign_legitimate_with_urls(self) -> None:
        path = str(BENIGN_DIR / "legitimate_with_urls.md")
        result = await parse_skill_file(path)

        assert result.metadata.name == "Python Documentation Helper"
        url_str = " ".join(result.urls)
        assert "docs.python.org" in url_str
        assert "github.com" in url_str
        assert "npmjs.com" in url_str

    async def test_nonexistent_file_raises(self) -> None:
        with pytest.raises(ParseError, match="Cannot read"):
            await parse_skill_file("/nonexistent/path/SKILL.md")


# ---------------------------------------------------------------------------
# All malicious fixtures must parse without crashing
# ---------------------------------------------------------------------------


class TestMaliciousFixturesParseable:
    """Every malicious fixture must be parseable without exceptions."""

    MALICIOUS_FILES = [
        "clawhavoc_amos.md",
        "base64_reverse_shell.md",
        "clickfix_fake_prereq.md",
        "prompt_injection_basic.md",
        "prompt_injection_unicode.md",
        "credential_harvester.md",
        "exfil_soul_md.md",
        "typosquatted_package.md",
        "obfuscated_curl.md",
        "multi_stage_dropper.md",
    ]

    @pytest.mark.parametrize("filename", MALICIOUS_FILES)
    async def test_malicious_fixture_parses(self, filename: str) -> None:
        path = str(MALICIOUS_DIR / filename)
        result = await parse_skill_file(path)

        # Must have produced a valid SkillContent with non-empty raw content
        assert result.raw_content
        assert result.sha256_hash
        assert result.file_size_bytes > 0
        # Must have parsed metadata (at minimum the raw_frontmatter dict)
        assert isinstance(result.metadata.raw_frontmatter, dict)

    async def test_clawhavoc_metadata(self) -> None:
        path = str(MALICIOUS_DIR / "clawhavoc_amos.md")
        result = await parse_skill_file(path)

        assert result.metadata.author == "Aslaep123"
        assert result.metadata.name == "Polymarket Trading Bot"

    async def test_credential_harvester_urls(self) -> None:
        path = str(MALICIOUS_DIR / "credential_harvester.md")
        result = await parse_skill_file(path)

        assert any("api-validator.tools-hub.io" in u for u in result.urls)

    async def test_multi_stage_dropper_urls(self) -> None:
        path = str(MALICIOUS_DIR / "multi_stage_dropper.md")
        result = await parse_skill_file(path)

        assert any("sk-tools-org" in u for u in result.urls)

    async def test_typosquatted_name(self) -> None:
        path = str(MALICIOUS_DIR / "typosquatted_package.md")
        result = await parse_skill_file(path)

        assert result.metadata.name == "polymarket-traiding-bot"
