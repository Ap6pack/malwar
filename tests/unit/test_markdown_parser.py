# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for the markdown parser utilities."""

from __future__ import annotations

from malwar.parsers.markdown_parser import extract_code_blocks, extract_sections, extract_urls

# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


class TestExtractUrls:
    """Tests for extract_urls."""

    def test_markdown_links(self) -> None:
        content = "Check [the docs](https://docs.python.org/3/) for details."
        urls = extract_urls(content)
        assert "https://docs.python.org/3/" in urls

    def test_bare_urls(self) -> None:
        content = "Visit https://example.com for more info."
        urls = extract_urls(content)
        assert "https://example.com" in urls

    def test_urls_in_code_blocks(self) -> None:
        content = """\
```bash
curl https://api.example.com/v1/data
```
"""
        urls = extract_urls(content)
        assert "https://api.example.com/v1/data" in urls

    def test_deduplication(self) -> None:
        content = """\
Visit [link](https://example.com) and also https://example.com again.
"""
        urls = extract_urls(content)
        assert urls.count("https://example.com") == 1

    def test_multiple_urls(self) -> None:
        content = """\
- [Python](https://python.org)
- [Rust](https://www.rust-lang.org)
- Also see https://golang.org
"""
        urls = extract_urls(content)
        assert len(urls) == 3
        assert "https://python.org" in urls
        assert "https://www.rust-lang.org" in urls
        assert "https://golang.org" in urls

    def test_http_urls(self) -> None:
        content = "Insecure link: http://example.com/path"
        urls = extract_urls(content)
        assert "http://example.com/path" in urls

    def test_no_urls(self) -> None:
        content = "No links here, just plain text."
        urls = extract_urls(content)
        assert urls == []

    def test_url_with_trailing_punctuation(self) -> None:
        content = "See https://example.com/page. Also https://other.com/path, and more."
        urls = extract_urls(content)
        assert "https://example.com/page" in urls
        assert "https://other.com/path" in urls

    def test_url_with_query_params(self) -> None:
        content = "Go to https://example.com/search?q=test&page=1 for results."
        urls = extract_urls(content)
        assert "https://example.com/search?q=test&page=1" in urls

    def test_mixed_markdown_and_bare(self) -> None:
        content = """\
See [docs](https://docs.example.com) and also
https://api.example.com/v2 for the API.
"""
        urls = extract_urls(content)
        assert len(urls) == 2


# ---------------------------------------------------------------------------
# Code block extraction
# ---------------------------------------------------------------------------


class TestExtractCodeBlocks:
    """Tests for extract_code_blocks."""

    def test_single_block_with_language(self) -> None:
        content = """\
Some text.

```python
print("hello")
```

More text.
"""
        blocks = extract_code_blocks(content)
        assert len(blocks) == 1
        assert blocks[0].language == "python"
        assert 'print("hello")' in blocks[0].content

    def test_single_block_no_language(self) -> None:
        content = """\
```
plain code
```
"""
        blocks = extract_code_blocks(content)
        assert len(blocks) == 1
        assert blocks[0].language is None
        assert "plain code" in blocks[0].content

    def test_multiple_blocks(self) -> None:
        content = """\
```bash
echo "one"
```

```python
print("two")
```

```json
{"three": 3}
```
"""
        blocks = extract_code_blocks(content)
        assert len(blocks) == 3
        assert blocks[0].language == "bash"
        assert blocks[1].language == "python"
        assert blocks[2].language == "json"

    def test_line_numbers(self) -> None:
        content = """\
Line 1
Line 2
```bash
echo "hello"
```
Line 6
"""
        blocks = extract_code_blocks(content)
        assert len(blocks) == 1
        # The fence starts on line 3 (1-based)
        assert blocks[0].line_start == 3

    def test_no_code_blocks(self) -> None:
        content = "Just plain text with no code blocks."
        blocks = extract_code_blocks(content)
        assert blocks == []

    def test_tilde_fence(self) -> None:
        content = """\
~~~ruby
puts "hello"
~~~
"""
        blocks = extract_code_blocks(content)
        assert len(blocks) == 1
        assert blocks[0].language == "ruby"

    def test_multiline_block(self) -> None:
        content = """\
```python
def greet(name):
    return f"Hello, {name}!"

if __name__ == "__main__":
    print(greet("world"))
```
"""
        blocks = extract_code_blocks(content)
        assert len(blocks) == 1
        assert "def greet(name):" in blocks[0].content
        assert 'print(greet("world"))' in blocks[0].content


# ---------------------------------------------------------------------------
# Section extraction
# ---------------------------------------------------------------------------


class TestExtractSections:
    """Tests for extract_sections."""

    def test_h2_sections(self) -> None:
        content = """\
## Setup

Install the package.

## Usage

Run the tool.

## Notes

Additional info.
"""
        sections = extract_sections(content)
        assert len(sections) == 3
        assert sections[0].heading == "Setup"
        assert sections[0].level == 2
        assert "Install the package." in sections[0].content
        assert sections[1].heading == "Usage"
        assert sections[2].heading == "Notes"

    def test_mixed_heading_levels(self) -> None:
        content = """\
# Title

Intro text.

## Section One

First section body.

### Sub Section

Nested content.

## Section Two

Second section body.
"""
        sections = extract_sections(content)
        assert len(sections) == 4
        assert sections[0].heading == "Title"
        assert sections[0].level == 1
        assert sections[1].heading == "Section One"
        assert sections[1].level == 2
        assert sections[2].heading == "Sub Section"
        assert sections[2].level == 3
        assert sections[3].heading == "Section Two"
        assert sections[3].level == 2

    def test_no_headings(self) -> None:
        content = "Just text, no headings at all."
        sections = extract_sections(content)
        assert sections == []

    def test_section_line_numbers(self) -> None:
        content = """\
## First

Content A.

## Second

Content B.
"""
        sections = extract_sections(content)
        assert len(sections) == 2
        # First heading is on line 1
        assert sections[0].line_start == 1
        # Second heading starts on line 5
        assert sections[1].line_start == 5

    def test_section_content_includes_code_blocks(self) -> None:
        content = """\
## Example

```python
print("hello")
```
"""
        sections = extract_sections(content)
        assert len(sections) == 1
        assert "```python" in sections[0].content

    def test_single_section(self) -> None:
        content = """\
## Only Section

All the content goes here.
More lines.
Even more.
"""
        sections = extract_sections(content)
        assert len(sections) == 1
        assert sections[0].heading == "Only Section"
        assert "All the content goes here." in sections[0].content
