<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Malwar Python SDK

The Malwar SDK provides a clean Python interface for embedding skill-file scanning
directly in your tools, CI pipelines, or automation scripts -- without going through
the HTTP API.

## Installation

```bash
pip install malwar
```

## Quick Start

### Synchronous usage

```python
from malwar import scan_sync

result = scan_sync(open("SKILL.md").read())
print(result.verdict)      # "CLEAN", "CAUTION", "SUSPICIOUS", or "MALICIOUS"
print(result.risk_score)   # 0-100
print(result.findings)     # list of Finding objects
```

### Async usage

```python
import asyncio
from malwar import scan

async def check_skill(content: str):
    result = await scan(content, file_name="my_skill.md")
    if result.verdict != "CLEAN":
        print(f"Risk detected: {result.verdict} (score={result.risk_score})")
        for finding in result.findings:
            print(f"  [{finding.severity}] {finding.title}")

asyncio.run(check_skill(open("SKILL.md").read()))
```

## API Reference

### `scan(content, *, file_name, use_llm, use_urls, layers) -> ScanResult`

Asynchronous scan of raw SKILL.md content.

| Parameter   | Type              | Default      | Description                                  |
|-------------|-------------------|--------------|----------------------------------------------|
| `content`   | `str`             | *(required)* | Full text of the SKILL.md file               |
| `file_name` | `str`             | `"SKILL.md"` | Label used as the target in the result       |
| `use_llm`   | `bool`            | `True`       | Whether to run the LLM analysis layer        |
| `use_urls`  | `bool`            | `True`       | Whether to run the URL crawler layer         |
| `layers`    | `list[str] | None`| `None`       | Explicit list of layers; overrides other flags|

### `scan_sync(content, **kwargs) -> ScanResult`

Synchronous wrapper that calls `asyncio.run(scan(...))`. Accepts the same
parameters as `scan()`. Must not be called from within an already-running
event loop.

### `scan_file(path, *, file_name, use_llm, use_urls, layers) -> ScanResult`

Asynchronous scan that reads a file from disk first.

| Parameter   | Type              | Default      | Description                                  |
|-------------|-------------------|--------------|----------------------------------------------|
| `path`      | `str | Path`      | *(required)* | Path to the SKILL.md file on disk            |
| `file_name` | `str | None`      | `None`       | Override for the label; defaults to file name |
| `use_llm`   | `bool`            | `True`       | Whether to run the LLM analysis layer        |
| `use_urls`  | `bool`            | `True`       | Whether to run the URL crawler layer         |
| `layers`    | `list[str] | None`| `None`       | Explicit list of layers to execute           |

### `scan_file_sync(path, **kwargs) -> ScanResult`

Synchronous wrapper around `scan_file()`.

### `scan_batch(items, *, use_llm, use_urls, layers) -> list[ScanResult]`

Scan multiple skills in sequence. Each item in the list is a dict with:

| Key         | Type   | Required | Description                        |
|-------------|--------|----------|------------------------------------|
| `content`   | `str`  | Yes      | Raw SKILL.md text                  |
| `file_name` | `str`  | No       | Label for this item (default: `"SKILL.md"`) |

The `use_llm`, `use_urls`, and `layers` parameters apply to every item
in the batch.

## Return Type: `ScanResult`

All functions return a `ScanResult` Pydantic model with these key fields:

| Field                    | Type               | Description                          |
|--------------------------|--------------------|--------------------------------------|
| `scan_id`                | `str`              | Unique identifier for this scan      |
| `verdict`                | `str`              | `CLEAN`, `CAUTION`, `SUSPICIOUS`, or `MALICIOUS` |
| `risk_score`             | `int`              | 0-100 aggregate risk score           |
| `overall_severity`       | `Severity`         | Highest severity among all findings  |
| `findings`               | `list[Finding]`    | Individual threat detections         |
| `layers_executed`        | `list[str]`        | Which detection layers ran           |
| `duration_ms`            | `int | None`       | Wall-clock scan time in milliseconds |
| `finding_count_by_severity` | `dict[str, int]` | Breakdown by severity level         |

## Available Layers

| Layer Name      | Description                              |
|-----------------|------------------------------------------|
| `rule_engine`   | Pattern matching and signature detection |
| `url_crawler`   | Fetch and analyze URLs found in content  |
| `llm_analyzer`  | LLM-powered semantic analysis            |
| `threat_intel`  | Threat intelligence IOC correlation      |

## Examples

### Skip expensive layers for fast local checks

```python
from malwar import scan_sync

result = scan_sync(content, use_llm=False, use_urls=False)
```

### Run only specific layers

```python
from malwar import scan_sync

result = scan_sync(content, layers=["rule_engine", "threat_intel"])
```

### Batch-scan a directory

```python
import asyncio
from pathlib import Path
from malwar import scan_batch

async def scan_directory(directory: str):
    items = []
    for md_file in Path(directory).glob("*.md"):
        items.append({
            "content": md_file.read_text(),
            "file_name": md_file.name,
        })

    results = await scan_batch(items, use_llm=False, use_urls=False)
    for result in results:
        print(f"{result.target}: {result.verdict} (score={result.risk_score})")

asyncio.run(scan_directory("./skills"))
```

### Use in a CI pipeline

```python
import sys
from malwar import scan_file_sync

result = scan_file_sync("SKILL.md", use_llm=False, use_urls=False)
if result.verdict in ("MALICIOUS", "SUSPICIOUS"):
    print(f"BLOCKED: {result.verdict} with risk score {result.risk_score}")
    for finding in result.findings:
        print(f"  - [{finding.severity}] {finding.rule_id}: {finding.title}")
    sys.exit(1)
print("PASSED: skill file is clean")
```
