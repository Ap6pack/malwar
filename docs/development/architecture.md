<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Architecture

## Overview

malwar is a 4-layer malware detection engine purpose-built for scanning agentic skills -- specifically SKILL.md files used in the OpenClaw/ClawHub ecosystem. Unlike traditional malware scanners that analyze binary executables or source code, malwar detects threats embedded in natural language markdown instructions that direct AI agents to perform malicious actions.

## System Architecture Diagram

```
                    +------------------+
                    |   Entry Points   |
                    +------------------+
                    |  CLI  |   API    |
                    | typer | FastAPI  |
                    +---+-------+------+
                        |       |
                        v       v
              +--------------------------+
              |     SKILL.md Parser      |
              | (frontmatter + markdown) |
              +------------+-------------+
                           |
                           v
              +---------------------------+
              |     Scan Pipeline          |
              |    (ScanPipeline)          |
              +---------------------------+
              |                           |
              |  +---------------------+  |
              |  |  Layer 1 (order=10) |  |
              |  |   Rule Engine       |  |
              |  | Pattern matching    |  |
              |  +--------+------------+  |
              |           |               |
              |           v               |
              |  +---------------------+  |
              |  |  Layer 2 (order=20) |  |
              |  |   URL Crawler       |  |
              |  | Fetch & analyze URLs|  |
              |  +--------+------------+  |
              |           |               |
              |           v               |
              |  +---------------------+  |
              |  |  Layer 3 (order=30) |  |
              |  |   LLM Analyzer      |  |
              |  | Semantic analysis   |  |
              |  +--------+------------+  |
              |           |               |
              |           v               |
              |  +---------------------+  |
              |  |  Layer 4 (order=40) |  |
              |  |   Threat Intel      |  |
              |  | IOC correlation     |  |
              |  +--------+------------+  |
              |           |               |
              +---------------------------+
                          |
                          v
              +---------------------------+
              |       ScanResult          |
              | verdict / risk_score /    |
              | findings / severity       |
              +---------------------------+
                    |           |
                    v           v
              +---------+  +---------+
              | SQLite  |  | Output  |
              |   DB    |  | Console |
              |         |  | JSON    |
              |         |  | SARIF   |
              +---------+  +---------+
```

## Core Components

### Entry Points

1. **CLI** (`malwar.cli.app`) -- A Typer-based command-line interface for scanning files, managing the database, listing signatures, and starting the API server.
2. **REST API** (`malwar.api.app`) -- A FastAPI web server with endpoints for scanning, retrieving results, managing threat signatures, viewing campaigns, and generating reports.

### SKILL.md Parser

The parser transforms raw SKILL.md content into a structured `SkillContent` object:

1. **Frontmatter Extraction** -- YAML frontmatter into `SkillMetadata`
2. **Markdown Body Parsing** -- URLs, code blocks, and sections extraction
3. **Content Hashing** -- SHA-256 hash for deduplication

### ScanContext

The mutable state object that flows through the pipeline:

```
ScanContext
  +-- skill: SkillContent           # Parsed skill content
  +-- scan_id: str                  # Unique scan identifier
  +-- findings: list[Finding]       # Accumulated findings from all layers
  +-- url_analysis_results: dict    # URL crawler enrichment data
  +-- llm_analysis: dict            # LLM analyzer enrichment data
  +-- matched_campaigns: list[str]  # Campaigns matched by threat intel
  +-- errors: list[str]             # Non-fatal errors from any layer
```

## The 4-Layer Detection Pipeline

### Pipeline Orchestration

Detectors are registered with the pipeline and sorted by their `order` property. Each layer reads the context from previous layers and adds its own findings.

**Error isolation:** If a detector raises an exception, the error is logged but the pipeline continues to the next layer.

### Layer 1: Rule Engine (order=10)

**Module:** `malwar.detectors.rule_engine`

Fast, deterministic pattern matching. 19 rules across 7 categories.

- `BaseRule` abstract base class
- `RuleRegistry` with `@rule` decorator for auto-registration
- `RuleEngineDetector` iterates all enabled rules

### Layer 2: URL Crawler (order=20)

**Module:** `malwar.detectors.url_crawler`

5-step URL analysis: extract, check reputation, fetch suspicious, analyze content, store enrichment.

**Safety bounds:** Max URLs (10), timeout (5s), max redirects (3), max body (1 MB), concurrency (5).

### Layer 3: LLM Analyzer (order=30)

**Module:** `malwar.detectors.llm_analyzer`

Semantic analysis via Claude. Detects social engineering, deceptive intent, and sophisticated prompt injection.

**Cost control:** Skipped when risk score is below `llm_skip_below_risk` threshold (default: 15).

### Layer 4: Threat Intelligence (order=40)

**Module:** `malwar.detectors.threat_intel`

IOC correlation against the signature database with campaign attribution. Supports exact match and regex patterns.

## Scoring and Verdict System

### Risk Score Calculation

```
risk_score = min(100, sum(SEVERITY_WEIGHT[f.severity] * f.confidence for f in findings))
```

| Severity | Weight |
|---|---|
| CRITICAL | 100 |
| HIGH | 75 |
| MEDIUM | 50 |
| LOW | 25 |
| INFO | 0 |

### Verdict Mapping

| Risk Score Range | Verdict |
|---|---|
| 75 -- 100 | MALICIOUS |
| 40 -- 74 | SUSPICIOUS |
| 15 -- 39 | CAUTION |
| 0 -- 14 | CLEAN |

## Storage Layer

SQLite with WAL mode via `aiosqlite`.

| Table | Purpose |
|---|---|
| `scans` | Scan results with verdict, risk score, timing |
| `findings` | Individual threat findings linked to scans |
| `signatures` | Threat intelligence signatures for IOC matching |
| `campaigns` | Tracked malware campaigns with IOCs and attribution |
| `publishers` | Author/publisher reputation tracking |
| `url_analysis` | URL fetch results linked to scans |

## Output Formats

1. **Console** -- Rich-formatted terminal output with color-coded severity
2. **JSON** -- Full Pydantic model serialization
3. **SARIF 2.1.0** -- For GitHub Code Scanning, VS Code, and other SARIF-compatible tools

## Configuration

All settings via environment variables with `MALWAR_` prefix. See [Configuration](../deployment/configuration.md) for the full reference.
