<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Development Guide

## Project Setup

### Prerequisites

- Python 3.13+
- Node.js 20+ (for frontend development)
- Git

### Clone and Install

```bash
git clone https://github.com/Ap6pack/malwar.git
cd malwar

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Initialize the database
malwar db init
```

### Frontend Setup (Optional)

```bash
cd web
npm ci
npm run dev  # Starts Vite dev server on http://localhost:3000
```

### Environment Configuration

```bash
cp .env.example .env
# Edit .env with your settings (MALWAR_ANTHROPIC_API_KEY for Layer 3 testing)
```

---

## Project Structure

```
malwar/
+-- src/malwar/                    # Main package
|   +-- __init__.py                # Version: 0.3.1
|   +-- __main__.py                # python -m malwar entrypoint
|   +-- core/                      # Core infrastructure
|   |   +-- config.py              # Pydantic Settings configuration
|   |   +-- constants.py           # Enums, severity weights, thresholds
|   |   +-- exceptions.py          # Custom exception hierarchy
|   |   +-- logging.py             # Structured logging with redaction
|   +-- scanner/                   # Pipeline orchestration
|   |   +-- pipeline.py            # ScanPipeline: chains the 4 layers
|   |   +-- base.py                # BaseDetector abstract interface
|   |   +-- context.py             # ScanContext: mutable pipeline state
|   |   +-- severity.py            # Risk score and verdict computation
|   +-- detectors/                 # Detection layers
|   |   +-- rule_engine/           # Layer 1: Pattern matching
|   |   |   +-- detector.py        # RuleEngineDetector
|   |   |   +-- base_rule.py       # BaseRule abstract class
|   |   |   +-- registry.py        # RuleRegistry + @rule decorator
|   |   |   +-- rules/             # Individual rule implementations
|   |   |       +-- obfuscation.py
|   |   |       +-- prompt_injection.py
|   |   |       +-- credential_exposure.py
|   |   |       +-- exfiltration.py
|   |   |       +-- known_malware.py
|   |   |       +-- social_engineering.py
|   |   |       +-- suspicious_commands.py
|   |   +-- url_crawler/           # Layer 2: URL analysis
|   |   |   +-- detector.py        # UrlCrawlerDetector
|   |   |   +-- extractor.py       # URL extraction from markdown
|   |   |   +-- fetcher.py         # SafeFetcher with bounds
|   |   |   +-- analyzer.py        # Fetched content analysis
|   |   |   +-- reputation.py      # Domain reputation scoring
|   |   +-- llm_analyzer/          # Layer 3: LLM semantic analysis
|   |   |   +-- detector.py        # LlmAnalyzerDetector
|   |   |   +-- prompts.py         # System + user prompt templates
|   |   |   +-- parser.py          # LLM JSON response parsing
|   |   +-- threat_intel/          # Layer 4: Threat intelligence
|   |       +-- detector.py        # ThreatIntelDetector
|   |       +-- matcher.py         # ThreatIntelMatcher with IOC correlation
|   +-- models/                    # Pydantic data models
|   |   +-- finding.py             # Finding, Location
|   |   +-- scan.py                # ScanRequest, ScanResult
|   |   +-- skill.py               # SkillContent, SkillMetadata, CodeBlock, MarkdownSection
|   |   +-- signature.py           # ThreatSignature, Campaign
|   |   +-- report.py              # BatchScanReport
|   |   +-- sarif.py               # SARIF 2.1.0 models
|   +-- parsers/                   # SKILL.md parsing
|   |   +-- skill_parser.py        # Frontmatter + markdown parsing
|   |   +-- markdown_parser.py     # URL, code block, section extraction
|   +-- crawl/                     # ClawHub registry crawler
|   |   +-- client.py              # Async HTTP client for ClawHub API
|   |   +-- models.py              # Pydantic response models
|   +-- cli/                       # Command-line interface
|   |   +-- app.py                 # Typer app with all commands
|   |   +-- commands/
|   |   |   +-- crawl.py           # ClawHub crawl commands
|   |   |   +-- db.py              # Database management commands
|   |   +-- formatters/
|   |       +-- console.py         # Rich console output
|   |       +-- json_fmt.py        # JSON output
|   |       +-- sarif.py           # SARIF 2.1.0 output
|   +-- api/                       # REST API
|   |   +-- app.py                 # FastAPI application factory
|   |   +-- auth.py                # X-API-Key authentication
|   |   +-- middleware.py          # Rate limiting + request logging
|   |   +-- routes/
|   |       +-- scan.py            # POST /scan, GET /scan/{id}, etc.
|   |       +-- health.py          # GET /health, GET /ready
|   |       +-- campaigns.py       # GET /campaigns, GET /campaigns/{id}
|   |       +-- signatures.py      # CRUD /signatures
|   |       +-- reports.py         # GET /reports, GET /reports/{id}
|   +-- storage/                   # Database layer
|   |   +-- database.py            # SQLite connection management
|   |   +-- migrations.py          # Schema creation + seed data
|   |   +-- repositories/
|   |       +-- scans.py           # ScanRepository
|   |       +-- findings.py        # FindingRepository
|   |       +-- signatures.py      # SignatureRepository
|   |       +-- campaigns.py       # CampaignRepository
|   |       +-- publishers.py      # PublisherRepository
|   +-- notifications/
|       +-- webhook.py             # Webhook notification dispatcher
+-- tests/                         # Test suite
|   +-- conftest.py                # Shared fixtures
|   +-- unit/                      # Unit tests
|   |   +-- test_core_models.py
|   |   +-- test_skill_parser.py
|   |   +-- test_markdown_parser.py
|   |   +-- test_storage.py
|   |   +-- test_webhook.py
|   |   +-- detectors/
|   |       +-- test_llm_analyzer.py
|   |       +-- test_url_crawler.py
|   |       +-- test_threat_intel.py
|   +-- integration/               # Integration tests
|   |   +-- test_api.py
|   |   +-- test_scan_pipeline.py
|   |   +-- test_batch_scan.py
|   |   +-- test_signatures_api.py
|   |   +-- test_campaigns_api.py
|   |   +-- test_reports_api.py
|   +-- e2e/                       # End-to-end tests
|   |   +-- test_full_scan.py
|   +-- fixtures/                  # Test fixture files
|       +-- skills/
|           +-- benign/            # Known-clean skill files
|           +-- malicious/         # Known-malicious skill files
|           +-- real/              # Real-world skill samples
|               +-- clawhub/       # Real ClawHub skills
|               +-- benign/        # Confirmed benign (Anthropic)
|               +-- malicious/     # Confirmed malicious (Snyk research)
+-- web/                           # React + TypeScript frontend
|   +-- src/                       # Frontend source
|   +-- dist/                      # Compiled assets (served by FastAPI)
|   +-- package.json
|   +-- vite.config.ts
|   +-- tsconfig.json
+-- docs/                          # Documentation
+-- pyproject.toml                 # Project configuration
+-- Dockerfile                     # Multi-stage Docker build
+-- docker-compose.yml             # Docker Compose deployment
+-- .env.example                   # Example environment configuration
+-- .github/workflows/ci.yml       # CI/CD pipeline
```

---

## How to Add a New Detection Rule

Detection rules are the primary extension point for malwar. Adding a new rule requires only a single Python file.

### Step 1: Create the Rule File

Create a new file in `src/malwar/detectors/rule_engine/rules/` or add a rule class to an existing file in that directory.

### Step 2: Implement the Rule Class

```python
# src/malwar/detectors/rule_engine/rules/my_new_rules.py
# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""My new detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule  # <-- This decorator auto-registers the rule
class MyNewRule(BaseRule):
    rule_id = "MALWAR-NEW-001"          # Unique ID following MALWAR-{CATEGORY}-{NUMBER}
    title = "Description of what this detects"
    severity = Severity.HIGH             # CRITICAL, HIGH, MEDIUM, LOW, or INFO
    category = ThreatCategory.SUSPICIOUS_COMMAND  # Must be a ThreatCategory enum value
    description = "Detailed description of the rule"

    # Compiled regex patterns for performance
    PATTERNS = [
        re.compile(r"""your-regex-pattern-here""", re.IGNORECASE),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id=f"{self.rule_id}-L{line_num}",
                        rule_id=self.rule_id,
                        title=self.title,
                        description=self.description,
                        severity=self.severity,
                        confidence=0.85,       # 0.0 to 1.0
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Describe what matched"],
                    ))
                    break  # One finding per line
        return findings
```

### Step 3: Register the Module Import

If you created a new file, add its import to the rule engine detector:

```python
# src/malwar/detectors/rule_engine/detector.py
import malwar.detectors.rule_engine.rules.my_new_rules  # noqa: F401
```

The `@rule` decorator handles registration automatically. The import triggers the decorator to execute.

### Step 4: Add Test Fixtures

Create test skill files:

```bash
# tests/fixtures/skills/malicious/my_new_threat.md
---
name: Trigger Skill
author: test
---
# Test
Content that triggers your new rule...
```

### Step 5: Write Tests

```python
# tests/unit/detectors/test_my_new_rules.py
from malwar.detectors.rule_engine.rules.my_new_rules import MyNewRule
from malwar.parsers.skill_parser import parse_skill_content


def test_my_new_rule_detects_threat():
    skill = parse_skill_content(
        "---\nname: test\n---\n# Test\nyour-trigger-pattern-here",
        file_path="test.md",
    )
    rule = MyNewRule()
    findings = rule.check(skill)
    assert len(findings) >= 1
    assert findings[0].rule_id == "MALWAR-NEW-001"
    assert findings[0].severity == "high"


def test_my_new_rule_no_false_positive():
    skill = parse_skill_content(
        "---\nname: benign\n---\n# Benign\nNormal content here.",
        file_path="test.md",
    )
    rule = MyNewRule()
    findings = rule.check(skill)
    assert len(findings) == 0
```

### Rule Design Guidelines

1. **Use compiled regex** -- Define patterns as class-level `re.compile()` for performance.
2. **Set appropriate confidence** -- Higher confidence (0.90+) for exact IOC matches. Lower (0.60-0.80) for heuristic patterns.
3. **Include evidence** -- Always add meaningful evidence strings explaining what triggered the rule.
4. **Break after first match per line** -- Avoid duplicate findings for the same line.
5. **Use sections for context** -- For context-sensitive rules (e.g., "dangerous command in prerequisites section"), iterate over `skill.sections` instead of raw lines.
6. **Follow the naming convention** -- Rule IDs must follow `MALWAR-{CATEGORY}-{NUMBER}`.

### Available ThreatCategory Values

| Enum Value | Description |
|---|---|
| `OBFUSCATED_COMMAND` | Encoded/obfuscated commands |
| `SOCIAL_ENGINEERING` | Deceptive instructions |
| `PROMPT_INJECTION` | AI agent instruction override |
| `KNOWN_MALWARE` | Known campaign IOCs |
| `CREDENTIAL_EXPOSURE` | Secrets and credential harvesting |
| `SUSPICIOUS_COMMAND` | Dangerous shell commands |
| `DATA_EXFILTRATION` | Sensitive file access and data transmission |
| `MALICIOUS_URL` | Malicious or suspicious URLs |
| `SUSPICIOUS_DEPENDENCY` | Untrusted package dependencies |
| `TYPOSQUATTING` | Name-based deception |
| `SECURITY_DISABLEMENT` | Disabling security controls |

---

## How to Add a New API Endpoint

### Step 1: Create or Modify a Route Module

API routes live in `src/malwar/api/routes/`. Either add to an existing module or create a new one.

```python
# src/malwar/api/routes/my_feature.py
# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""My feature API endpoints."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from malwar.api.auth import require_api_key

router = APIRouter()


class MyResponse(BaseModel):
    message: str
    data: list[str]


@router.get("/my-endpoint", response_model=MyResponse)
async def my_endpoint(
    _api_key: str = Depends(require_api_key),
) -> MyResponse:
    """Description of what this endpoint does."""
    return MyResponse(message="Hello", data=["item1", "item2"])
```

### Step 2: Register the Router

Add the router to the FastAPI app in `src/malwar/api/app.py`:

```python
from malwar.api.routes import my_feature

# In create_app():
app.include_router(my_feature.router, prefix="/api/v1", tags=["my-feature"])
```

### Step 3: Add Tests

```python
# tests/integration/test_my_feature.py
import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.mark.asyncio
async def test_my_endpoint(app):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/api/v1/my-endpoint")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
```

---

## Testing Strategy

### Test Organization

| Directory | Purpose | Markers |
|---|---|---|
| `tests/unit/` | Unit tests for individual modules | (none) |
| `tests/integration/` | Tests that exercise multiple components together | `@pytest.mark.integration` |
| `tests/e2e/` | End-to-end tests scanning real skill files | `@pytest.mark.e2e` |
| `tests/fixtures/` | Test data files (SKILL.md samples) | -- |

### Test Fixtures

The test suite includes both synthetic and real-world skill files:

**Synthetic fixtures** (`tests/fixtures/skills/`):
- `benign/` -- Clean skills: hello_world, git_helper, web_search, code_formatter, legitimate_with_urls
- `malicious/` -- Malicious skills: clawhavoc_amos, credential_harvester, obfuscated_curl, base64_reverse_shell, exfil_soul_md, multi_stage_dropper, prompt_injection_basic, prompt_injection_unicode, clickfix_fake_prereq, typosquatted_package

**Real-world fixtures** (`tests/fixtures/skills/real/`):
- `clawhub/` -- Actual ClawHub skills (bankrbot variants, metamask helpers, etc.)
- `benign/` -- Confirmed benign skills from Anthropic
- `malicious/` -- Confirmed malicious skills from Snyk research

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/

# Run only e2e tests
pytest tests/e2e/

# Run with coverage
pytest --cov=malwar --cov-report=term-missing

# Run with coverage and fail if below threshold
pytest --cov=malwar --cov-fail-under=85
```

### Shared Fixtures

The `tests/conftest.py` provides:

- `benign_dir` -- Path to the benign test fixtures directory
- `malicious_dir` -- Path to the malicious test fixtures directory
- `_clear_rate_limit_state` (autouse) -- Resets in-memory rate limit state between tests

### Async Testing

All tests use `pytest-asyncio` with `asyncio_mode = "auto"` configuration. Async test functions are automatically detected and run with an event loop.

---

## Linting and Formatting

### Ruff

The project uses Ruff for linting and formatting with a comprehensive rule set.

```bash
# Check for lint errors
ruff check src/ tests/

# Auto-fix lint errors
ruff check --fix src/ tests/

# Format code
ruff format src/ tests/
```

**Configuration** (from `pyproject.toml`):
- Target: Python 3.13
- Line length: 100
- Enabled rule sets: E, W, F, I, N, UP, B, S, A, C4, DTZ, T20, SIM, TCH, RUF, ASYNC

### Type Checking

```bash
# Run mypy
mypy src/ --ignore-missing-imports
```

**Configuration** (from `pyproject.toml`):
- Python version: 3.13
- `warn_return_any = true`
- `warn_unused_configs = true`

---

## Build and Package

### Build the Python Package

```bash
# Install build tool
pip install build

# Build wheel and sdist
python -m build
```

Output goes to the `dist/` directory.

### Build the Docker Image

```bash
docker build -t malwar .
```

The Dockerfile uses a multi-stage build:
1. Stage 1: Build React frontend with Node.js 20
2. Stage 2: Install Python package and copy frontend assets

---

## Code Conventions

### Imports

- Use `from __future__ import annotations` for modern type annotation syntax.
- Organize imports: stdlib, third-party, first-party (`malwar.*`).
- Ruff isort is configured with `known-first-party = ["malwar"]`.

### Error Handling

- Use the custom exception hierarchy from `malwar.core.exceptions`:
  - `MalwarError` -- Base exception
  - `ConfigurationError` -- Invalid configuration
  - `ParseError` -- Failed to parse SKILL.md
  - `ScanError` -- Error during scanning
  - `DetectorError` -- Error in a detection layer
  - `StorageError` -- Database errors
  - `FetchError` -- URL fetch errors
  - `LLMError` -- LLM API errors
  - `AuthenticationError` -- API auth failures

### Copyright Headers

Every source file must include the copyright header:

```python
# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
```

### Data Models

- Use Pydantic `BaseModel` for all data models.
- Use `Field()` with descriptions for API-facing models.
- Use `computed_field` for derived properties (e.g., `risk_score`, `verdict`).
- Use Python `StrEnum` for enumeration types.

### Async/Await

- All I/O operations (database, HTTP, file reading) are async.
- Detection layers implement `async def detect()`.
- The CLI uses `asyncio.run()` to bridge sync Typer with async internals.

### Logging

- Use `logging.getLogger("malwar.module.submodule")` for all loggers.
- Log levels: DEBUG for verbose tracing, INFO for normal operations, WARNING for degraded states, ERROR for failures.
- Sensitive data is automatically redacted by the custom log formatters.
