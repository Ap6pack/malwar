<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Contributing

## Getting Started

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
# Edit .env with your settings
```

---

## Project Structure

```
malwar/
+-- src/malwar/                    # Main package
|   +-- core/                      # Core infrastructure (config, constants, exceptions)
|   +-- scanner/                   # Pipeline orchestration
|   +-- detectors/                 # Detection layers
|   |   +-- rule_engine/           # Layer 1: Pattern matching
|   |   +-- url_crawler/           # Layer 2: URL analysis
|   |   +-- llm_analyzer/          # Layer 3: LLM semantic analysis
|   |   +-- threat_intel/          # Layer 4: Threat intelligence
|   +-- models/                    # Pydantic data models
|   +-- parsers/                   # SKILL.md parsing
|   +-- crawl/                     # ClawHub registry crawler
|   +-- cli/                       # Command-line interface
|   +-- api/                       # REST API
|   +-- storage/                   # Database layer
|   +-- notifications/             # Webhook dispatcher
+-- tests/                         # Test suite
|   +-- unit/                      # Unit tests
|   +-- integration/               # Integration tests
|   +-- e2e/                       # End-to-end tests
|   +-- fixtures/                  # Test fixture files
+-- web/                           # React + TypeScript frontend
+-- docs/                          # Documentation
```

---

## How to Add a New Detection Rule

### Step 1: Create the Rule Class

Create a new file in `src/malwar/detectors/rule_engine/rules/` or add to an existing file:

```python
# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent

@rule
class MyNewRule(BaseRule):
    rule_id = "MALWAR-NEW-001"
    title = "Description of what this detects"
    severity = Severity.HIGH
    category = ThreatCategory.SUSPICIOUS_COMMAND
    description = "Detailed description"

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            # Pattern matching logic here
            pass
        return findings
```

### Step 2: Register the Import

If you created a new file, add its import to the rule engine detector:

```python
# src/malwar/detectors/rule_engine/detector.py
import malwar.detectors.rule_engine.rules.my_new_rules  # noqa: F401
```

### Step 3: Add Tests

```python
def test_my_new_rule_detects_threat():
    skill = parse_skill_content("---\nname: test\n---\n# Test\ntrigger-content")
    rule = MyNewRule()
    findings = rule.check(skill)
    assert len(findings) >= 1
```

### Rule Design Guidelines

1. **Use compiled regex** for performance
2. **Set appropriate confidence** (0.90+ for exact IOC matches, 0.60-0.80 for heuristics)
3. **Include evidence** explaining what triggered the rule
4. **Break after first match per line** to avoid duplicates
5. **Follow the naming convention** `MALWAR-{CATEGORY}-{NUMBER}`

---

## How to Add a New API Endpoint

### Step 1: Create a Route Module

```python
# src/malwar/api/routes/my_feature.py
from fastapi import APIRouter, Depends
from malwar.api.auth import require_api_key

router = APIRouter()

@router.get("/my-endpoint")
async def my_endpoint(_api_key: str = Depends(require_api_key)):
    return {"message": "Hello"}
```

### Step 2: Register the Router

```python
# In src/malwar/api/app.py create_app():
app.include_router(my_feature.router, prefix="/api/v1", tags=["my-feature"])
```

---

## Testing

### Running Tests

```bash
pytest                                    # Run all tests
pytest -v                                 # Verbose output
pytest tests/unit/                        # Unit tests only
pytest tests/integration/                 # Integration tests only
pytest --cov=malwar --cov-report=term-missing  # With coverage
pytest --cov=malwar --cov-fail-under=85   # Coverage threshold
```

### Test Organization

| Directory | Purpose |
|---|---|
| `tests/unit/` | Unit tests for individual modules |
| `tests/integration/` | Tests exercising multiple components |
| `tests/e2e/` | End-to-end tests with real skill files |
| `tests/fixtures/` | Test data files (SKILL.md samples) |

---

## Linting and Formatting

```bash
ruff check src/ tests/        # Check for lint errors
ruff check --fix src/ tests/  # Auto-fix
ruff format src/ tests/       # Format code
mypy src/                     # Type checking
```

---

## Code Conventions

### Copyright Headers

Every source file must include:

```python
# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
```

### Imports

- Use `from __future__ import annotations`
- Organize: stdlib, third-party, first-party (`malwar.*`)

### Data Models

- Use Pydantic `BaseModel` for all data models
- Use `Field()` with descriptions for API-facing models
- Use Python `StrEnum` for enumerations

### Async/Await

- All I/O operations are async
- The CLI uses `asyncio.run()` to bridge sync Typer with async internals
