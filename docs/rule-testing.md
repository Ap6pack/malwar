# Rule Testing Framework

The rule testing framework validates that detection rules behave correctly against
a set of known fixture files. It provides a manifest-driven approach to declaring
expected outcomes and automatically checks for regressions when rules change.

## Overview

The framework has three core components:

1. **Manifest** (`rule_tests.yml`) -- a YAML file declaring test cases: which
   fixture to scan, what verdict to expect, and which rules should (or should
   not) fire.
2. **Runner** (`RuleTestRunner`) -- scans each fixture using the `rule_engine`
   and `threat_intel` layers (no LLM, no URL crawling) and compares results to
   expectations.
3. **Report** (`RuleTestReport`) -- aggregates results and exports them as
   plain text, JSON, or JUnit XML for CI integration.

## Manifest Format

The manifest is a YAML file with the following structure:

```yaml
version: "1"
description: "Rule testing manifest"
base_dir: "."   # Resolved relative to the YAML file's parent directory

test_cases:
  - fixture: tests/fixtures/skills/benign/hello_world.md
    expected_verdict: CLEAN
    description: "Should be clean"

  - fixture: tests/fixtures/skills/malicious/env_harvesting.md
    expected_verdict: MALICIOUS
    expected_rules:
      - MALWAR-ENV-001
    not_expected_rules:
      - MALWAR-PI-001
    description: "Should detect environment variable harvesting"
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `fixture` | Yes | Relative path to the fixture file (from `base_dir`) |
| `expected_verdict` | Yes | `CLEAN`, `MALICIOUS`, or `SUSPICIOUS` |
| `expected_rules` | No | List of rule IDs that must fire |
| `not_expected_rules` | No | List of rule IDs that must NOT fire |
| `description` | No | Human-readable description |

### Verdict Matching

- **CLEAN** -- the actual verdict must be exactly `CLEAN`.
- **MALICIOUS** -- the actual verdict must be `MALICIOUS` or `SUSPICIOUS`.
- **SUSPICIOUS** -- the actual verdict must be `SUSPICIOUS`, `MALICIOUS`, or `CAUTION`.

### Pass/Fail Criteria

A test case **passes** when all of the following are true:

1. The actual verdict matches the expected verdict (per the rules above).
2. Every rule in `expected_rules` fired at least once.
3. No rule in `not_expected_rules` fired.

A test case is flagged as a **regression** when the expected verdict is
`MALICIOUS` or `SUSPICIOUS` but the actual verdict does not match -- indicating
a previously-detected threat is no longer caught.

## CLI Usage

### Run all tests (default manifest)

```bash
malwar test-rules
```

### Custom manifest

```bash
malwar test-rules --manifest path/to/manifest.yml
```

### Output formats

```bash
# Plain text (default)
malwar test-rules --format text

# JSON
malwar test-rules --format json

# JUnit XML (for CI)
malwar test-rules --format junit
```

### Write results to a file

```bash
malwar test-rules --format junit --output results.xml
```

### Exit codes

- **0** -- all tests passed.
- **1** -- one or more tests failed or errored.

## Python API

```python
import asyncio
from malwar.testing import RuleTestManifest, RuleTestRunner

async def main():
    manifest = RuleTestManifest.from_yaml("tests/rule_tests.yml")
    report = await RuleTestRunner.run(manifest)

    print(report.to_text())
    print(f"All passed: {report.all_passed}")

asyncio.run(main())
```

## CI Integration

### GitHub Actions

```yaml
- name: Run rule tests
  run: |
    malwar test-rules --format junit --output rule-test-results.xml

- name: Publish test results
  uses: dorny/test-reporter@v1
  if: always()
  with:
    name: Rule Tests
    path: rule-test-results.xml
    reporter: java-junit
```

### Adding New Test Cases

When adding a new detection rule or fixture:

1. Create the fixture file under `tests/fixtures/skills/benign/` or
   `tests/fixtures/skills/malicious/`.
2. Add an entry to `tests/rule_tests.yml` specifying the expected verdict and
   rule IDs.
3. Run `malwar test-rules` to verify.

### Regression Detection

The framework automatically flags regressions: if a fixture that was previously
detected as malicious is now classified as clean, it is marked as a regression
in the report. This makes it easy to catch rule breakage during development.
