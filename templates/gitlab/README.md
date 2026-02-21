# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

# Malwar GitLab CI Integration

Scan SKILL.md files in your GitLab CI/CD pipelines for malware, prompt injection, data exfiltration, and other threats targeting agentic AI systems.

## Quick Start

Add the following to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Ap6pack/malwar/main/templates/gitlab/.gitlab-ci.yml'
```

This adds a `malwar-scan` job to the `test` stage that:

1. Installs malwar from PyPI
2. Scans the repository for SKILL.md files
3. Produces a GitLab Code Quality report as a pipeline artifact
4. Fails the pipeline if malicious content is detected

## Configuration

Override variables in your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Ap6pack/malwar/main/templates/gitlab/.gitlab-ci.yml'

variables:
  MALWAR_SCAN_PATH: "skills/"        # Directory to scan (default: ".")
  MALWAR_FAIL_ON: "SUSPICIOUS"       # Fail threshold (default: "MALICIOUS")
  MALWAR_VERSION: "0.2.1"            # Pin a version (default: latest)
  MALWAR_OUTPUT_FORMAT: "gitlab-codequality"  # Output format
```

### Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MALWAR_SCAN_PATH` | Directory containing SKILL.md files to scan | `.` |
| `MALWAR_FAIL_ON` | Verdict threshold that fails the pipeline: `MALICIOUS`, `SUSPICIOUS`, or `CAUTION` | `MALICIOUS` |
| `MALWAR_VERSION` | Specific malwar version to install (empty for latest) | `""` |
| `MALWAR_OUTPUT_FORMAT` | Output format for CI integration | `gitlab-codequality` |

### Verdict Thresholds

| Verdict | Risk Score | Description |
|---------|-----------|-------------|
| `CLEAN` | 0-14 | No threats detected |
| `CAUTION` | 15-39 | Minor concerns found |
| `SUSPICIOUS` | 40-74 | Likely threats detected |
| `MALICIOUS` | 75-100 | Confirmed malicious content |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean: no threats detected |
| 1 | Malicious content found |
| 2 | Scan error (internal failure) |
| 3 | Suspicious or cautionary findings |

## Code Quality Report

The pipeline produces a GitLab Code Quality report (`gl-code-quality-report.json`) as an artifact. This integrates with the GitLab Merge Request UI to show findings inline with code changes.

The report is automatically uploaded via the `artifacts:reports:codequality` configuration.

## Artifacts

The scan job produces the following artifacts (retained for 30 days):

- `gl-code-quality-report.json` — GitLab Code Quality report with all findings

## Pipeline Rules

By default, the scan runs on:

- Merge request pipelines
- Pushes to the default branch

Customize by overriding the `rules` key in your `.gitlab-ci.yml`.

## Example: Custom Configuration

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Ap6pack/malwar/main/templates/gitlab/.gitlab-ci.yml'

variables:
  MALWAR_SCAN_PATH: "agent-skills/"
  MALWAR_FAIL_ON: "SUSPICIOUS"
  MALWAR_VERSION: "0.2.1"

malwar-scan:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
      when: always
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: always
    - when: never
```

## Example: SARIF Output

To produce SARIF output instead of Code Quality JSON:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Ap6pack/malwar/main/templates/gitlab/.gitlab-ci.yml'

variables:
  MALWAR_OUTPUT_FORMAT: "sarif"

malwar-scan:
  script:
    - malwar scan "${MALWAR_SCAN_PATH}" --ci-mode --format sarif --output malwar-results.sarif
  artifacts:
    paths:
      - malwar-results.sarif
    when: always
```

## See Also

- [CI Integration Guide](../../docs/ci-integration.md) — covers GitHub Actions, GitLab CI, and Azure DevOps
- [GitHub Action](../../.github/actions/scan-skills/action.yml) — GitHub Actions integration
- [Azure DevOps Template](../azure/README.md) — Azure Pipelines integration
