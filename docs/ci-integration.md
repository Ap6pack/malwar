# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

# CI/CD Integration Guide

Malwar integrates with all major CI/CD platforms to scan SKILL.md files for malware, prompt injection, data exfiltration, and other threats targeting agentic AI systems. This guide covers GitHub Actions, GitLab CI/CD, and Azure DevOps.

## Overview

All CI integrations follow the same pattern:

1. Install malwar from PyPI
2. Scan a directory for SKILL.md files
3. Produce platform-specific output (annotations, code quality reports, SARIF)
4. Fail the pipeline if the scan verdict exceeds a configurable threshold

### Verdicts

Malwar assigns one of four verdicts to each scanned file:

| Verdict | Risk Score | Description |
|---------|-----------|-------------|
| `CLEAN` | 0-14 | No threats detected |
| `CAUTION` | 15-39 | Minor concerns found |
| `SUSPICIOUS` | 40-74 | Likely threats detected |
| `MALICIOUS` | 75-100 | Confirmed malicious content |

### CI Exit Codes

When running with `--ci-mode`, malwar uses standardized exit codes:

| Code | Meaning |
|------|---------|
| 0 | Clean: no threats detected |
| 1 | Malicious content found |
| 2 | Scan error (internal failure) |
| 3 | Suspicious or cautionary findings |

### CI Output Formats

Use `--format` to specify the output format:

| Format | Platform | Description |
|--------|----------|-------------|
| `console` | Any | Human-readable Rich console output (default) |
| `json` | Any | Full scan result as JSON |
| `sarif` | Any | SARIF 2.1.0 for security scanning tools |
| `gitlab-codequality` | GitLab | GitLab Code Quality report JSON |
| `azure-annotations` | Azure DevOps | `##vso[task.logissue]` logging commands |

---

## GitHub Actions

Malwar provides a composite GitHub Action at `.github/actions/scan-skills/action.yml`.

### Quick Start

```yaml
name: Scan SKILL.md Files

on:
  pull_request:
    paths:
      - "**.md"

permissions:
  contents: read
  pull-requests: write

jobs:
  scan-skills:
    name: Malwar Skill Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan SKILL.md files
        uses: Ap6pack/malwar/.github/actions/scan-skills@main
        with:
          path: "**/SKILL.md"
          fail-on: "SUSPICIOUS"
```

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Glob pattern for SKILL.md files | `**/SKILL.md` |
| `fail-on` | Verdict threshold to fail: `MALICIOUS`, `SUSPICIOUS`, `CAUTION` | `SUSPICIOUS` |
| `format` | Output format: `text`, `json`, `sarif` | `text` |

### Outputs

| Output | Description |
|--------|-------------|
| `verdict` | Worst verdict across all scanned files |
| `risk_score` | Highest risk score (0-100) |
| `finding_count` | Total findings |
| `sarif_path` | SARIF file path (when format is `sarif`) |

### SARIF Upload Example

```yaml
- name: Scan skills
  id: malwar
  uses: Ap6pack/malwar/.github/actions/scan-skills@main
  with:
    format: sarif

- name: Upload SARIF
  if: always() && steps.malwar.outputs.sarif_path != ''
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.malwar.outputs.sarif_path }}
    category: malwar
```

For full documentation, see [GitHub Action docs](github-action.md).

---

## GitLab CI/CD

Malwar provides a ready-to-use pipeline template at `templates/gitlab/.gitlab-ci.yml`.

### Quick Start

Include the template in your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Ap6pack/malwar/main/templates/gitlab/.gitlab-ci.yml'
```

### Configuration

Override variables to customize:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Ap6pack/malwar/main/templates/gitlab/.gitlab-ci.yml'

variables:
  MALWAR_SCAN_PATH: "skills/"
  MALWAR_FAIL_ON: "SUSPICIOUS"
  MALWAR_VERSION: "0.3.0"
```

### Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MALWAR_SCAN_PATH` | Directory to scan | `.` |
| `MALWAR_FAIL_ON` | Fail threshold: `MALICIOUS`, `SUSPICIOUS`, `CAUTION` | `MALICIOUS` |
| `MALWAR_VERSION` | Pin a version (empty for latest) | `""` |
| `MALWAR_OUTPUT_FORMAT` | Output format | `gitlab-codequality` |

### Code Quality Integration

The template automatically generates a GitLab Code Quality report and uploads it as a pipeline artifact. Findings appear in the merge request diff view as inline annotations.

### Manual Pipeline Setup

If you prefer not to use the remote include, copy the template into your repository:

```yaml
stages:
  - test

malwar-scan:
  stage: test
  image: python:3.13-slim
  before_script:
    - pip install malwar
  script:
    - malwar scan "." --ci-mode --format gitlab-codequality --output gl-code-quality-report.json
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
    when: always
```

For full documentation, see [templates/gitlab/README.md](../templates/gitlab/README.md).

---

## Azure DevOps

Malwar provides a pipeline template at `templates/azure/azure-pipelines.yml`.

### Quick Start: Template Reference

Reference the template from your Azure DevOps pipeline:

```yaml
resources:
  repositories:
    - repository: malwar
      type: github
      name: Ap6pack/malwar
      ref: main
      endpoint: github-service-connection

extends:
  template: templates/azure/azure-pipelines.yml@malwar
  parameters:
    scanPath: "."
    failOn: "MALICIOUS"
```

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `scanPath` | Directory to scan | `.` |
| `failOn` | Fail threshold: `MALICIOUS`, `SUSPICIOUS`, `CAUTION` | `MALICIOUS` |
| `malwarVersion` | Pin a version (empty for latest) | `""` |
| `pythonVersion` | Python version | `3.13` |

### Pipeline Annotations

Findings are reported as Azure DevOps logging commands (`##vso[task.logissue]`), which appear as inline annotations in the pipeline UI. Critical and high severity findings appear as errors; medium and low as warnings.

### SARIF Artifact

The template generates a SARIF report and publishes it as a build artifact named `malwar-sarif`.

### Manual Pipeline Setup

If you prefer not to use the template, add these steps to your `azure-pipelines.yml`:

```yaml
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.13"

  - script: pip install malwar
    displayName: "Install malwar"

  - script: |
      malwar scan "." --ci-mode --format azure-annotations
    displayName: "Scan SKILL.md files"
```

For full documentation, see [templates/azure/README.md](../templates/azure/README.md).

---

## CLI Reference

### CI Mode

Enable CI mode with the `--ci-mode` flag. This activates standardized exit codes instead of Rich console output:

```bash
malwar scan ./skills --ci-mode --format gitlab-codequality --output report.json
```

### Options

| Flag | Description |
|------|-------------|
| `--ci-mode` | Enable CI mode with standardized exit codes |
| `--format gitlab-codequality` | GitLab Code Quality JSON output |
| `--format azure-annotations` | Azure DevOps `##vso` logging commands |
| `--format sarif` | SARIF 2.1.0 output (all platforms) |
| `--output FILE` | Write output to a file instead of stdout |

### Example Commands

```bash
# GitLab CI
malwar scan . --ci-mode --format gitlab-codequality --output gl-code-quality-report.json

# Azure DevOps
malwar scan . --ci-mode --format azure-annotations

# SARIF (any platform)
malwar scan . --ci-mode --format sarif --output malwar-results.sarif

# Check exit code
malwar scan . --ci-mode
echo $?  # 0=clean, 1=malicious, 2=error, 3=suspicious
```
