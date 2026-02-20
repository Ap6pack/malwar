# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

# Malwar GitHub Action

Scan SKILL.md files in pull requests for malware, prompt injection, data exfiltration, and other threats targeting agentic AI systems.

## Quick Start

Add this workflow to your repository at `.github/workflows/scan-skills.yml`:

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

## Inputs

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `path` | Glob pattern for SKILL.md files to scan | `**/SKILL.md` | No |
| `fail-on` | Verdict threshold that causes the action to fail. One of: `MALICIOUS`, `SUSPICIOUS`, `CAUTION` | `SUSPICIOUS` | No |
| `format` | Output format: `text`, `json`, or `sarif` | `text` | No |

### Verdict Thresholds

Malwar assigns one of four verdicts to each scanned file:

| Verdict | Risk Score | Description |
|---------|-----------|-------------|
| `CLEAN` | 0-14 | No threats detected |
| `CAUTION` | 15-39 | Minor concerns found |
| `SUSPICIOUS` | 40-74 | Likely threats detected |
| `MALICIOUS` | 75-100 | Confirmed malicious content |

The `fail-on` input controls when the action returns a non-zero exit code:
- `MALICIOUS` — only fail on confirmed malware (most permissive)
- `SUSPICIOUS` — fail on likely and confirmed threats (default)
- `CAUTION` — fail on any concern (strictest)

## Outputs

| Output | Description |
|--------|-------------|
| `verdict` | Worst verdict across all scanned files |
| `risk_score` | Highest risk score across all scanned files (0-100) |
| `finding_count` | Total number of findings across all scanned files |
| `sarif_path` | Path to the SARIF output file (only set when `format` is `sarif`) |

## Examples

### Basic Usage

Scan all SKILL.md files and fail on suspicious or malicious content:

```yaml
- name: Scan skills
  uses: Ap6pack/malwar/.github/actions/scan-skills@main
```

### With SARIF Upload

Scan files and upload results to the GitHub Security tab for code scanning alerts:

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

Note: SARIF upload requires the `security-events: write` permission:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
```

### Strict Mode

Fail on any finding, including low-risk cautions:

```yaml
- name: Scan skills (strict)
  uses: Ap6pack/malwar/.github/actions/scan-skills@main
  with:
    fail-on: "CAUTION"
```

### Custom Paths

Scan skill files in a specific directory:

```yaml
- name: Scan vendor skills
  uses: Ap6pack/malwar/.github/actions/scan-skills@main
  with:
    path: "skills/vendor/**/SKILL.md"
```

Scan all Markdown files (not just SKILL.md):

```yaml
- name: Scan all Markdown
  uses: Ap6pack/malwar/.github/actions/scan-skills@main
  with:
    path: "**/*.md"
```

### Using Outputs in Subsequent Steps

```yaml
- name: Scan skills
  id: malwar
  uses: Ap6pack/malwar/.github/actions/scan-skills@main
  with:
    fail-on: "MALICIOUS"

- name: Report results
  if: always()
  run: |
    echo "Verdict: ${{ steps.malwar.outputs.verdict }}"
    echo "Risk Score: ${{ steps.malwar.outputs.risk_score }}"
    echo "Findings: ${{ steps.malwar.outputs.finding_count }}"
```

### Full Workflow Example

A complete workflow with SARIF upload and PR comments:

```yaml
name: Scan SKILL.md Files

on:
  pull_request:
    paths:
      - "**.md"

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  scan-skills:
    name: Malwar Skill Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan SKILL.md files
        id: malwar
        uses: Ap6pack/malwar/.github/actions/scan-skills@main
        with:
          path: "**/SKILL.md"
          fail-on: "SUSPICIOUS"
          format: "sarif"

      - name: Upload SARIF to GitHub Security
        if: always() && steps.malwar.outputs.sarif_path != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.malwar.outputs.sarif_path }}
          category: "malwar"
```

The action automatically posts a summary comment on pull requests with the scan verdict, risk score, and finding count. Existing comments are updated on subsequent runs rather than creating duplicates.
