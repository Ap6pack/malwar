# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

# Malwar Azure DevOps Integration

Scan SKILL.md files in your Azure DevOps pipelines for malware, prompt injection, data exfiltration, and other threats targeting agentic AI systems.

## Quick Start

Copy `azure-pipelines.yml` to your repository, or reference it as a template:

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

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `scanPath` | Directory containing SKILL.md files to scan | `.` |
| `failOn` | Verdict threshold that fails the pipeline: `MALICIOUS`, `SUSPICIOUS`, or `CAUTION` | `MALICIOUS` |
| `malwarVersion` | Specific malwar version to install (empty for latest) | `""` |
| `pythonVersion` | Python version to use | `3.13` |

## What the Pipeline Does

1. **Sets up Python** using the `UsePythonVersion` task
2. **Installs malwar** from PyPI (optionally pinned to a specific version)
3. **Runs the scan** with Azure DevOps annotation output (`##vso[task.logissue]` commands)
4. **Generates a SARIF report** and publishes it as a build artifact
5. **Evaluates the threshold** and fails the build if the verdict exceeds it

## Verdict Thresholds

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

## Azure DevOps Annotations

Findings are reported using Azure DevOps logging commands (`##vso[task.logissue]`), which appear as annotations in the pipeline UI. Each finding includes:

- **Type**: `error` (critical/high severity) or `warning` (medium/low/info)
- **Source path**: The scanned file
- **Line number**: Where the finding was detected
- **Code**: The malwar rule ID

## Artifacts

The pipeline publishes a SARIF report as a build artifact named `malwar-sarif`:

- `malwar-results.sarif` — SARIF 2.1.0 report with all findings

## Example: Standalone Pipeline

Add `azure-pipelines.yml` to your repository root:

```yaml
trigger:
  branches:
    include:
      - main
  paths:
    include:
      - "**/*.md"

pr:
  branches:
    include:
      - main

pool:
  vmImage: "ubuntu-latest"

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.13"

  - script: pip install malwar
    displayName: "Install malwar"

  - script: |
      malwar scan "." --ci-mode --format azure-annotations
    displayName: "Scan SKILL.md files"

  - script: |
      malwar scan "." --ci-mode --format sarif --output "$(Build.ArtifactStagingDirectory)/malwar-results.sarif"
    displayName: "Generate SARIF"
    continueOnError: true

  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      PathtoPublish: "$(Build.ArtifactStagingDirectory)/malwar-results.sarif"
      ArtifactName: "malwar-sarif"
```

## Example: Custom Scan Path and Strict Threshold

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
    scanPath: "agent-skills/"
    failOn: "SUSPICIOUS"
    malwarVersion: "0.3.0"
```

## See Also

- [CI Integration Guide](../../docs/ci-integration.md) — covers GitHub Actions, GitLab CI, and Azure DevOps
- [GitHub Action](../../.github/actions/scan-skills/action.yml) — GitHub Actions integration
- [GitLab CI Template](../gitlab/README.md) — GitLab CI/CD integration
