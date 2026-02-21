# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CI-specific output formatters for malwar scan results.

Provides:
- GitLab Code Quality JSON format
- Azure DevOps logging commands (##vso task commands for annotations)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from malwar.core.constants import Severity
from malwar.models.scan import ScanResult

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_TO_GITLAB: dict[str, str] = {
    Severity.CRITICAL: "blocker",
    Severity.HIGH: "critical",
    Severity.MEDIUM: "major",
    Severity.LOW: "minor",
    Severity.INFO: "info",
}

_SEVERITY_TO_AZURE: dict[str, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "warning",
}


# ---------------------------------------------------------------------------
# GitLab Code Quality
# ---------------------------------------------------------------------------


def format_gitlab_code_quality(results: list[ScanResult]) -> str:
    """Format scan results as GitLab Code Quality JSON.

    The GitLab Code Quality report format is an array of issue objects,
    each describing a single finding with location, severity, and description.

    See: https://docs.gitlab.com/ee/ci/testing/code_quality.html

    Args:
        results: List of ScanResult objects from malwar scans.

    Returns:
        JSON string conforming to the GitLab Code Quality report schema.
    """
    issues: list[dict[str, Any]] = []

    for result in results:
        for finding in result.findings:
            # Build a stable fingerprint from rule_id + target + line
            line = finding.location.line_start if finding.location else 1
            fingerprint_src = f"{finding.rule_id}:{result.target}:{line}"
            fingerprint = hashlib.md5(  # noqa: S324
                fingerprint_src.encode()
            ).hexdigest()

            issue: dict[str, Any] = {
                "type": "issue",
                "check_name": finding.rule_id,
                "description": finding.title,
                "content": {"body": finding.description},
                "categories": ["Security"],
                "severity": _SEVERITY_TO_GITLAB.get(finding.severity, "major"),
                "fingerprint": fingerprint,
                "location": {
                    "path": result.target,
                    "lines": {
                        "begin": line,
                    },
                },
            }

            if finding.location and finding.location.line_end:
                issue["location"]["lines"]["end"] = finding.location.line_end

            issues.append(issue)

    return json.dumps(issues, indent=2)


# ---------------------------------------------------------------------------
# Azure DevOps logging commands
# ---------------------------------------------------------------------------


def format_azure_annotations(results: list[ScanResult]) -> str:
    """Format scan results as Azure DevOps logging commands.

    Azure DevOps uses special logging commands (##vso) to create
    annotations in the pipeline UI. Each finding becomes a task.logissue
    command with file, line, and severity information.

    See: https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands

    Args:
        results: List of ScanResult objects from malwar scans.

    Returns:
        Newline-separated string of ##vso logging commands.
    """
    lines: list[str] = []

    for result in results:
        for finding in result.findings:
            issue_type = _SEVERITY_TO_AZURE.get(finding.severity, "warning")
            line_num = finding.location.line_start if finding.location else 1
            col_num = finding.location.column_start if finding.location and finding.location.column_start else 1

            # Escape semicolons and newlines in the message per Azure DevOps spec
            message = finding.title.replace(";", "%3B").replace("\n", "%0A")
            source_file = result.target.replace(";", "%3B")
            code = finding.rule_id.replace(";", "%3B")

            vso_cmd = (
                f"##vso[task.logissue type={issue_type};"
                f"sourcepath={source_file};"
                f"linenumber={line_num};"
                f"columnnumber={col_num};"
                f"code={code}]"
                f"{message}"
            )
            lines.append(vso_cmd)

    # Add summary line if there were any findings
    total_findings = sum(len(r.findings) for r in results)
    if total_findings > 0:
        verdicts = [r.verdict for r in results]
        worst = max(verdicts, key=lambda v: ["CLEAN", "CAUTION", "SUSPICIOUS", "MALICIOUS"].index(v))
        lines.append(
            f"##vso[task.logissue type=warning]"
            f"Malwar scan complete: {total_findings} finding(s), worst verdict: {worst}"
        )

    return "\n".join(lines)
