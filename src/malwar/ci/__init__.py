# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CI/CD integration module for malwar.

Provides output formatters and exit codes for GitLab CI, Azure DevOps,
and GitHub Actions pipelines.
"""

from malwar.ci.exit_codes import CIExitCode, verdict_to_exit_code
from malwar.ci.parser import format_azure_annotations, format_gitlab_code_quality

__all__ = [
    "CIExitCode",
    "format_azure_annotations",
    "format_gitlab_code_quality",
    "verdict_to_exit_code",
]
