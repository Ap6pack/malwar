# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Standardized exit codes for CI/CD pipeline integrations.

Exit codes:
    0 — CLEAN: no threats detected
    1 — MALICIOUS: confirmed malicious content found
    2 — ERROR: scan could not complete (internal error)
    3 — SUSPICIOUS/CAUTION: suspicious or cautionary findings
"""

from __future__ import annotations

from enum import IntEnum


class CIExitCode(IntEnum):
    """Exit codes used by malwar in CI mode."""

    CLEAN = 0
    MALICIOUS = 1
    SCAN_ERROR = 2
    SUSPICIOUS = 3


# Map verdict strings to exit codes
_VERDICT_MAP: dict[str, CIExitCode] = {
    "CLEAN": CIExitCode.CLEAN,
    "MALICIOUS": CIExitCode.MALICIOUS,
    "SUSPICIOUS": CIExitCode.SUSPICIOUS,
    "CAUTION": CIExitCode.SUSPICIOUS,
}


def verdict_to_exit_code(verdict: str) -> CIExitCode:
    """Convert a malwar verdict string to a CI exit code.

    Args:
        verdict: One of CLEAN, CAUTION, SUSPICIOUS, MALICIOUS.

    Returns:
        The corresponding CIExitCode.

    Raises:
        ValueError: If the verdict string is not recognized.
    """
    normalized = verdict.upper().strip()
    if normalized not in _VERDICT_MAP:
        msg = f"Unknown verdict: {verdict!r}. Expected one of: {', '.join(_VERDICT_MAP)}"
        raise ValueError(msg)
    return _VERDICT_MAP[normalized]
