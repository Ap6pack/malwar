# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Exceptions raised by Malwar integrations."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from malwar.models.finding import Finding


class MalwarBlockedError(Exception):
    """Raised when scanned content exceeds the configured threat threshold.

    Attributes
    ----------
    verdict : str
        The scan verdict that triggered the block (e.g. ``"MALICIOUS"``).
    risk_score : int
        Numeric risk score (0-100) from the scan.
    findings : list[Finding]
        The individual findings detected by the scan.
    scan_id : str
        Unique identifier for the scan that produced the block.
    """

    def __init__(
        self,
        message: str,
        *,
        verdict: str,
        risk_score: int,
        findings: list[Finding],
        scan_id: str,
    ) -> None:
        super().__init__(message)
        self.verdict = verdict
        self.risk_score = risk_score
        self.findings = findings
        self.scan_id = scan_id
