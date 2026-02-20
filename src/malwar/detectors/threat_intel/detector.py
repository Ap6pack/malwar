# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Layer 4: Threat intelligence correlation and campaign attribution."""

from __future__ import annotations

import logging

from malwar.core.constants import DetectorLayer
from malwar.detectors.threat_intel.matcher import ThreatIntelMatcher
from malwar.models.finding import Finding
from malwar.scanner.base import BaseDetector
from malwar.scanner.context import ScanContext

logger = logging.getLogger("malwar.detectors.threat_intel")


class ThreatIntelDetector(BaseDetector):
    """Layer 4: Correlate IOCs against known threat intelligence signatures."""

    def __init__(self, signatures: list[dict[str, str]] | None = None) -> None:
        self._signatures = signatures

    @property
    def layer_name(self) -> str:
        return DetectorLayer.THREAT_INTEL

    @property
    def order(self) -> int:
        return 40

    async def detect(self, context: ScanContext) -> list[Finding]:
        """Run threat intelligence matching against skill and prior findings."""
        matcher = ThreatIntelMatcher(signatures=self._signatures)

        findings = matcher.match(context.skill, context.findings)

        # Track matched campaigns in context
        campaigns: set[str] = set()
        for f in findings:
            campaign = f.metadata.get("campaign")
            if campaign:
                campaigns.add(str(campaign))

        for campaign in sorted(campaigns):
            if campaign not in context.matched_campaigns:
                context.matched_campaigns.append(campaign)

        logger.info(
            "Threat intel found %d findings for %s (campaigns: %s)",
            len(findings),
            context.skill.file_path,
            ", ".join(sorted(campaigns)) if campaigns else "none",
        )

        return findings
