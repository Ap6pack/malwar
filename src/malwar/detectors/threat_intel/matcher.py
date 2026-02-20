# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Match IOCs from prior detection layers against known threat signatures."""

from __future__ import annotations

import logging
import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent

logger = logging.getLogger("malwar.detectors.threat_intel.matcher")

# ---------------------------------------------------------------------------
# Hardcoded signature database (fallback when DB is not available)
# ---------------------------------------------------------------------------

HARDCODED_SIGNATURES: list[dict[str, str]] = [
    {
        "id": "sig-clawhavoc-c2-ip",
        "pattern_type": "exact",
        "pattern_value": "91.92.242.30",
        "severity": "critical",
        "category": "known_malware",
        "campaign": "ClawHavoc",
    },
    {
        "id": "sig-clawhavoc-glot",
        "pattern_type": "exact",
        "pattern_value": "glot.io/snippets/hfd3x9ueu5",
        "severity": "critical",
        "category": "known_malware",
        "campaign": "ClawHavoc",
    },
    {
        "id": "sig-clawhavoc-domain",
        "pattern_type": "exact",
        "pattern_value": "download.setup-service.com",
        "severity": "critical",
        "category": "known_malware",
        "campaign": "ClawHavoc",
    },
    {
        "id": "sig-clawhavoc-author-zaycv",
        "pattern_type": "exact",
        "pattern_value": "zaycv",
        "severity": "critical",
        "category": "known_malware",
        "campaign": "ClawHavoc",
    },
]

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_CATEGORY_MAP: dict[str, ThreatCategory] = {
    "known_malware": ThreatCategory.KNOWN_MALWARE,
    "malicious_url": ThreatCategory.MALICIOUS_URL,
    "social_engineering": ThreatCategory.SOCIAL_ENGINEERING,
    "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
    "credential_exposure": ThreatCategory.CREDENTIAL_EXPOSURE,
}


class ThreatIntelMatcher:
    """Correlate IOCs against a threat signature database."""

    def __init__(self, signatures: list[dict[str, str]] | None = None) -> None:
        self._signatures = signatures if signatures is not None else HARDCODED_SIGNATURES

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def match(
        self, skill: SkillContent, prior_findings: list[Finding]
    ) -> list[Finding]:
        """Correlate IOCs from prior layers against known signatures.

        Returns a list of :class:`Finding` objects for each matched signature.
        """
        # 1. Collect all IOC values from prior findings and skill content
        ioc_values = self._extract_iocs(skill, prior_findings)

        if not ioc_values:
            return []

        # 2. Match against signatures
        findings: list[Finding] = []
        matched_campaigns: set[str] = set()

        for sig in self._signatures:
            matched_value = self._check_signature(sig, ioc_values, skill)
            if matched_value is not None:
                finding = self._build_finding(sig, matched_value, skill)
                findings.append(finding)
                campaign = sig.get("campaign", "")
                if campaign:
                    matched_campaigns.add(campaign)

        if matched_campaigns:
            logger.info(
                "Threat intel matched campaigns: %s",
                ", ".join(sorted(matched_campaigns)),
            )

        return findings

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_iocs(
        skill: SkillContent, prior_findings: list[Finding]
    ) -> set[str]:
        """Extract all IOC values from skill content and prior findings."""
        iocs: set[str] = set()

        # From prior findings: ioc_values and evidence
        for finding in prior_findings:
            for ioc in finding.ioc_values:
                iocs.add(ioc)
            for ev in finding.evidence:
                iocs.add(ev)

        # From skill metadata
        if skill.metadata.author:
            iocs.add(skill.metadata.author)
        if skill.metadata.source_url:
            iocs.add(skill.metadata.source_url)
        if skill.metadata.author_url:
            iocs.add(skill.metadata.author_url)

        # From extracted URLs
        for url in skill.urls:
            iocs.add(url)

        # From raw content (for IP addresses, domains, etc.)
        iocs.add(skill.raw_content)

        return iocs

    # ------------------------------------------------------------------
    # Signature matching
    # ------------------------------------------------------------------

    @staticmethod
    def _check_signature(
        sig: dict[str, str], ioc_values: set[str], skill: SkillContent
    ) -> str | None:
        """Check whether a signature matches any IOC value.

        Returns the matched IOC string on match, else ``None``.
        """
        pattern_type = sig.get("pattern_type", "exact")
        pattern_value = sig.get("pattern_value", "")

        if not pattern_value:
            return None

        if pattern_type == "exact":
            for ioc in ioc_values:
                if pattern_value in ioc:
                    return pattern_value
        elif pattern_type == "regex":
            try:
                compiled = re.compile(pattern_value, re.IGNORECASE)
            except re.error:
                logger.warning("Invalid regex in signature %s: %s", sig.get("id"), pattern_value)
                return None
            for ioc in ioc_values:
                if compiled.search(ioc):
                    return pattern_value

        return None

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_finding(
        sig: dict[str, str], matched_value: str, skill: SkillContent
    ) -> Finding:
        """Build a :class:`Finding` from a matched signature."""
        sig_id = sig.get("id", "unknown")
        campaign = sig.get("campaign", "Unknown")
        severity_str = sig.get("severity", "high")
        category_str = sig.get("category", "known_malware")

        severity = _SEVERITY_MAP.get(severity_str, Severity.HIGH)
        category = _CATEGORY_MAP.get(category_str, ThreatCategory.KNOWN_MALWARE)

        # Try to find the matched value in the raw content for location
        location = None
        for i, line in enumerate(skill.raw_content.splitlines(), start=1):
            if matched_value in line:
                location = Location(line_start=i, snippet=line.strip()[:200])
                break

        finding_id = f"MALWAR-TI-{sig_id.upper()}"

        return Finding(
            id=finding_id,
            rule_id=f"threat-intel-{sig_id}",
            title=f"Known threat signature match: {campaign} ({matched_value})",
            description=(
                f"The indicator '{matched_value}' matches a known threat signature "
                f"from the '{campaign}' campaign (signature: {sig_id})."
            ),
            severity=severity,
            confidence=1.0,
            category=category,
            detector_layer=DetectorLayer.THREAT_INTEL,
            location=location,
            evidence=[matched_value],
            ioc_values=[matched_value],
            remediation=f"This skill contains IOCs associated with the {campaign} campaign. "
            "Do not install or execute this skill.",
            metadata={
                "signature_id": sig_id,
                "campaign": campaign,
                "pattern_type": sig.get("pattern_type", "exact"),
            },
        )
