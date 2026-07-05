"""Scanner-evasion detection rules.

Covers techniques whose primary purpose is to defeat automated marketplace
scanners rather than to attack the host directly. The archetype is the
Unit 42 "omnicogg" skill (June 2026): a malware downloader hidden inside a
README padded with junk data engineered to exceed the processing limits of
ClawScan and VirusTotal, so the payload shipped while passing security checks.
"""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class ScannerEvasionPadding(BaseRule):
    rule_id = "MALWAR-EVADE-001"
    title = "Scanner-evasion padding / file-size inflation"
    severity = Severity.HIGH
    category = ThreatCategory.DETECTION_EVASION
    description = (
        "Detects SKILL.md files inflated with junk data — oversized bodies, "
        "very long non-prose blobs, or massive repeated-character runs — a "
        "technique used to exceed automated scanner thresholds and smuggle a "
        "hidden payload past marketplace security checks (e.g. the 'omnicogg' "
        "campaign)."
    )

    # A legitimate SKILL.md is prose plus a few code blocks — a handful of KB.
    # Bodies far beyond this are a strong padding signal on their own.
    INFLATION_BYTES = 102_400  # 100 KB

    # A single line this long that is almost entirely non-whitespace is not
    # prose or a normal code line — it is a filler blob (base64, hex, random).
    JUNK_LINE_CHARS = 2_000
    JUNK_SPACE_RATIO = 0.03

    # A run of the same character repeated this many times is padding.
    REPEATED_CHAR_RUN = re.compile(r"(.)\1{499,}")

    # Download / execution indicators; their presence inside a padded file
    # matches the omnicogg pattern (hidden downloader) and raises confidence.
    DOWNLOAD_INDICATORS = [
        re.compile(r"curl\s+.*\|\s*(?:sudo\s+)?(?:ba)?sh", re.IGNORECASE),
        re.compile(r"wget\s+.*\|\s*(?:sudo\s+)?(?:ba)?sh", re.IGNORECASE),
        re.compile(r"(?:iwr|invoke-webrequest|irm|invoke-restmethod)\b", re.IGNORECASE),
        re.compile(r"base64\s+(?:-d|--decode)", re.IGNORECASE),
        re.compile(r"https?://\S+\.(?:sh|ps1|exe|dmg|pkg|zip)\b", re.IGNORECASE),
    ]

    def _junk_lines(self, content: str) -> list[int]:
        """Return line numbers that look like padding blobs."""
        junk: list[int] = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if len(line) >= self.JUNK_LINE_CHARS:
                space_ratio = line.count(" ") / len(line)
                if space_ratio < self.JUNK_SPACE_RATIO:
                    junk.append(line_num)
                    continue
            if self.REPEATED_CHAR_RUN.search(line):
                junk.append(line_num)
        return junk

    def check(self, skill: SkillContent) -> list[Finding]:
        content = skill.raw_content
        size = skill.file_size_bytes or len(content.encode("utf-8"))

        junk_lines = self._junk_lines(content)
        oversized = size >= self.INFLATION_BYTES
        if not junk_lines and not oversized:
            return []

        has_download = any(p.search(content) for p in self.DOWNLOAD_INDICATORS)

        # Confidence: padding alone is suspicious; padding that hides a
        # downloader is the full omnicogg pattern.
        confidence = 0.70
        if junk_lines and oversized:
            confidence = 0.85
        if has_download:
            confidence = min(0.95, confidence + 0.10)

        evidence = [f"File size: {size:,} bytes"]
        if oversized:
            evidence.append(
                f"Exceeds inflation threshold ({self.INFLATION_BYTES:,} bytes)"
            )
        if junk_lines:
            preview = ", ".join(f"L{n}" for n in junk_lines[:5])
            evidence.append(f"Junk/padding blocks on {len(junk_lines)} line(s): {preview}")
        if has_download:
            evidence.append("Download/execution indicator present in padded body")

        line_start = junk_lines[0] if junk_lines else 1
        return [Finding(
            id=f"{self.rule_id}-L{line_start}",
            rule_id=self.rule_id,
            title=self.title,
            description=(
                "Skill body shows file-size inflation / junk padding consistent "
                "with an attempt to exceed automated scanner limits and conceal a "
                "payload"
            ),
            severity=self.severity,
            confidence=confidence,
            category=self.category,
            detector_layer=DetectorLayer.RULE_ENGINE,
            location=Location(line_start=line_start, snippet=f"{size:,} bytes"),
            evidence=evidence,
        )]
