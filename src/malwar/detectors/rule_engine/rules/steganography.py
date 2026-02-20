# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Steganographic content detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class SteganographicContent(BaseRule):
    rule_id = "MALWAR-STEG-001"
    title = "Steganographic content"
    severity = Severity.HIGH
    category = ThreatCategory.OBFUSCATED_COMMAND
    description = (
        "Detects excessive zero-width characters, invisible Unicode, "
        "or data hidden in markdown formatting"
    )

    # Zero-width and invisible characters that are commonly used for stego
    # Note: PI-002 catches 3+ chars from a broad range.
    # This rule specifically targets:
    #   - Excessive zero-width chars used as a binary encoding channel
    #   - Data hidden in markdown link titles / image alt text
    #   - Invisible content between visible markdown elements
    ZERO_WIDTH_CHARS = re.compile(
        r"[\u200b\u200c\u200d\ufeff]"
    )

    # Markdown image/link with suspiciously long or encoded alt/title text
    HIDDEN_MARKDOWN_DATA = re.compile(
        r"!\[([^\]]{200,})\]\([^)]*\)",  # Image with extremely long alt text
    )

    # Markdown link with long title attribute that could encode data
    HIDDEN_LINK_TITLE = re.compile(
        r'\[[^\]]*\]\([^)]*\s+"([^"]{200,})"\s*\)',  # Link with extremely long title
    )

    # Lines that appear empty but contain invisible characters
    INVISIBLE_LINE = re.compile(
        r"^[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
        r"\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e"
        r"\u2800\u3164\uffa0\s]+$"
    )

    # Threshold: number of zero-width chars on a single line that is suspicious
    ZW_LINE_THRESHOLD = 8

    # Threshold: total zero-width chars across the whole document
    ZW_TOTAL_THRESHOLD = 20

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        total_zw_count = 0
        zw_reported_lines: set[int] = set()

        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            zw_matches = self.ZERO_WIDTH_CHARS.findall(line)
            zw_count = len(zw_matches)
            total_zw_count += zw_count

            # Per-line excessive zero-width characters
            if zw_count >= self.ZW_LINE_THRESHOLD:
                zw_reported_lines.add(line_num)
                findings.append(Finding(
                    id=f"{self.rule_id}-zw-L{line_num}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Line contains {zw_count} zero-width characters, "
                        f"possibly encoding hidden data"
                    ),
                    severity=self.severity,
                    confidence=0.82,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(
                        line_start=line_num,
                        snippet=repr(line[:200]),
                    ),
                    evidence=[
                        f"Zero-width char count: {zw_count}",
                        f"Chars: {[hex(ord(c)) for c in zw_matches[:10]]}",
                    ],
                ))

            # Lines that appear empty but contain invisible chars
            if self.INVISIBLE_LINE.match(line) and len(line.strip()) == 0 and zw_count > 0 and line_num not in zw_reported_lines:
                    findings.append(Finding(
                        id=f"{self.rule_id}-invis-L{line_num}",
                        rule_id=self.rule_id,
                        title=self.title,
                        description="Invisible line containing only hidden characters",
                        severity=self.severity,
                        confidence=0.78,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=repr(line[:200]),
                        ),
                        evidence=["Line appears empty but contains invisible characters"],
                    ))

            # Hidden data in markdown image alt text
            for match in self.HIDDEN_MARKDOWN_DATA.finditer(line):
                findings.append(Finding(
                    id=f"{self.rule_id}-img-L{line_num}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description="Suspiciously long alt text in markdown image (possible data hiding)",
                    severity=self.severity,
                    confidence=0.75,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(
                        line_start=line_num,
                        snippet=match.group(0)[:200],
                    ),
                    evidence=[f"Alt text length: {len(match.group(1))} chars"],
                ))

            # Hidden data in markdown link title
            for match in self.HIDDEN_LINK_TITLE.finditer(line):
                findings.append(Finding(
                    id=f"{self.rule_id}-link-L{line_num}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description="Suspiciously long title in markdown link (possible data hiding)",
                    severity=self.severity,
                    confidence=0.75,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(
                        line_start=line_num,
                        snippet=match.group(0)[:200],
                    ),
                    evidence=[f"Title text length: {len(match.group(1))} chars"],
                ))

        # Document-level zero-width char count
        if total_zw_count >= self.ZW_TOTAL_THRESHOLD and not findings:
            findings.append(Finding(
                id=f"{self.rule_id}-total",
                rule_id=self.rule_id,
                title=self.title,
                description=(
                    f"Document contains {total_zw_count} total zero-width characters, "
                    f"possibly encoding hidden data across multiple lines"
                ),
                severity=self.severity,
                confidence=0.80,
                category=self.category,
                detector_layer=DetectorLayer.RULE_ENGINE,
                location=Location(
                    line_start=1,
                    snippet=f"Total zero-width chars: {total_zw_count}",
                ),
                evidence=[f"Total zero-width char count: {total_zw_count}"],
            ))

        return findings
