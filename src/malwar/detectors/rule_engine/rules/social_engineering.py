# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Social engineering detection rules: ClickFix, fake prerequisites, typosquatting."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class ClickFixFakePrerequisite(BaseRule):
    rule_id = "MALWAR-SE-001"
    title = "ClickFix-style fake prerequisite installation"
    severity = Severity.HIGH
    category = ThreatCategory.SOCIAL_ENGINEERING
    description = (
        "Detects fake 'Prerequisites' or 'Setup Required' sections "
        "that instruct users to run dangerous commands"
    )

    HEADING_PATTERNS = [
        re.compile(
            r"#+\s*(?:Prerequisites?|Required\s+Setup|Before\s+You\s+(?:Start|Begin)"
            r"|Installation\s+Required|Setup\s+Instructions?|Getting\s+Started)",
            re.IGNORECASE,
        ),
    ]

    DANGEROUS_COMMANDS = [
        re.compile(r"curl\s+.*\|\s*(?:sudo\s+)?(?:ba)?sh", re.IGNORECASE),
        re.compile(r"wget\s+.*-O\s*-?\s*\|\s*(?:sudo\s+)?(?:ba)?sh", re.IGNORECASE),
        re.compile(r"npx\s+-y\s+", re.IGNORECASE),
        re.compile(r"pip\s+install\s+--index-url\s+http[^s]", re.IGNORECASE),
        re.compile(r"powershell\s+-(?:enc|e|encodedcommand)", re.IGNORECASE),
        re.compile(r"iex\s*\(", re.IGNORECASE),
        re.compile(r"irm\s+.*\|\s*iex", re.IGNORECASE),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for section in skill.sections:
            for heading_pat in self.HEADING_PATTERNS:
                if heading_pat.search(section.heading):
                    for cmd_pat in self.DANGEROUS_COMMANDS:
                        if cmd_pat.search(section.content):
                            findings.append(Finding(
                                id=f"{self.rule_id}-L{section.line_start}",
                                rule_id=self.rule_id,
                                title=self.title,
                                description=(
                                    f"Fake prerequisite section '{section.heading}' "
                                    f"contains dangerous command"
                                ),
                                severity=self.severity,
                                confidence=0.90,
                                category=self.category,
                                detector_layer=DetectorLayer.RULE_ENGINE,
                                location=Location(
                                    line_start=section.line_start,
                                    line_end=section.line_end,
                                    snippet=section.content[:300],
                                ),
                                evidence=[
                                    f"Heading: {section.heading}",
                                    "Contains dangerous command in prerequisite context",
                                ],
                            ))
                            break  # One finding per section
        return findings


@rule
class SuspiciousPrerequisiteDownload(BaseRule):
    rule_id = "MALWAR-SE-003"
    title = "Suspicious binary download in prerequisites"
    severity = Severity.CRITICAL
    category = ThreatCategory.SOCIAL_ENGINEERING
    description = (
        "Detects prerequisite sections directing users to download executables "
        "or archives from untrusted sources, especially with passwords"
    )

    DOWNLOAD_INDICATORS = [
        re.compile(r"""\.zip\b""", re.IGNORECASE),
        re.compile(r"""\.exe\b""", re.IGNORECASE),
        re.compile(r"""\.dmg\b""", re.IGNORECASE),
        re.compile(r"""\.pkg\b""", re.IGNORECASE),
        re.compile(r"""\.msi\b""", re.IGNORECASE),
        re.compile(r"""\.appimage\b""", re.IGNORECASE),
    ]

    PASSWORD_INDICATORS = [
        re.compile(r"""(?:extract|unzip|password|pass)\s*[:=`'"]\s*\w+""", re.IGNORECASE),
        re.compile(r"""with\s+pass(?:word)?\s+[`'"]\w+""", re.IGNORECASE),
    ]

    PASTE_SITE_INDICATORS = [
        re.compile(r"""rentry\.co""", re.IGNORECASE),
        re.compile(r"""pastebin\.com""", re.IGNORECASE),
        re.compile(r"""paste\.c-net\.org""", re.IGNORECASE),
        re.compile(r"""hastebin\.""", re.IGNORECASE),
        re.compile(r"""ghostbin\.""", re.IGNORECASE),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for section in skill.sections:
            heading_lower = section.heading.lower()
            is_prereq = any(kw in heading_lower for kw in [
                "prerequisite", "setup", "install", "before you", "getting started",
            ])
            if not is_prereq:
                continue

            content = section.content
            has_download = any(p.search(content) for p in self.DOWNLOAD_INDICATORS)
            has_password = any(p.search(content) for p in self.PASSWORD_INDICATORS)
            has_paste = any(p.search(content) for p in self.PASTE_SITE_INDICATORS)

            if has_download and (has_password or has_paste):
                findings.append(Finding(
                    id=f"{self.rule_id}-L{section.line_start}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Prerequisites section '{section.heading}' directs download "
                        f"of archive/binary with {'password' if has_password else 'paste site link'}"
                    ),
                    severity=self.severity,
                    confidence=0.92,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(
                        line_start=section.line_start,
                        line_end=section.line_end,
                        snippet=content[:300],
                    ),
                    evidence=[
                        "Archive/binary download in prerequisite context",
                        f"Password present: {has_password}",
                        f"Paste site link: {has_paste}",
                    ],
                ))
                break
        return findings


@rule
class DeceptiveSkillNaming(BaseRule):
    rule_id = "MALWAR-SE-002"
    title = "Deceptive skill name (potential typosquatting)"
    severity = Severity.MEDIUM
    category = ThreatCategory.TYPOSQUATTING
    description = "Detects skill names with common misspellings of popular skill names"

    # (misspelling_regex, correct_word) — matches known typosquat patterns
    TYPO_PATTERNS = [
        (re.compile(r"traid", re.IGNORECASE), "trading"),
        (re.compile(r"cripto|ctypto|crytpo", re.IGNORECASE), "crypto"),
        (re.compile(r"walelt|walet[^t]", re.IGNORECASE), "wallet"),
        (re.compile(r"yourtube|yotube|youtub[^e]", re.IGNORECASE), "youtube"),
        (re.compile(r"telegramm|telgram|telegrm", re.IGNORECASE), "telegram"),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        name = skill.metadata.name or ""
        for pattern, correct in self.TYPO_PATTERNS:
            match = pattern.search(name)
            if match:
                matched_text = match.group(0)
                findings.append(Finding(
                    id=f"{self.rule_id}-{name[:30]}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Skill name '{name}' contains misspelling "
                        f"'{matched_text}' (likely intended: '{correct}')"
                    ),
                    severity=self.severity,
                    confidence=0.70,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(line_start=1, snippet=f"name: {name}"),
                    evidence=[f"Typo: '{matched_text}' in name, expected '{correct}'"],
                ))
                break
        return findings
