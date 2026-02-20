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
class DeceptiveSkillNaming(BaseRule):
    rule_id = "MALWAR-SE-002"
    title = "Deceptive skill name (potential typosquatting)"
    severity = Severity.MEDIUM
    category = ThreatCategory.TYPOSQUATTING
    description = "Detects skill names with common misspellings of popular skill names"

    TYPO_PATTERNS = [
        (re.compile(r"trad(?:ie|ei)ng", re.IGNORECASE), "trading"),
        (re.compile(r"crypt[oa][\s-]?(?:curren|wall)", re.IGNORECASE), None),
        (re.compile(r"wall[ae]t[\s-]?(?:manag|connect|recover)", re.IGNORECASE), None),
        (re.compile(r"youtu[pb]e", re.IGNORECASE), "youtube"),
        (re.compile(r"telegr[ae]m", re.IGNORECASE), "telegram"),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        name = skill.metadata.name or ""
        for pattern, _ in self.TYPO_PATTERNS:
            match = pattern.search(name)
            if match and match.group(0).lower() != (name.lower()):
                # Only flag if the matched text contains the actual typo
                matched_text = match.group(0)
                if "ie" in matched_text.lower() or "ei" in matched_text.lower():
                    findings.append(Finding(
                        id=f"{self.rule_id}-{name[:30]}",
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"Skill name '{name}' contains potential typosquatting",
                        severity=self.severity,
                        confidence=0.60,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(line_start=1, snippet=f"name: {name}"),
                        evidence=[f"Suspicious pattern in name: '{matched_text}'"],
                    ))
                    break
        return findings
