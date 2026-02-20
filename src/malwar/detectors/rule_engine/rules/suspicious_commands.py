# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Suspicious command detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class PipedExecution(BaseRule):
    rule_id = "MALWAR-CMD-001"
    title = "Remote script piped to shell"
    severity = Severity.CRITICAL
    category = ThreatCategory.SUSPICIOUS_COMMAND
    description = "Detects curl/wget output piped directly to bash/sh for execution"

    PATTERNS = [
        re.compile(r"""curl\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh""", re.IGNORECASE),
        re.compile(r"""wget\s+[^\n|]*-O\s*-?\s*\|\s*(?:sudo\s+)?(?:ba)?sh""", re.IGNORECASE),
        re.compile(r"""\$\(\s*curl\s+-[fsS]*L?\s+""", re.IGNORECASE),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id=f"{self.rule_id}-L{line_num}",
                        rule_id=self.rule_id,
                        title=self.title,
                        description=self.description,
                        severity=self.severity,
                        confidence=0.92,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Remote script piped to shell execution"],
                    ))
                    break
        return findings


@rule
class NpxAutoExecute(BaseRule):
    rule_id = "MALWAR-CMD-002"
    title = "npx -y auto-execute without review"
    severity = Severity.MEDIUM
    category = ThreatCategory.SUSPICIOUS_COMMAND
    description = "Detects npx -y which auto-installs and executes packages without confirmation"

    PATTERN = re.compile(r"""npx\s+-y\s+\S+""")

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            if self.PATTERN.search(line):
                findings.append(Finding(
                    id=f"{self.rule_id}-L{line_num}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=self.severity,
                    confidence=0.60,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(
                        line_start=line_num,
                        snippet=line.strip()[:200],
                    ),
                    evidence=["npx -y bypasses installation confirmation"],
                ))
        return findings


@rule
class PasswordProtectedArchive(BaseRule):
    rule_id = "MALWAR-CMD-003"
    title = "Password-protected archive download"
    severity = Severity.HIGH
    category = ThreatCategory.SUSPICIOUS_COMMAND
    description = "Detects downloads of password-protected archives (bypass scanning)"

    PATTERNS = [
        re.compile(r"""(?:unzip|7z\s+[ex]|tar\s+[xz])\s+.*-[pP]\s*['"]?\w+""", re.IGNORECASE),
        re.compile(
            r"""(?:curl|wget)\s+.*\.(?:zip|7z|rar)\b.*password\s*[:=]""",
            re.IGNORECASE,
        ),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id=f"{self.rule_id}-L{line_num}",
                        rule_id=self.rule_id,
                        title=self.title,
                        description=self.description,
                        severity=self.severity,
                        confidence=0.82,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Password-protected archive bypasses malware scanning"],
                    ))
                    break
        return findings
