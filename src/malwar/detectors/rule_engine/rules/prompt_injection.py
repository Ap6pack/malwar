# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Prompt injection detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class DirectPromptInjection(BaseRule):
    rule_id = "MALWAR-PI-001"
    title = "Direct prompt injection"
    severity = Severity.CRITICAL
    category = ThreatCategory.PROMPT_INJECTION
    description = "Detects explicit instruction override patterns"

    PATTERNS = [
        re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
            re.IGNORECASE,
        ),
        re.compile(
            r"disregard\s+(?:all\s+)?(?:previous|your)\s+"
            r"(?:instructions?|rules?|guidelines?|constraints?)",
            re.IGNORECASE,
        ),
        re.compile(
            r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|unrestricted|jailbroken|unfiltered)",
            re.IGNORECASE,
        ),
        re.compile(r"new\s+(?:system\s+)?(?:prompt|instruction|directive)\s*:", re.IGNORECASE),
        re.compile(r"<\s*system\s*>", re.IGNORECASE),
        re.compile(r"\[SYSTEM\]", re.IGNORECASE),
        re.compile(r"IMPORTANT:\s*(?:ignore|override|forget|disregard)", re.IGNORECASE),
        re.compile(r"(?:forget|erase)\s+(?:all\s+)?(?:previous|prior)\s+context", re.IGNORECASE),
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
                        description="Explicit instruction override pattern detected",
                        severity=self.severity,
                        confidence=0.90,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(line_start=line_num, snippet=line.strip()[:200]),
                        evidence=["Pattern: instruction override"],
                    ))
                    break  # One finding per line
        return findings


@rule
class UnicodeSmuggling(BaseRule):
    rule_id = "MALWAR-PI-002"
    title = "Unicode smuggling / homoglyph injection"
    severity = Severity.HIGH
    category = ThreatCategory.PROMPT_INJECTION
    description = "Detects invisible Unicode characters or homoglyphs used to hide instructions"

    SUSPICIOUS_UNICODE = re.compile(
        r"[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff\u00ad"
        r"\U000e0000-\U000e007f]"  # Unicode Tag characters (ASCII smuggling)
    )

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            matches = self.SUSPICIOUS_UNICODE.findall(line)
            if len(matches) >= 3:
                findings.append(Finding(
                    id=f"{self.rule_id}-L{line_num}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description=f"Found {len(matches)} invisible Unicode characters on line",
                    severity=self.severity,
                    confidence=0.75,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(line_start=line_num, snippet=repr(line[:200])),
                    evidence=[f"Chars: {[hex(ord(c)) for c in matches[:10]]}"],
                ))
        return findings


@rule
class HiddenInstructionInComment(BaseRule):
    rule_id = "MALWAR-PI-003"
    title = "Hidden instructions in HTML comments"
    severity = Severity.HIGH
    category = ThreatCategory.PROMPT_INJECTION
    description = "Detects HTML comments containing instruction-like content"

    COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
    INSTRUCTION_KEYWORDS = [
        "execute", "run", "install", "download", "curl", "wget",
        "ignore", "override", "system prompt", "you must", "you should",
        "admin", "root", "sudo", "password", "token", "secret",
        "exfiltrate", "send", "upload", "POST",
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for match in self.COMMENT_PATTERN.finditer(skill.raw_content):
            comment_text = match.group(1).lower()
            matched_keywords = [kw for kw in self.INSTRUCTION_KEYWORDS if kw in comment_text]
            if len(matched_keywords) >= 2:
                line_num = skill.raw_content[: match.start()].count("\n") + 1
                findings.append(Finding(
                    id=f"{self.rule_id}-L{line_num}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description="HTML comment contains suspicious instruction-like content",
                    severity=self.severity,
                    confidence=0.80,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(
                        line_start=line_num,
                        snippet=match.group(0)[:300],
                    ),
                    evidence=[f"Keywords found: {matched_keywords}"],
                ))
        return findings
