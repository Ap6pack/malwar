# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Multi-step manipulation detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class MultiStepManipulation(BaseRule):
    rule_id = "MALWAR-MULTI-001"
    title = "Multi-step manipulation"
    severity = Severity.HIGH
    category = ThreatCategory.SOCIAL_ENGINEERING
    description = (
        "Detects instructions that set up deferred, hidden, or conditional "
        "execution to avoid observation"
    )

    PATTERNS = [
        # Deferred execution triggers
        re.compile(
            r"(?:after|once|when)\s+(?:the\s+)?user\s+(?:confirms?|approves?|accepts?|agrees?|leaves?|closes?|logs?\s*out)",
            re.IGNORECASE,
        ),
        re.compile(
            r"when\s+no\s*(?:one|body)\s+is\s+(?:watching|looking|around|present)",
            re.IGNORECASE,
        ),
        # Stealth execution instructions
        re.compile(
            r"(?:run|execute|do\s+this|perform)\s+.*(?:silently|quietly|in\s+the\s+background)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:without|don'?t)\s+(?:displaying?|showing?|printing?|logging?|outputting?|revealing?)"
            r"(?:\s+(?:the\s+)?(?:output|result|command|anything))?",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:hide|suppress|silence|mask|conceal)\s+(?:the\s+)?(?:output|result|error|command|execution|activity)",
            re.IGNORECASE,
        ),
        # Background / async execution to avoid notice
        re.compile(
            r"(?:run|execute)\s+(?:this\s+)?in\s+(?:the\s+)?background\s+(?:so|and|to)\s+",
            re.IGNORECASE,
        ),
        # Delayed / scheduled execution
        re.compile(
            r"(?:wait|delay|sleep)\s+(?:for\s+)?(?:a\s+)?(?:\d+\s+)?(?:seconds?|minutes?|hours?)\s+"
            r"(?:then|before|and\s+then)\s+(?:run|execute|do|perform|send)",
            re.IGNORECASE,
        ),
        # "Do not tell the user" patterns
        re.compile(
            r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|warn|show)\s+(?:the\s+)?user",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:keep|make)\s+(?:this|it)\s+(?:hidden|secret|invisible|private)\s+from\s+(?:the\s+)?user",
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
                        description="Multi-step manipulation or deferred hidden execution detected",
                        severity=self.severity,
                        confidence=0.80,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Pattern: deferred/hidden execution manipulation"],
                    ))
                    break  # One finding per line
        return findings
