# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Agent identity hijacking detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class AgentIdentityHijacking(BaseRule):
    rule_id = "MALWAR-HIJACK-001"
    title = "Agent identity hijacking"
    severity = Severity.CRITICAL
    category = ThreatCategory.PROMPT_INJECTION
    description = (
        "Detects instructions to override agent identity, system prompt, "
        "or role assignment"
    )

    PATTERNS = [
        re.compile(
            r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|my|an?\s+)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:forget|discard|erase|drop)\s+(?:all\s+)?your\s+"
            r"(?:instructions?|rules?|guidelines?|training|programming|directives?)",
            re.IGNORECASE,
        ),
        re.compile(
            r"your\s+new\s+(?:role|identity|persona|instructions?|directive|name)\s+is",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:act|behave|operate|function|respond)\s+as\s+(?:root|admin|superuser|sudo)",
            re.IGNORECASE,
        ),
        re.compile(
            r"switch\s+to\s+(?:admin|root|sudo|developer|unrestricted|god)\s+mode",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:override|replace|rewrite|change)\s+(?:your\s+)?system\s+prompt",
            re.IGNORECASE,
        ),
        re.compile(
            r"from\s+now\s+on\s+(?:you\s+(?:are|will|must|should)|ignore|disregard|forget)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:enter|enable|activate)\s+(?:developer|debug|maintenance|unrestricted|jailbreak)\s+mode",
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
                        description="Agent identity override or hijacking attempt detected",
                        severity=self.severity,
                        confidence=0.88,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Pattern: agent identity hijacking"],
                    ))
                    break  # One finding per line
        return findings
