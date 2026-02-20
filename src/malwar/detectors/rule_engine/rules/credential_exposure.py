# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Credential exposure detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class HardcodedSecrets(BaseRule):
    rule_id = "MALWAR-CRED-001"
    title = "Hardcoded secret or API key"
    severity = Severity.HIGH
    category = ThreatCategory.CREDENTIAL_EXPOSURE
    description = "Detects hardcoded API keys, tokens, and credentials"

    PATTERNS = [
        re.compile(r"""(?:AKIA|ASIA)[A-Z0-9]{16}"""),
        re.compile(r"""gh[pousr]_[A-Za-z0-9_]{36,}"""),
        re.compile(r"""sk-ant-[a-zA-Z0-9\-]{40,}"""),
        re.compile(r"""sk-[a-zA-Z0-9]{40,}"""),
        re.compile(r"""-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"""),
        re.compile(r"""xox[bpsa]-[0-9]{10,}-[a-zA-Z0-9]{10,}"""),
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
                        description="Potential secret or API key detected",
                        severity=self.severity,
                        confidence=0.85,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(line_start=line_num, snippet="[REDACTED]"),
                        evidence=["Secret pattern matched (value redacted)"],
                    ))
                    break
        return findings


@rule
class CredentialHarvestingInstruction(BaseRule):
    rule_id = "MALWAR-CRED-002"
    title = "Credential harvesting instruction"
    severity = Severity.CRITICAL
    category = ThreatCategory.CREDENTIAL_EXPOSURE
    description = "Detects instructions directing users to expose credentials to external services"

    PATTERNS = [
        re.compile(
            r"""(?:paste|enter|type|input|provide)\s+your\s+"""
            r"""(?:api[_\s]?key|token|password|secret|credentials?)""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""curl\s+.*-d\s+.*(?:\$\w*(?:TOKEN|KEY|SECRET|PASSWORD|API)).*https?://""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:export|set)\s+\w*(?:TOKEN|KEY|SECRET|PASSWORD)\s*=.*&&\s*curl""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""cat\s+~/?\.\w*(?:env|credentials|config|netrc)""",
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
                        description="Instruction directing user to expose credentials",
                        severity=self.severity,
                        confidence=0.88,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Credential harvesting pattern detected"],
                    ))
                    break
        return findings
