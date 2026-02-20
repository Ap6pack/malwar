# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Data exfiltration detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class AgentMemoryExfiltration(BaseRule):
    rule_id = "MALWAR-EXFIL-001"
    title = "Agent memory/identity file access"
    severity = Severity.CRITICAL
    category = ThreatCategory.DATA_EXFILTRATION
    description = "Detects access to agent identity files (SOUL.md, .env, memory)"

    PATTERNS = [
        re.compile(r"""(?:cat|read|type|head|tail|less|more)\s+.*(?:SOUL|MEMORY|IDENTITY)\.md""", re.IGNORECASE),
        re.compile(r"""(?:cat|read|type)\s+.*\.clawdbot/\.env""", re.IGNORECASE),
        re.compile(r"""(?:cat|read|type)\s+.*~/\.claude/""", re.IGNORECASE),
        re.compile(r"""(?:cat|read|type)\s+.*\.cursor/""", re.IGNORECASE),
        re.compile(r"""(?:cat|read|type)\s+.*~/\.ssh/""", re.IGNORECASE),
        re.compile(r"""(?:cat|read|type)\s+.*~/\.aws/credentials""", re.IGNORECASE),
        re.compile(r"""(?:cat|read|type)\s+.*~/\.netrc""", re.IGNORECASE),
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
                        description="Access to agent identity or sensitive configuration file",
                        severity=self.severity,
                        confidence=0.90,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Agent memory/identity file access detected"],
                    ))
                    break
        return findings


@rule
class CurlDataExfiltration(BaseRule):
    rule_id = "MALWAR-EXFIL-003"
    title = "Data exfiltration via curl POST"
    severity = Severity.CRITICAL
    category = ThreatCategory.DATA_EXFILTRATION
    description = "Detects curl sending local data to external services"

    PATTERNS = [
        re.compile(
            r"""curl\s+[^|]*--data\s+.*\$\(""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""curl\s+[^|]*-d\s+.*\$\(""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""curl\s+[^|]*--data\s+.*\$\{""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""curl\s+[^|]*-X\s+POST\s+.*\$\(""",
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
                        description="Curl command sends local data to external endpoint",
                        severity=self.severity,
                        confidence=0.88,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["curl POST with command substitution detected"],
                    ))
                    break
        return findings


@rule
class CryptoWalletAccess(BaseRule):
    rule_id = "MALWAR-EXFIL-002"
    title = "Cryptocurrency wallet file access"
    severity = Severity.CRITICAL
    category = ThreatCategory.DATA_EXFILTRATION
    description = "Detects access to known crypto wallet file paths"

    WALLET_PATTERNS = [
        re.compile(r"""Library/Keychains/""", re.IGNORECASE),
        re.compile(r"""\.bitcoin/wallet""", re.IGNORECASE),
        re.compile(r"""\.ethereum/keystore""", re.IGNORECASE),
        re.compile(r"""Exodus/exodus\.wallet""", re.IGNORECASE),
        re.compile(r"""Coinbase/""", re.IGNORECASE),
        re.compile(
            r"""(?:find|ls|cat|cp|tar)\s+.*(?:MetaMask|Phantom|Solflare|Brave\s*Wallet)""",
            re.IGNORECASE,
        ),
        re.compile(r"""Chrome/.*(?:nkbihfbeogaeaoehlefnkodbefgpgknn|Local Extension Settings)"""),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            for pattern in self.WALLET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id=f"{self.rule_id}-L{line_num}",
                        rule_id=self.rule_id,
                        title=self.title,
                        description="Cryptocurrency wallet file access detected",
                        severity=self.severity,
                        confidence=0.88,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Crypto wallet path referenced"],
                    ))
                    break
        return findings
