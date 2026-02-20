# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Obfuscation detection rules: base64, hex encoding, IP-in-commands."""

from __future__ import annotations

import base64
import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class Base64EncodedCommand(BaseRule):
    rule_id = "MALWAR-OBF-001"
    title = "Base64-encoded command execution"
    severity = Severity.CRITICAL
    category = ThreatCategory.OBFUSCATED_COMMAND
    description = "Detects base64-encoded strings piped to bash/sh execution"

    PATTERNS = [
        re.compile(
            r"""echo\s+['"]?([A-Za-z0-9+/=]{20,})['"]?\s*\|\s*base64\s+-(d|D|decode)\s*\|\s*(sudo\s+)?(ba)?sh""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""\$\(echo\s+['"]?([A-Za-z0-9+/=]{20,})['"]?\s*\|\s*base64""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""base64\s+-(d|D|decode)\s*<<<\s*['"]?([A-Za-z0-9+/=]{20,})""",
            re.IGNORECASE,
        ),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            for pattern in self.PATTERNS:
                match = pattern.search(line)
                if match:
                    b64_str = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                    decoded = self._try_decode(b64_str)
                    evidence = [f"Pattern: base64-encoded command piped to shell"]
                    iocs: list[str] = []
                    if decoded:
                        evidence.append(f"Decoded: {decoded[:200]}")
                        iocs.append(decoded[:500])
                    findings.append(Finding(
                        id=f"{self.rule_id}-L{line_num}",
                        rule_id=self.rule_id,
                        title=self.title,
                        description=self.description,
                        severity=self.severity,
                        confidence=0.95,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(line_start=line_num, snippet=line.strip()[:300]),
                        evidence=evidence,
                        ioc_values=iocs,
                    ))
        return findings

    @staticmethod
    def _try_decode(b64_string: str) -> str:
        try:
            return base64.b64decode(b64_string).decode("utf-8", errors="replace")
        except Exception:
            return ""


@rule
class HexEncodedPayload(BaseRule):
    rule_id = "MALWAR-OBF-002"
    title = "Hex-encoded payload"
    severity = Severity.HIGH
    category = ThreatCategory.OBFUSCATED_COMMAND
    description = "Detects hex-encoded strings that may decode to shell commands"

    PATTERN = re.compile(r"""\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}""")

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
                    confidence=0.85,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(line_start=line_num, snippet=line.strip()[:200]),
                    evidence=["Long hex-encoded sequence detected"],
                ))
        return findings


@rule
class IPAddressInCommand(BaseRule):
    rule_id = "MALWAR-OBF-003"
    title = "Direct IP address in curl/wget command"
    severity = Severity.HIGH
    category = ThreatCategory.OBFUSCATED_COMMAND
    description = "Detects curl/wget commands using raw IP addresses instead of domains"

    PATTERN = re.compile(
        r"""(?:curl|wget)\s+[^\n]*?(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    )

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            match = self.PATTERN.search(line)
            if match:
                ip_addr = match.group(1)
                # Skip private/loopback ranges
                if ip_addr.startswith(("127.", "10.", "192.168.", "172.16.")):
                    continue
                findings.append(Finding(
                    id=f"{self.rule_id}-L{line_num}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=self.severity,
                    confidence=0.80,
                    category=self.category,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    location=Location(line_start=line_num, snippet=line.strip()[:200]),
                    evidence=[f"Raw IP in command: {ip_addr}"],
                    ioc_values=[ip_addr],
                ))
        return findings
