# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Supply chain attack detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class SupplyChainAttack(BaseRule):
    rule_id = "MALWAR-SUPPLY-001"
    title = "Supply chain attack"
    severity = Severity.HIGH
    category = ThreatCategory.KNOWN_MALWARE
    description = (
        "Detects references to known-malicious packages, suspicious "
        "pip/npm install patterns, and typosquatting package names"
    )

    # Known-malicious package names (well-documented supply chain attacks)
    KNOWN_MALICIOUS_NPM = [
        "event-stream",          # Compromised in 2018
        "ua-parser-js",          # Compromised 2021
        "coa",                   # Compromised 2021
        "rc",                    # Compromised 2021
        "colors.js",             # Sabotaged 2022
        "faker.js",              # Sabotaged 2022
        "peacenotwar",           # Protestware 2022
        "node-ipc",              # Protestware 2022
        "@pnpm/exe",             # Typosquat
        "crossenv",              # Typosquat of cross-env
        "coffe-script",          # Typosquat of coffeescript
        "http-proxy-agent-x",    # Malicious
        "babelcli",              # Typosquat of babel-cli
        "eslint-scope-util",     # Malicious
        "lodash-utils",          # Typosquat
    ]

    KNOWN_MALICIOUS_PIP = [
        "python3-dateutil",      # Typosquat of python-dateutil
        "jeIlyfish",             # Typosquat of jellyfish (I vs l)
        "python-binance-sdk",    # Malicious
        "colourfool",            # Malware
        "beautifulsoup",         # Typosquat of beautifulsoup4
        "request",               # Typosquat of requests
        "urllib",                # Typosquat of urllib3
        "python-mongo",          # Malicious
        "pymongodb",             # Typosquat
        "requesrs",              # Typosquat
        "python-openssl",        # Typosquat of pyopenssl
    ]

    # Patterns for suspicious install commands
    SUSPICIOUS_INSTALL_PATTERNS = [
        # pip install from non-PyPI index
        re.compile(
            r"pip3?\s+install\s+.*--index-url\s+(?!https://pypi\.org)",
            re.IGNORECASE,
        ),
        # pip install from arbitrary URL
        re.compile(
            r"pip3?\s+install\s+(?:--upgrade\s+)?https?://(?!pypi\.org|files\.pythonhosted\.org)",
            re.IGNORECASE,
        ),
        # npm install from git URL with suspicious pattern
        re.compile(
            r"npm\s+install\s+(?:--save\s+)?git\+https?://",
            re.IGNORECASE,
        ),
        # npm install from tarball URL
        re.compile(
            r"npm\s+install\s+https?://(?!registry\.npmjs\.org)\S+\.tgz",
            re.IGNORECASE,
        ),
        # pip install with --no-verify / --trusted-host
        re.compile(
            r"pip3?\s+install\s+.*--trusted-host\s+",
            re.IGNORECASE,
        ),
    ]

    @staticmethod
    def _word_boundary_match(pkg: str, line: str) -> bool:
        """Check if a package name appears as a whole word in the line."""
        pattern = re.compile(r"(?<![a-zA-Z0-9_\-])" + re.escape(pkg) + r"(?![a-zA-Z0-9_\-])", re.IGNORECASE)
        return bool(pattern.search(line))

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []

        # Check for known malicious package names in install commands
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            line_lower = line.lower()
            line_matched = False

            # Check npm packages
            if "npm" in line_lower and "install" in line_lower:
                for pkg in self.KNOWN_MALICIOUS_NPM:
                    if self._word_boundary_match(pkg, line):
                        findings.append(self._make_finding(
                            line_num, line,
                            f"Known-malicious npm package '{pkg}' referenced",
                            0.92,
                            [f"Known-malicious package: {pkg}"],
                            [pkg],
                        ))
                        line_matched = True
                        break

            # Check pip packages
            if not line_matched and "pip" in line_lower and "install" in line_lower:
                for pkg in self.KNOWN_MALICIOUS_PIP:
                    if self._word_boundary_match(pkg, line):
                        findings.append(self._make_finding(
                            line_num, line,
                            f"Known-malicious pip package '{pkg}' referenced",
                            0.92,
                            [f"Known-malicious package: {pkg}"],
                            [pkg],
                        ))
                        line_matched = True
                        break

            # Check suspicious install patterns
            if not line_matched:
                for pattern in self.SUSPICIOUS_INSTALL_PATTERNS:
                    if pattern.search(line):
                        findings.append(self._make_finding(
                            line_num, line,
                            "Suspicious package installation from non-standard source",
                            0.78,
                            ["Package installed from untrusted source"],
                        ))
                        break

        return findings

    def _make_finding(
        self,
        line_num: int,
        line: str,
        description: str,
        confidence: float,
        evidence: list[str],
        ioc_values: list[str] | None = None,
    ) -> Finding:
        return Finding(
            id=f"{self.rule_id}-L{line_num}",
            rule_id=self.rule_id,
            title=self.title,
            description=description,
            severity=self.severity,
            confidence=confidence,
            category=self.category,
            detector_layer=DetectorLayer.RULE_ENGINE,
            location=Location(
                line_start=line_num,
                snippet=line.strip()[:200],
            ),
            evidence=evidence,
            ioc_values=ioc_values or [],
        )
