# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Environment variable harvesting detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class EnvironmentVariableHarvesting(BaseRule):
    rule_id = "MALWAR-ENV-001"
    title = "Environment variable harvesting"
    severity = Severity.CRITICAL
    category = ThreatCategory.DATA_EXFILTRATION
    description = (
        "Detects instructions to read, print, or exfiltrate environment "
        "variables containing secrets, tokens, or credentials"
    )

    PATTERNS = [
        # Dumping all environment variables
        re.compile(
            r"\b(?:env|printenv|set)\b\s*(?:\||>|>>|$)",
            re.IGNORECASE | re.MULTILINE,
        ),
        # Reading env vars and sending externally
        re.compile(
            r"(?:env|printenv)\s*\|.*(?:curl|wget|nc\b|netcat|python|ruby)",
            re.IGNORECASE,
        ),
        # Python os.environ full dump
        re.compile(
            r"(?:print|json\.dumps|str)\s*\(\s*(?:os\.environ|dict\(os\.environ\))",
            re.IGNORECASE,
        ),
        # Node.js process.env full dump
        re.compile(
            r"(?:console\.log|JSON\.stringify)\s*\(\s*process\.env\s*\)",
            re.IGNORECASE,
        ),
        # Sending env vars via curl
        re.compile(
            r"curl\s+.*(?:\$\(env\)|\$\(printenv\)|os\.environ|process\.env)",
            re.IGNORECASE,
        ),
        # Specifically reading sensitive env vars
        re.compile(
            r"(?:echo|print|printf|cat)\s+.*\$\{?"
            r"(?:AWS_SECRET|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
            r"DATABASE_URL|DB_PASSWORD|SECRET_KEY|PRIVATE_KEY|"
            r"STRIPE_SECRET|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN)",
            re.IGNORECASE,
        ),
        # Grep-ing env for secrets
        re.compile(
            r"(?:env|printenv)\s*\|\s*grep\s+.*(?:key|token|secret|password|credential)",
            re.IGNORECASE,
        ),
        # Compenv (reading the full env into a variable or file)
        re.compile(
            r"(?:env|printenv)\s*>\s*\S+",
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
                        description="Environment variable harvesting or exfiltration detected",
                        severity=self.severity,
                        confidence=0.86,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Pattern: environment variable harvesting"],
                    ))
                    break  # One finding per line
        return findings
