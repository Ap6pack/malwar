# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Persistence mechanism detection rules."""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class PersistenceMechanism(BaseRule):
    rule_id = "MALWAR-PERSIST-001"
    title = "Persistence mechanism"
    severity = Severity.CRITICAL
    category = ThreatCategory.SUSPICIOUS_COMMAND
    description = (
        "Detects instructions to install persistence via crontab, "
        "shell profiles, systemd services, launchd plists, or startup files"
    )

    PATTERNS = [
        # crontab manipulation
        re.compile(
            r"(?:crontab\s+-[elr]|crontab\s+<<|"
            r"\(crontab\s+-l\s*[;|]|echo\s+.*>>\s*/(?:etc/)?cron)",
            re.IGNORECASE,
        ),
        # Shell profile modification (writing to, not reading)
        re.compile(
            r"(?:>>|>\s*~?/?\s*(?:~|\$HOME)?/?)\.(?:bashrc|bash_profile|zshrc|zprofile|profile|zshenv)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:echo|printf|cat|tee)\s+.*(?:>>|>)\s*.*\.(?:bashrc|bash_profile|zshrc|zprofile|profile|zshenv)",
            re.IGNORECASE,
        ),
        # systemd service creation
        re.compile(
            r"(?:systemctl\s+(?:enable|start|daemon-reload)|"
            r"(?:>>|>)\s*/etc/systemd/|"
            r"cp\s+.*\.service\s+/etc/systemd/)",
            re.IGNORECASE,
        ),
        # launchd plist creation
        re.compile(
            r"(?:launchctl\s+(?:load|bootstrap)|"
            r"(?:>>|>)\s*.*LaunchAgents?/|"
            r"(?:>>|>)\s*.*LaunchDaemons?/|"
            r"cp\s+.*\.plist\s+.*(?:LaunchAgents?|LaunchDaemons?))",
            re.IGNORECASE,
        ),
        # Windows startup / registry persistence
        re.compile(
            r"(?:HKCU|HKLM)\\.*\\(?:Run|RunOnce)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:>>|>)\s*.*(?:Start\s*Menu|Startup).*\.(?:bat|cmd|vbs|ps1|exe)",
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
                        description="Persistence mechanism installation detected",
                        severity=self.severity,
                        confidence=0.87,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Pattern: persistence mechanism"],
                    ))
                    break  # One finding per line
        return findings


@rule
class FileSystemModification(BaseRule):
    rule_id = "MALWAR-PERSIST-002"
    title = "File system modification"
    severity = Severity.HIGH
    category = ThreatCategory.SUSPICIOUS_COMMAND
    description = (
        "Detects instructions to modify skill files, agent config, "
        "or write to system directories"
    )

    PATTERNS = [
        # Writing/copying to system directories (with possible args between command and path)
        re.compile(
            r"(?:cp|mv)\s+\S+\s+/(?:etc|usr/local/bin|usr/local/sbin|usr/bin|usr/sbin|opt)/",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:tee|>>|>\s*)\s*/(?:etc|usr/local/bin|usr/local/sbin|usr/bin|usr/sbin|opt)/",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:echo|printf|cat)\s+.*(?:>>|>)\s*/(?:etc|usr/local/bin|usr/local/sbin|usr/bin|usr/sbin|opt)/",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:install|mkdir\s+-p)\s+/(?:etc|usr/local/bin|usr/local/sbin)/",
            re.IGNORECASE,
        ),
        # Modifying agent config / skill files
        re.compile(
            r"(?:echo|printf|cat|tee|sed|>>|>).*(?:SKILL\.md|CLAUDE\.md|\.claude/|\.cursor/)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:cp|mv|rm)\s+.*(?:SKILL\.md|CLAUDE\.md|\.claude/settings|\.cursor/)",
            re.IGNORECASE,
        ),
        # chmod on system binaries
        re.compile(
            r"chmod\s+.*\s+/(?:etc|usr|bin|sbin)/",
            re.IGNORECASE,
        ),
        # Writing to /tmp then moving to system paths
        re.compile(
            r"mv\s+/tmp/\S+\s+/(?:usr|bin|sbin|etc|opt)/",
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
                        description="File system modification to system paths or agent config detected",
                        severity=self.severity,
                        confidence=0.82,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=["Pattern: system/config file modification"],
                    ))
                    break  # One finding per line
        return findings
