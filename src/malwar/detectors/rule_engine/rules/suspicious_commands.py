"""Suspicious command detection rules."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent

# Dedicated installer hosts whose *entire domain* is controlled by the project
# and only serves that project's official install script. `curl <host> | sh`
# from one of these is the vendor-documented install path, not malware, so it
# must not become a CRITICAL detection on its own.
#
# Deliberately excludes multi-tenant hosts (raw.githubusercontent.com,
# gist.github.com, gitlab.com, s3, cdn buckets): they serve arbitrary
# user-uploaded content, so `curl | sh` from them genuinely warrants a closer
# look. Those stay flagged and are resolved by second-opinion escalation
# rather than a blanket allowlist that an attacker could hide behind.
INSTALLER_HOST_ALLOWLIST: frozenset[str] = frozenset({
    "sh.rustup.rs",
    "rustup.rs",
    "get.docker.com",
    "get.helm.sh",
    "install.python-poetry.org",
    "deno.land",
    "bun.sh",
    "starship.rs",
    "get.pnpm.io",
    "sdk.cloud.google.com",
    "cli.github.com",
    "fnm.vercel.app",
    "get.volta.sh",
    "astral.sh",
    "get.rvm.io",
})

# Extracts http(s) URLs from a shell line so the download host can be checked
# against the installer allowlist.
_URL_RE = re.compile(r"https?://[^\s'\"|)>]+", re.IGNORECASE)


def _host_is_allowlisted(host: str) -> bool:
    """True when host equals or is a subdomain of an allowlisted installer domain."""
    host = host.lower()
    return any(
        host == allowed or host.endswith("." + allowed)
        for allowed in INSTALLER_HOST_ALLOWLIST
    )


def _all_download_hosts_allowlisted(line: str) -> bool:
    """True when the line has at least one URL and *every* URL is an allowlisted host.

    A single non-allowlisted URL (e.g. a second, malicious ``curl``) keeps the
    line flagged. A line whose download target is a shell variable yields no
    URL, so it is not allowlisted — we cannot vouch for a host we cannot see.
    """
    urls = _URL_RE.findall(line)
    if not urls:
        return False
    return all(_host_is_allowlisted(urlparse(u).hostname or "") for u in urls)


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
        re.compile(r"""(?:bash|sh|eval)\s+.*\$\(\s*curl\s+""", re.IGNORECASE),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    # Vendor-official installer host (whole domain controlled by
                    # the project) — the documented install path, not malware.
                    if _all_download_hosts_allowlisted(line):
                        break
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


@rule
class DownloadAndExecute(BaseRule):
    rule_id = "MALWAR-CMD-004"
    title = "Download-and-execute pattern"
    severity = Severity.HIGH
    category = ThreatCategory.SUSPICIOUS_COMMAND
    description = "Detects downloading a script/binary then executing it in subsequent steps"

    DOWNLOAD_PATTERNS = [
        re.compile(
            r"""(?:wget|curl\s+-[^\n]*-o)\s+\S*?(?:\.py|\.sh|\.ps1|\.exe|\.bin|helper)\b""",
            re.IGNORECASE,
        ),
    ]
    EXECUTE_PATTERNS = [
        re.compile(
            r"""(?:python3?|bash|sh|chmod\s+\+x)\s+\S*?(?:\.py|\.sh|helper)\b""",
            re.IGNORECASE,
        ),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings = []
        has_download = False
        download_line = 0

        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            for pattern in self.DOWNLOAD_PATTERNS:
                if pattern.search(line):
                    has_download = True
                    download_line = line_num
                    break

        if has_download:
            for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
                if line_num <= download_line:
                    continue
                for pattern in self.EXECUTE_PATTERNS:
                    if pattern.search(line):
                        findings.append(Finding(
                            id=f"{self.rule_id}-L{download_line}",
                            rule_id=self.rule_id,
                            title=self.title,
                            description="Downloads a script then executes it in a later step",
                            severity=self.severity,
                            confidence=0.78,
                            category=self.category,
                            detector_layer=DetectorLayer.RULE_ENGINE,
                            location=Location(
                                line_start=download_line,
                                snippet=f"Download at L{download_line}, execute at L{line_num}",
                            ),
                            evidence=["Multi-step download-and-execute pattern detected"],
                        ))
                        return findings
        return findings
