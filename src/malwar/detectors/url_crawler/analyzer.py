# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Analyze fetched URL content for malicious indicators."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.url_crawler.fetcher import FetchResult
from malwar.models.finding import Finding, Location

# Patterns indicating bash / shell scripts in response body
_SHELL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"#!/bin/(ba)?sh"),
    re.compile(r"\bcurl\b.*\|\s*(ba)?sh"),
    re.compile(r"\bwget\b.*\|\s*(ba)?sh"),
    re.compile(r"\bchmod\s+\+x\b"),
    re.compile(r"\beval\s*\$\("),
]

# Patterns indicating PowerShell scripts in response body
_POWERSHELL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"Invoke-Expression", re.IGNORECASE),
    re.compile(r"Invoke-WebRequest", re.IGNORECASE),
    re.compile(r"IEX\s*\(", re.IGNORECASE),
    re.compile(r"New-Object\s+System\.Net", re.IGNORECASE),
    re.compile(r"DownloadString\(", re.IGNORECASE),
    re.compile(r"\-enc(odedcommand)?\s+", re.IGNORECASE),
]

# Malware payload indicators in response body
_MALWARE_BODY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"base64\s*-d", re.IGNORECASE), "Base64 decode command"),
    (re.compile(r"/etc/passwd"), "Reads /etc/passwd"),
    (re.compile(r"~/.ssh/"), "Accesses SSH directory"),
    (re.compile(r"\bkeylogger\b", re.IGNORECASE), "Keylogger reference"),
    (re.compile(r"\breverse.?shell\b", re.IGNORECASE), "Reverse shell reference"),
    (re.compile(r"\bc2\s*server\b", re.IGNORECASE), "C2 server reference"),
    (re.compile(r"exfiltrat", re.IGNORECASE), "Data exfiltration reference"),
]

# Content types that indicate binary/archive delivery
_ARCHIVE_CONTENT_TYPES = frozenset(
    {
        "application/octet-stream",
        "application/zip",
        "application/x-tar",
        "application/gzip",
        "application/x-bzip2",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/x-executable",
        "application/x-mach-binary",
        "application/vnd.microsoft.portable-executable",
    }
)

_SCRIPT_CONTENT_TYPES = frozenset(
    {
        "application/javascript",
        "application/x-javascript",
        "text/javascript",
        "application/x-sh",
        "application/x-shellscript",
        "text/x-shellscript",
    }
)

_finding_counter: int = 0


def _next_finding_id(prefix: str) -> str:
    global _finding_counter
    _finding_counter += 1
    return f"MALWAR-URL-{prefix}-{_finding_counter:03d}"


def _domains_differ(urls: list[str]) -> bool:
    """Return True if the redirect chain traverses multiple different domains."""
    domains: set[str] = set()
    for u in urls:
        try:
            host = urlparse(u).hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass
    return len(domains) > 1


def analyze_fetch_result(result: FetchResult) -> list[Finding]:
    """Analyze a fetched URL for malicious indicators.

    Checks performed:
    1. Redirect chain through different domains
    2. Content-type mismatch (claims document, serves script)
    3. Serves bash / PowerShell script
    4. Serves archive / binary
    5. Contains malware patterns in response body
    """
    findings: list[Finding] = []

    # ------------------------------------------------------------------
    # 1. Suspicious redirect chain (crosses domain boundaries)
    # ------------------------------------------------------------------
    full_chain = result.redirect_chain + [result.final_url]
    if len(full_chain) > 1 and _domains_differ(full_chain):
        findings.append(
            Finding(
                id=_next_finding_id("RDR"),
                rule_id="url_redirect_chain",
                title="Cross-domain redirect chain",
                description=(
                    f"URL {result.url} redirects through multiple domains: "
                    f"{' -> '.join(full_chain)}"
                ),
                severity=Severity.MEDIUM,
                confidence=0.7,
                category=ThreatCategory.MALICIOUS_URL,
                detector_layer=DetectorLayer.URL_CRAWLER,
                evidence=[f"Redirect chain: {' -> '.join(full_chain)}"],
                ioc_values=[result.url, result.final_url],
                remediation="Verify the redirect chain is intentional and not used for cloaking.",
            )
        )

    # ------------------------------------------------------------------
    # 2. Content-type mismatch
    # ------------------------------------------------------------------
    ct = result.content_type.lower()
    if ct in _SCRIPT_CONTENT_TYPES and result.url.endswith(
        (".md", ".txt", ".html", ".doc", ".pdf")
    ):
        findings.append(
            Finding(
                id=_next_finding_id("CTM"),
                rule_id="url_content_type_mismatch",
                title="Content-type mismatch",
                description=(
                    f"URL {result.url} has extension suggesting a document but serves "
                    f"content-type '{ct}'"
                ),
                severity=Severity.HIGH,
                confidence=0.8,
                category=ThreatCategory.MALICIOUS_URL,
                detector_layer=DetectorLayer.URL_CRAWLER,
                evidence=[f"Content-Type: {ct}", f"URL: {result.url}"],
                ioc_values=[result.url],
                remediation="Investigate whether the URL is serving unexpected executable content.",
            )
        )

    # ------------------------------------------------------------------
    # 3. Serves bash / PowerShell scripts
    # ------------------------------------------------------------------
    body = result.content or ""
    for pattern in _SHELL_PATTERNS:
        if pattern.search(body):
            findings.append(
                Finding(
                    id=_next_finding_id("SH"),
                    rule_id="url_serves_shell_script",
                    title="URL serves shell script",
                    description=(
                        f"URL {result.url} response body contains shell script pattern: "
                        f"{pattern.pattern}"
                    ),
                    severity=Severity.HIGH,
                    confidence=0.85,
                    category=ThreatCategory.MALICIOUS_URL,
                    detector_layer=DetectorLayer.URL_CRAWLER,
                    evidence=[f"Pattern matched: {pattern.pattern}"],
                    ioc_values=[result.url],
                    remediation="Review the script content for malicious behavior before trusting this URL.",
                )
            )
            break  # one finding per category is enough

    for pattern in _POWERSHELL_PATTERNS:
        if pattern.search(body):
            findings.append(
                Finding(
                    id=_next_finding_id("PS"),
                    rule_id="url_serves_powershell_script",
                    title="URL serves PowerShell script",
                    description=(
                        f"URL {result.url} response body contains PowerShell pattern: "
                        f"{pattern.pattern}"
                    ),
                    severity=Severity.HIGH,
                    confidence=0.85,
                    category=ThreatCategory.MALICIOUS_URL,
                    detector_layer=DetectorLayer.URL_CRAWLER,
                    evidence=[f"Pattern matched: {pattern.pattern}"],
                    ioc_values=[result.url],
                    remediation="Review the PowerShell content for malicious behavior.",
                )
            )
            break

    # ------------------------------------------------------------------
    # 4. Serves archive / binary
    # ------------------------------------------------------------------
    if ct in _ARCHIVE_CONTENT_TYPES:
        findings.append(
            Finding(
                id=_next_finding_id("BIN"),
                rule_id="url_serves_binary",
                title="URL serves binary/archive content",
                description=(
                    f"URL {result.url} serves binary content (content-type: {ct})"
                ),
                severity=Severity.MEDIUM,
                confidence=0.75,
                category=ThreatCategory.MALICIOUS_URL,
                detector_layer=DetectorLayer.URL_CRAWLER,
                evidence=[f"Content-Type: {ct}"],
                ioc_values=[result.url],
                remediation="Binary content from URLs in skill files is highly suspicious. Investigate.",
            )
        )

    # ------------------------------------------------------------------
    # 5. Malware patterns in body
    # ------------------------------------------------------------------
    for pattern, label in _MALWARE_BODY_PATTERNS:
        if pattern.search(body):
            findings.append(
                Finding(
                    id=_next_finding_id("MAL"),
                    rule_id="url_malware_pattern",
                    title=f"Malware indicator in URL response: {label}",
                    description=(
                        f"URL {result.url} response body contains malware indicator: {label}"
                    ),
                    severity=Severity.HIGH,
                    confidence=0.8,
                    category=ThreatCategory.MALICIOUS_URL,
                    detector_layer=DetectorLayer.URL_CRAWLER,
                    evidence=[f"Indicator: {label}", f"Pattern: {pattern.pattern}"],
                    ioc_values=[result.url],
                    remediation="This URL may be hosting malicious content. Do not execute its contents.",
                )
            )

    return findings
