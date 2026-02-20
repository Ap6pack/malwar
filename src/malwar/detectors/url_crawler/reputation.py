# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Domain reputation scoring for URL threat assessment."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class DomainReputation:
    """Reputation assessment for a single domain."""

    domain: str
    score: float  # 0.0 (malicious) to 1.0 (trusted)
    reasons: list[str] = field(default_factory=list)


# Domains considered safe / well-known
SAFE_DOMAINS: set[str] = {
    "github.com",
    "docs.python.org",
    "pypi.org",
    "npmjs.com",
    "developer.mozilla.org",
    "stackoverflow.com",
    "wikipedia.org",
    "docs.anthropic.com",
    "openai.com",
    "google.com",
}

# Paste-bin sites (often used to host malicious payloads)
PASTE_SITES: set[str] = {
    "pastebin.com",
    "hastebin.com",
    "glot.io",
    "paste.ee",
    "dpaste.org",
    "ghostbin.com",
}

# Known-malicious domains and IPs from threat intelligence
KNOWN_MALICIOUS: set[str] = {
    "91.92.242.30",
    "download.setup-service.com",
    "openclawcli.vercel.app",
}

# Pattern to detect raw IP addresses (v4)
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _extract_domain(url: str) -> str:
    """Extract the hostname/domain from a URL string."""
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _is_ip_address(domain: str) -> bool:
    """Return True if *domain* is a bare IP address."""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _domain_matches(domain: str, known: set[str]) -> bool:
    """Check if *domain* matches any entry in *known* (exact or parent)."""
    if domain in known:
        return True
    # Also match subdomains: e.g. "raw.github.com" should match "github.com"
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in known:
            return True
    return False


def check_domain_reputation(url: str) -> DomainReputation:
    """Score a URL's domain reputation.

    Scoring rules (applied in priority order):
    - Known malicious domains/IPs: 0.0
    - Bare IP address URLs: 0.2
    - Paste-bin sites: 0.3
    - Known-safe domains: 1.0
    - Everything else (unknown): 0.5
    """
    domain = _extract_domain(url)
    if not domain:
        return DomainReputation(domain=domain, score=0.2, reasons=["Unparseable URL"])

    # 1. Known malicious (highest priority)
    if _domain_matches(domain, KNOWN_MALICIOUS):
        return DomainReputation(
            domain=domain,
            score=0.0,
            reasons=[f"Domain '{domain}' is in the known-malicious list"],
        )

    # 2. Bare IP address
    if _is_ip_address(domain):
        return DomainReputation(
            domain=domain,
            score=0.2,
            reasons=[f"URL uses raw IP address '{domain}' instead of a domain name"],
        )

    # 3. Paste site
    if _domain_matches(domain, PASTE_SITES):
        return DomainReputation(
            domain=domain,
            score=0.3,
            reasons=[f"Domain '{domain}' is a paste-bin site often used for payload hosting"],
        )

    # 4. Known safe
    if _domain_matches(domain, SAFE_DOMAINS):
        return DomainReputation(
            domain=domain,
            score=1.0,
            reasons=[f"Domain '{domain}' is a known-safe domain"],
        )

    # 5. Unknown
    return DomainReputation(
        domain=domain,
        score=0.5,
        reasons=[f"Domain '{domain}' is not in any reputation list"],
    )
