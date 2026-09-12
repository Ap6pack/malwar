"""Decide whether a URL is safe for the scanner itself to fetch.

The URL crawler exists to follow links found in skill content, and skill
content is hostile input by definition -- it is the thing being analysed. URLs
come from the body, from ``source_url`` and ``author_url``, and from arbitrary
frontmatter keys, so the destination is fully attacker-controlled.

Without a guard, scanning a skill containing::

    http://169.254.169.254/latest/meta-data/iam/security-credentials/

makes the scanner fetch cloud instance credentials, from CI or from whatever
machine a user ran it on. That is server-side request forgery reached through
the tool's normal, default-on code path (``use_urls=True``).

Three rules, and the third is the one that is easy to get wrong:

1. Only ``http`` and ``https``. Blocks ``file://``, ``gopher://`` and friends.
2. Resolve the hostname and reject if **any** returned address is private,
   loopback, link-local, reserved or otherwise not a public unicast address.
   Checking the literal string is not enough: an attacker controls DNS for
   their own domain, so ``evil.example`` with an A record of ``127.0.0.1``
   walks straight past a textual check.
3. Re-check every redirect hop. A URL that passes on the first request can
   redirect to metadata on the second, so validating only the initial target
   is equivalent to not validating at all.

Residual risk, stated rather than papered over: this resolves the name and
then hands the URL to httpx, which resolves it again to connect. A DNS entry
that changes between those two lookups (rebinding) defeats the check. Closing
that needs a transport that pins the validated address, which is a larger
change; it is tracked as a known limit, not silently ignored.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], list[IPAddress]]


def _address_is_public(ip: IPAddress) -> bool:
    """True only for ordinary routable unicast addresses.

    ``is_global`` alone is not sufficient on every Python version for every
    family, so the specific categories that matter for SSRF are also named.
    """
    if (
        ip.is_private            # 10/8, 172.16/12, 192.168/16, fc00::/7, ...
        or ip.is_loopback        # 127/8, ::1
        or ip.is_link_local      # 169.254/16 (cloud metadata), fe80::/10
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified     # 0.0.0.0, ::
    ):
        return False
    # IPv4-mapped and 6to4 addresses can smuggle a private v4 address inside a
    # v6 literal, so unwrap and re-check rather than trusting the outer form.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _address_is_public(mapped)
    sixtofour = getattr(ip, "sixtofour", None)
    if sixtofour is not None:
        return _address_is_public(sixtofour)
    return True


def resolve_host(host: str) -> list[IPAddress]:
    """Return every address ``host`` resolves to, or [] if it does not resolve.

    An IP literal resolves to itself without a DNS lookup.
    """
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return []
    out: list[IPAddress] = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return out


def check_url(url: str, resolver: Resolver = resolve_host) -> tuple[bool, str]:
    """Return ``(safe, reason)`` for one URL.

    ``reason`` is empty when safe and names the specific failure otherwise, so
    a blocked fetch is explainable rather than a silent drop.

    ``resolver`` is injectable so tests can exercise the address-classification
    logic against fixed answers. Making the whole check skippable instead would
    mean the tests that mock HTTP stop covering the guard entirely, which is
    how a control ends up passing its own suite while doing nothing.
    """
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return False, f"unparseable URL: {exc}"

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"scheme {parts.scheme!r} not allowed"

    host = parts.hostname
    if not host:
        return False, "no host in URL"

    addresses = resolver(host)
    if not addresses:
        # Unresolvable is not unsafe, but there is nothing to fetch and letting
        # it through would mean the connect-time resolution is the only one
        # that ever happens -- i.e. no check at all.
        return False, f"host {host!r} does not resolve"

    # Every address must be public. One private answer among several is enough
    # to reach an internal service, because which one gets connected to is not
    # ours to choose.
    for ip in addresses:
        if not _address_is_public(ip):
            return False, f"host {host!r} resolves to non-public address {ip}"

    return True, ""
