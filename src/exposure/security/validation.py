"""Deterministic validation predicates shared across subsystems.

The IP-range and URL-scheme rules live here (not in the retriever) so that the
same policy can be unit-tested in isolation and reused by the network backend,
the discovery layer, and the API. See spec section 8.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Schemes we explicitly reject with a clear error (spec section 8).
REJECTED_SCHEMES = frozenset(
    {"file", "ftp", "gopher", "data", "javascript", "blob", "ws", "wss", "mailto", "tel"}
)

# Cloud metadata endpoints that must never be reachable.
_METADATA_HOSTS = frozenset(
    {"169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254"}
)


class UrlPolicyError(ValueError):
    """Raised when a URL violates the retrieval policy."""


def is_blocked_address(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if ``ip`` is in any range we must never connect to.

    Blocks loopback, private, link-local, multicast, reserved, unspecified, and
    IPv4-mapped/6to4 wrappers of those ranges, plus the cloud metadata IPs.
    """
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address = (
        ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    )

    # Unwrap IPv6 representations of IPv4 so a mapped private address can't slip
    # through (e.g. ::ffff:169.254.169.254 or 2002:: 6to4).
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        elif addr.sixtofour is not None:
            addr = addr.sixtofour

    if str(addr) in _METADATA_HOSTS:
        return True

    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        # is_global is the positive counterpart; anything not global is suspect
        # except public addresses already covered above. Keep it explicit:
        or not addr.is_global
    )


def is_blocked_hostname(hostname: str) -> bool:
    """Block metadata hostnames and obvious loopback names by literal match."""
    h = hostname.strip().strip("[]").lower().rstrip(".")
    if h in _METADATA_HOSTS:
        return True
    return h in {"localhost", "localhost.localdomain"} or h.endswith(".localhost")


def validate_url_syntax(url: str) -> str:
    """Validate scheme/host of ``url`` and return a cleaned URL string.

    Does *not* resolve DNS — that happens atomically at connect time in the
    network backend to avoid a TOCTOU rebinding gap. Raises ``UrlPolicyError``.
    """
    url = (url or "").strip()
    if not url:
        raise UrlPolicyError("empty_url")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme in REJECTED_SCHEMES:
        raise UrlPolicyError(f"rejected_scheme:{scheme}")
    if scheme not in ALLOWED_SCHEMES:
        raise UrlPolicyError(f"unsupported_scheme:{scheme or 'none'}")
    if not parts.hostname:
        raise UrlPolicyError("missing_host")
    if is_blocked_hostname(parts.hostname):
        raise UrlPolicyError("blocked_hostname")
    # If the host is a literal IP, we can reject immediately.
    try:
        addr = ipaddress.ip_address(parts.hostname.strip("[]"))
    except ValueError:
        addr = None
    if addr is not None and is_blocked_address(addr):
        raise UrlPolicyError("blocked_ip_literal")
    return url


def registrable_domain(url_or_host: str) -> str:
    """Return the registrable domain (eTLD+1) using an offline suffix list."""
    from exposure.retrieval.canonicalize import registrable_domain as _rd

    return _rd(url_or_host)
