"""URL canonicalization and registrable-domain extraction (offline).

``tldextract`` is configured with an empty ``suffix_list_urls`` so it uses only
its packaged Public Suffix List snapshot and never touches the network — a
local-first requirement (spec P1).
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit

import tldextract

# Offline extractor: no network fetch, no on-disk cache writes.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Query parameters that are pure tracking noise; dropped during canonicalization.
_TRACKING_PREFIXES = ("utm_",)
_TRACKING_KEYS = frozenset(
    {"fbclid", "gclid", "gclsrc", "dclid", "msclkid", "mc_eid", "igshid", "ref", "ref_src"}
)


def registrable_domain(url_or_host: str) -> str:
    """Return the eTLD+1 (e.g. ``bbc.co.uk``), or the full host if unknown.

    When the suffix list does not recognise the TLD (private, internal, or
    reserved TLDs such as ``.example`` and ``.local``), fall back to the whole
    hostname. Falling back to a single label would collapse unrelated hosts —
    ``a.example`` and ``b.example`` would both become ``example`` — which would
    group distinct sites together in matching and route selection.
    """
    host = url_or_host
    if "://" in url_or_host:
        host = urlsplit(url_or_host).hostname or ""
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return ""
    ext = _extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host


def _clean_query(query: str) -> str:
    if not query:
        return ""
    kept: list[str] = []
    for pair in query.split("&"):
        if not pair:
            continue
        key = pair.split("=", 1)[0].lower()
        if key in _TRACKING_KEYS or any(key.startswith(p) for p in _TRACKING_PREFIXES):
            continue
        kept.append(pair)
    return "&".join(kept)


def canonical_url(url: str) -> str:
    """Return a stable canonical form used for deduplication.

    Lowercases scheme/host, drops the fragment, removes default ports and
    tracking parameters, and normalizes an empty path to ``/``.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    netloc = host
    if parts.port and not (
        (scheme == "http" and parts.port == 80) or (scheme == "https" and parts.port == 443)
    ):
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return urlunsplit((scheme, netloc, path, _clean_query(parts.query), ""))


def resolve_redirect(base_url: str, location: str) -> str:
    """Resolve a (possibly relative) redirect target against ``base_url``."""
    return urljoin(base_url, location)
