"""robots.txt compliance for the retriever.

Exposure asks a site's own rules before fetching. This is the opposite posture
to the scraping frameworks it is often compared with: several of those default
to TLS-fingerprint impersonation, forged referers and CAPTCHA solving. A tool
whose purpose is to *reduce* the amount of unwanted automated access to people's
data should not be built on evasion.

The trade-off is real and handled explicitly rather than silently: when robots
disallows a page, Exposure records ``RETRIEVAL_BLOCKED`` with a reason instead
of skipping it. The page still appears in the results with its link, so the
person can open it in their own browser — which robots.txt has never governed.

Uses protego (BSD-3-Clause), the same parser Scrapy uses.
"""

from __future__ import annotations

import threading
from urllib.parse import urlsplit, urlunsplit

import httpx

_ROBOTS_TIMEOUT = 5.0
_MAX_ROBOTS_BYTES = 512 * 1024


class RobotsPolicy:
    """Caches and evaluates robots.txt per origin.

    A missing, unreachable or malformed robots.txt means *allowed* — the
    conventional interpretation, and the one that avoids turning an unrelated
    network failure into a wall of blocked pages.
    """

    def __init__(self, user_agent: str, enabled: bool = True) -> None:
        self._user_agent = user_agent
        self._enabled = enabled
        self._cache: dict[str, object | None] = {}
        self._lock = threading.Lock()

    def _robots_url(self, url: str) -> tuple[str, str]:
        parts = urlsplit(url)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        return origin, urlunsplit((parts.scheme, parts.netloc, "/robots.txt", "", ""))

    def _load(self, robots_url: str) -> object | None:
        try:
            from protego import Protego
        except ImportError:  # pragma: no cover - optional dependency
            return None
        try:
            with httpx.Client(timeout=_ROBOTS_TIMEOUT, trust_env=False) as client:
                resp = client.get(robots_url, headers={"User-Agent": self._user_agent})
        except httpx.HTTPError:
            return None
        if resp.status_code >= 400:
            return None
        body = resp.content[:_MAX_ROBOTS_BYTES]
        try:
            return Protego.parse(body.decode("utf-8", errors="replace"))
        except Exception:
            return None

    def allows(self, url: str) -> bool:
        """True if this URL may be fetched. Fails open on any robots error."""
        if not self._enabled:
            return True
        origin, robots_url = self._robots_url(url)
        with self._lock:
            if origin not in self._cache:
                self._cache[origin] = self._load(robots_url)
            parser = self._cache[origin]
        if parser is None:
            return True
        try:
            return bool(parser.can_fetch(url, self._user_agent))  # type: ignore[attr-defined]
        except Exception:
            return True
