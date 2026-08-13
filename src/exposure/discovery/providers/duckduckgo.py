"""DuckDuckGo discovery provider — keyless, zero-setup default.

Uses the maintained ``ddgs`` library, which performs the token-and-JSON dance
DuckDuckGo's web UI uses. This is the only path that returns *general* web
results with **no API key and nothing for the user to run** — which is what the
product needs so that "search for me" works out of the box.

Honest caveat, reflected in the errors below: this is unofficial and scraping
based. DuckDuckGo rate-limits aggressively, so a scan may come back empty with a
``duckduckgo_rate_limited`` provider error. That is surfaced as an *incomplete*
scan (never as "no findings"), and the user can retry, wait, or configure Brave /
SearXNG for reliability. Result URLs are still fetched through the SSRF-guarded
retriever like any other candidate.
"""

from __future__ import annotations

import time
from typing import Any

from exposure.discovery.provider import ProviderError, SearchCandidate, SearchQuery


class DuckDuckGoProvider:
    id = "duckduckgo"

    #: Seconds to wait between queries in a scan. Firing a scan's worth of
    #: queries back-to-back reliably trips DuckDuckGo's rate limiter — observed
    #: in real use, where a second scan failed on all 8 queries. The scanner
    #: honours this pause; keyed APIs leave it at 0.
    polite_delay = 2.0

    def __init__(self, timeout: int = 15, retries: int = 3) -> None:
        self._timeout = timeout
        self._retries = retries

    def search(self, query: SearchQuery, limit: int) -> list[SearchCandidate]:
        try:
            from ddgs import DDGS
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise ProviderError("duckduckgo_library_missing") from exc

        rows: list[dict[str, Any]] = []
        last_exc: Exception | None = None
        for attempt in range(self._retries):
            try:
                with DDGS(timeout=self._timeout) as ddgs:
                    rows = list(ddgs.text(query.text, max_results=max(1, min(limit, 25))))
                last_exc = None
                break
            except Exception as exc:  # noqa: BLE001 - classified below
                last_exc = exc
                if attempt < self._retries - 1:
                    # Exponential backoff: rate limiting is usually short-lived.
                    time.sleep(2.0 * (2**attempt))

        if last_exc is not None:
            err = last_exc
            name = type(err).__name__.lower()
            text = str(err).lower()
            # ddgs wraps most upstream refusals (including rate limiting) in a
            # generic DDGSException, so treat that family as rate limiting —
            # that is overwhelmingly what it means in practice, and it gives the
            # user an action ("wait and retry") instead of an opaque code.
            if (
                "ratelimit" in name
                or "ddgsexception" in name
                or "429" in text
                or "202" in text
                or "rate" in text
            ):
                raise ProviderError("duckduckgo_rate_limited") from err
            if "timeout" in name:
                raise ProviderError("duckduckgo_timeout") from err
            raise ProviderError(f"duckduckgo_failed:{type(err).__name__}") from err

        candidates: list[SearchCandidate] = []
        for row in rows[:limit]:
            url = row.get("href") or row.get("url") or ""
            if not url:
                continue
            candidates.append(
                SearchCandidate(
                    url=url,
                    title=row.get("title", "") or "",
                    snippet=row.get("body") or row.get("content") or "",
                    provider=self.id,
                    query=query.text,
                )
            )
        return candidates
