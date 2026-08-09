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

from exposure.discovery.provider import ProviderError, SearchCandidate, SearchQuery


class DuckDuckGoProvider:
    id = "duckduckgo"

    def __init__(self, timeout: int = 15) -> None:
        self._timeout = timeout

    def search(self, query: SearchQuery, limit: int) -> list[SearchCandidate]:
        try:
            from ddgs import DDGS
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise ProviderError("duckduckgo_library_missing") from exc

        try:
            with DDGS(timeout=self._timeout) as ddgs:
                rows = list(ddgs.text(query.text, max_results=max(1, min(limit, 25))))
        except Exception as exc:
            # ddgs raises library-specific exceptions; classify by name so we do
            # not hard-depend on its exception classes.
            name = type(exc).__name__.lower()
            if "ratelimit" in name or "429" in str(exc):
                raise ProviderError("duckduckgo_rate_limited") from exc
            if "timeout" in name:
                raise ProviderError("duckduckgo_timeout") from exc
            raise ProviderError(f"duckduckgo_failed:{type(exc).__name__}") from exc

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
