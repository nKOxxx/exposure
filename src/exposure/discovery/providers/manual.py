"""Manual URL provider.

Exposure remains useful without sending any personal identifier to a search API
(spec section 7). The user can run the generated queries themselves and import
the URLs they find; this provider simply returns those URLs as candidates.
"""

from __future__ import annotations

from exposure.discovery.provider import SearchCandidate, SearchQuery


class ManualURLProvider:
    id = "manual"

    def __init__(self, urls: list[str]) -> None:
        # Do NOT silently drop unsafe URLs here. Pass them through so the
        # retriever validates each one and records an explicit RETRIEVAL_BLOCKED
        # source the user can inspect (spec section 35: never convert failure
        # into silent absence).
        self._urls: list[str] = [u.strip() for u in urls if u and u.strip()]

    def search(self, query: SearchQuery, limit: int) -> list[SearchCandidate]:
        # Manual URLs are not query-specific; return them once.
        return [
            SearchCandidate(url=u, provider=self.id, query="(manual import)")
            for u in self._urls[:limit]
        ]

    def all_candidates(self) -> list[SearchCandidate]:
        return [SearchCandidate(url=u, provider=self.id, query="(manual import)") for u in self._urls]
