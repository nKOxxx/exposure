"""Brave Search provider.

Brave offers a general Search API (verified 2026-08-08). The API key is read
from the secret store, never persisted in the database or logged. A provider
failure raises ``ProviderError`` so the scan can report "incomplete" rather than
silently showing zero findings (spec section 35).
"""

from __future__ import annotations

import httpx

from exposure.discovery.provider import ProviderError, SearchCandidate, SearchQuery

_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"


class BraveSearchProvider:
    id = "brave"

    def __init__(self, api_key: str, timeout: float = 10.0) -> None:
        if not api_key:
            raise ProviderError("brave_api_key_missing")
        self._api_key = api_key
        self._timeout = timeout

    def search(self, query: SearchQuery, limit: int) -> list[SearchCandidate]:
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": self._api_key,
        }
        params: dict[str, str | int] = {"q": query.text, "count": max(1, min(limit, 20))}
        try:
            with httpx.Client(timeout=self._timeout, trust_env=False) as client:
                resp = client.get(_ENDPOINT, headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise ProviderError(f"brave_request_failed:{type(exc).__name__}") from exc

        if resp.status_code == 401:
            raise ProviderError("brave_unauthorized")
        if resp.status_code == 429:
            raise ProviderError("brave_rate_limited")
        if resp.status_code >= 400:
            raise ProviderError(f"brave_http_{resp.status_code}")

        try:
            data = resp.json()
        except ValueError as exc:
            raise ProviderError("brave_bad_json") from exc

        results = (data.get("web") or {}).get("results") or []
        candidates: list[SearchCandidate] = []
        for item in results[:limit]:
            url = item.get("url")
            if not url:
                continue
            candidates.append(
                SearchCandidate(
                    url=url,
                    title=item.get("title", ""),
                    snippet=item.get("description", ""),
                    provider=self.id,
                    query=query.text,
                )
            )
        return candidates
