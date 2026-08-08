"""SearXNG discovery provider — metasearch, no API key required.

SearXNG is self-hostable metasearch software. It is the keyless path for users
who do not want to pay for a commercial search API (spec section 7 lists it as an
optional/community provider).

**No default instance is shipped.** Pointing this at an arbitrary public instance
would silently hand the user's name to a server run by a stranger, which is the
opposite of what Exposure is for. The user must supply the base URL, and the UI
recommends self-hosting.

Note on address policy: the base URL is allowed to be loopback or private,
unlike the URLs this application retrieves. That distinction is deliberate — the
SSRF boundary exists to stop *untrusted, discovered* URLs from reaching internal
services, whereas this endpoint is one the user typed in themselves and a
self-hosted SearXNG normally listens on ``127.0.0.1``. Result URLs coming back
from it are still fetched through the guarded retriever like anything else.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from exposure.discovery.provider import ProviderError, SearchCandidate, SearchQuery

_USER_AGENT = "Exposure/0.2 (personal exposure scan)"


def validate_instance_url(url: str) -> str:
    """Validate a user-supplied SearXNG base URL. Returns it normalized."""
    url = (url or "").strip().rstrip("/")
    if not url:
        raise ProviderError("searxng_url_missing")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ProviderError("searxng_url_bad_scheme")
    if not parts.hostname:
        raise ProviderError("searxng_url_missing_host")
    return url


class SearXNGProvider:
    id = "searxng"

    def __init__(self, base_url: str, timeout: float = 15.0) -> None:
        self._base_url = validate_instance_url(base_url)
        self._timeout = timeout

    def search(self, query: SearchQuery, limit: int) -> list[SearchCandidate]:
        params = {"q": query.text, "format": "json"}
        try:
            with httpx.Client(
                timeout=self._timeout,
                trust_env=False,
                follow_redirects=True,
                headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
            ) as client:
                resp = client.get(f"{self._base_url}/search", params=params)
        except httpx.HTTPError as exc:
            raise ProviderError(f"searxng_request_failed:{type(exc).__name__}") from exc

        if resp.status_code in (403, 429):
            # Most public instances rate-limit or disable the JSON API outright.
            raise ProviderError("searxng_json_api_blocked")
        if resp.status_code >= 400:
            raise ProviderError(f"searxng_http_{resp.status_code}")

        try:
            data = resp.json()
        except ValueError as exc:
            # A instance with the JSON format disabled returns an HTML page here.
            raise ProviderError("searxng_json_api_disabled") from exc

        results = data.get("results") or []
        candidates: list[SearchCandidate] = []
        for item in results[:limit]:
            url = item.get("url")
            if not url:
                continue
            candidates.append(
                SearchCandidate(
                    url=url,
                    title=item.get("title", "") or "",
                    snippet=item.get("content", "") or "",
                    provider=self.id,
                    query=query.text,
                )
            )
        return candidates
