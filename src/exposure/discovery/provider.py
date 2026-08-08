"""Discovery provider abstraction.

Providers must be replaceable because the commercial search-API landscape is
unstable: Microsoft retired the Bing Search APIs (Aug 2025), Google's Custom
Search JSON API is closed to new customers (existing customers must migrate by
Jan 1 2027), so Exposure must not depend structurally on any single provider
(spec section 7). Verified 2026-08-08.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(slots=True)
class SearchQuery:
    text: str
    sensitive: bool = False
    site: str | None = None


@dataclass(slots=True)
class SearchCandidate:
    url: str
    title: str = ""
    snippet: str = ""
    provider: str = ""
    query: str = ""


class ProviderError(Exception):
    """A discovery provider failed. Surfaced explicitly, never as zero results."""


@runtime_checkable
class DiscoveryProvider(Protocol):
    id: str

    def search(self, query: SearchQuery, limit: int) -> list[SearchCandidate]:
        ...


@dataclass(slots=True)
class PlannedQuery:
    text: str
    sensitive: bool = False
    rationale: str = ""
    site: str | None = None
    filetype: str | None = None

    def as_query(self) -> SearchQuery:
        text = self.text
        if self.filetype:
            text = f"{text} filetype:{self.filetype}"
        return SearchQuery(text=text, sensitive=self.sensitive, site=self.site)


@dataclass(slots=True)
class DiscoveryPlan:
    queries: list[PlannedQuery] = field(default_factory=list)

    @property
    def sensitive_count(self) -> int:
        return sum(1 for q in self.queries if q.sensitive)
