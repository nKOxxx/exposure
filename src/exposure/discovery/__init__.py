"""Discovery: plan queries and produce candidate URLs (never truth)."""

from __future__ import annotations

from exposure.discovery.planner import plan_queries
from exposure.discovery.provider import (
    DiscoveryPlan,
    DiscoveryProvider,
    PlannedQuery,
    ProviderError,
    SearchCandidate,
    SearchQuery,
)

__all__ = [
    "plan_queries",
    "DiscoveryPlan",
    "DiscoveryProvider",
    "PlannedQuery",
    "ProviderError",
    "SearchCandidate",
    "SearchQuery",
]
