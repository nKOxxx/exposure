"""Retrieval boundary: canonicalization, SSRF network policy, limits, client."""

from __future__ import annotations

from exposure.retrieval.canonicalize import canonical_url, registrable_domain
from exposure.retrieval.client import RetrievalError, RetrievedDocument, SecureRetriever

__all__ = [
    "canonical_url",
    "registrable_domain",
    "RetrievalError",
    "RetrievedDocument",
    "SecureRetriever",
]
