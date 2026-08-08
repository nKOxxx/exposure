"""Verification: observe the current state, never assume it (spec section 19).

Two independent checks:

* **source verification** re-retrieves the original URL and compares it to what
  we recorded;
* **search verification** re-runs the query and reports only what is observed.

Wording is deliberately cautious: not finding something in one query is
"not observed in the tested search", never "removed from Google".
"""

from __future__ import annotations

from exposure.domain.enums import SearchStatus, SourceStatus, VerificationStatus
from exposure.domain.models import Source, Subject, Verification
from exposure.extraction import extract_document
from exposure.retrieval.client import RetrievalError, SecureRetriever


def verify_source(
    retriever: SecureRetriever,
    source: Source,
    target_values: list[str],
    subject: Subject | None = None,
) -> Verification:
    """Re-fetch ``source`` and classify how it changed relative to ``target_values``.

    ``target_values`` are the normalized observation values whose disappearance
    would mean the personal data was removed.
    """
    try:
        doc = retriever.fetch(source.url)
    except RetrievalError as exc:
        if exc.status == SourceStatus.RETRIEVAL_BLOCKED:
            return Verification(source_status=VerificationStatus.ACCESS_BLOCKED, note=exc.reason)
        if exc.status == SourceStatus.TIMEOUT:
            return Verification(source_status=VerificationStatus.UNKNOWN, note="timeout")
        return Verification(source_status=VerificationStatus.UNKNOWN, note=exc.reason)

    if doc.status_code in (404, 410):
        return Verification(
            source_status=VerificationStatus.URL_GONE,
            new_content_hash=doc.content_hash,
            note=f"http_{doc.status_code}",
        )

    result = extract_document(doc.content_type, doc.body, subject)
    present_values = {item.value_normalized for item in result.items}
    still_present = [v for v in target_values if v in present_values]

    if not result.items and not doc.body.strip():
        status = VerificationStatus.CONTENT_REMOVED
    elif target_values and not still_present:
        status = VerificationStatus.PERSONAL_DATA_REMOVED
    elif doc.content_hash == source.content_hash:
        status = VerificationStatus.UNCHANGED
    else:
        status = VerificationStatus.CONTENT_CHANGED

    return Verification(source_status=status, new_content_hash=doc.content_hash)


def verify_search(
    provider: object, query: str, source_url: str, limit: int = 10
) -> tuple[SearchStatus, Verification]:
    """Re-run ``query`` and report whether ``source_url`` is observed."""
    from exposure.discovery.provider import SearchQuery
    from exposure.retrieval.canonicalize import canonical_url

    target = canonical_url(source_url)
    try:
        candidates = provider.search(SearchQuery(text=query), limit)  # type: ignore[attr-defined]
    except Exception as exc:  # provider failure must not read as "removed"
        return (
            SearchStatus.SEARCH_RESULT_PRESENT,
            Verification(
                source_status=VerificationStatus.UNKNOWN,
                query_used=query,
                provider=getattr(provider, "id", "unknown"),
                note=f"search_failed:{type(exc).__name__}",
            ),
        )

    observed = any(canonical_url(c.url) == target for c in candidates)
    status = (
        SearchStatus.SEARCH_RESULT_PRESENT if observed else SearchStatus.SEARCH_RESULT_NOT_OBSERVED
    )
    note = (
        "observed in the tested search"
        if observed
        else "not observed in the tested search (does not prove universal delisting)"
    )
    return status, Verification(
        source_status=VerificationStatus.UNKNOWN,
        query_used=query,
        provider=getattr(provider, "id", "unknown"),
        note=note,
    )
