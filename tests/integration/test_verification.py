"""Source verification outcomes (spec section 19)."""

from __future__ import annotations

import httpx

from exposure.config import Settings
from exposure.domain.enums import SourceStatus, VerificationStatus
from exposure.domain.models import Source
from exposure.remediation.verification import verify_search, verify_source
from exposure.retrieval.client import SecureRetriever

_HTML_WITH = "<html><body><p>jane@example.com</p></body></html>"
_HTML_WITHOUT = "<html><body><p>nothing personal here now</p></body></html>"


def _retriever(settings: Settings, handler) -> SecureRetriever:
    return SecureRetriever(settings, transport=httpx.MockTransport(handler))


def _source(content_hash: str = "old") -> Source:
    return Source(
        url="https://example.com/p", canonical_url="https://example.com/p",
        registrable_domain="example.com", content_hash=content_hash,
        status=SourceStatus.RETRIEVED,
    )


def test_url_gone(settings: Settings) -> None:
    r = _retriever(settings, lambda req: httpx.Response(404))
    v = verify_source(r, _source(), ["jane@example.com"])
    assert v.source_status == VerificationStatus.URL_GONE
    r.close()


def test_personal_data_removed(settings: Settings) -> None:
    r = _retriever(settings, lambda req: httpx.Response(
        200, headers={"content-type": "text/html"}, text=_HTML_WITHOUT))
    v = verify_source(r, _source(), ["jane@example.com"])
    assert v.source_status == VerificationStatus.PERSONAL_DATA_REMOVED
    r.close()


def test_unchanged_when_hash_matches(settings: Settings) -> None:
    import hashlib

    body = _HTML_WITH.encode()
    h = hashlib.sha256(body).hexdigest()
    r = _retriever(settings, lambda req: httpx.Response(
        200, headers={"content-type": "text/html"}, text=_HTML_WITH))
    v = verify_source(r, _source(content_hash=h), ["jane@example.com"])
    assert v.source_status == VerificationStatus.UNCHANGED
    r.close()


def test_access_blocked(settings: Settings) -> None:
    # Redirect to a private address -> blocked -> ACCESS_BLOCKED, not "removed".
    r = _retriever(settings, lambda req: httpx.Response(
        302, headers={"location": "http://10.0.0.1/"}))
    v = verify_source(r, _source(), ["jane@example.com"])
    assert v.source_status == VerificationStatus.ACCESS_BLOCKED
    r.close()


def test_search_verification_wording() -> None:
    class _Provider:
        id = "stub"

        def search(self, query, limit):
            from exposure.discovery.provider import SearchCandidate

            return [SearchCandidate(url="https://other.example/x")]

    from exposure.domain.enums import SearchStatus

    status, v = verify_search(_Provider(), '"Jane Example"', "https://example.com/p")
    assert status == SearchStatus.SEARCH_RESULT_NOT_OBSERVED
    assert "does not prove universal delisting" in v.note
