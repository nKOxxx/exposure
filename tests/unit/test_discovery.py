"""Discovery: Brave provider, manual provider, and the query planner."""

from __future__ import annotations

import httpx
import pytest

from exposure.config import Settings
from exposure.discovery import ProviderError, SearchQuery, plan_queries
from exposure.discovery.providers import BraveSearchProvider, ManualURLProvider
from exposure.domain.models import (
    LocationHint,
    Name,
    OrganisationHint,
    SecretField,
    Subject,
)
from exposure.security.redaction import mask_email, mask_phone


def _client_factory(handler):  # type: ignore[no-untyped-def]
    """Patch httpx.Client so the provider talks to a MockTransport."""
    real_client = httpx.Client

    def factory(*args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    return factory


# --------------------------------------------------------------------------- #
# Brave provider
# --------------------------------------------------------------------------- #


def test_brave_requires_api_key() -> None:
    with pytest.raises(ProviderError, match="brave_api_key_missing"):
        BraveSearchProvider("")


def test_brave_parses_results(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["token"] = request.headers.get("x-subscription-token")
        return httpx.Response(200, json={"web": {"results": [
            {"url": "https://a.example/1", "title": "A", "description": "first"},
            {"url": "https://b.example/2", "title": "B", "description": "second"},
            {"title": "no url — skipped"},
        ]}})

    monkeypatch.setattr(httpx, "Client", _client_factory(handler))
    provider = BraveSearchProvider("sk-test")
    results = provider.search(SearchQuery(text='"Jane Example"'), 10)

    assert [r.url for r in results] == ["https://a.example/1", "https://b.example/2"]
    assert results[0].title == "A" and results[0].snippet == "first"
    assert results[0].provider == "brave"
    assert seen["token"] == "sk-test"
    assert "Jane+Example" in str(seen["url"]) or "Jane%20Example" in str(seen["url"])


def test_brave_respects_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"web": {"results": [
            {"url": f"https://x.example/{i}"} for i in range(10)
        ]}})

    monkeypatch.setattr(httpx, "Client", _client_factory(handler))
    assert len(BraveSearchProvider("k").search(SearchQuery(text="q"), 3)) == 3


@pytest.mark.parametrize(
    "status,expected",
    [(401, "brave_unauthorized"), (429, "brave_rate_limited"), (500, "brave_http_500")],
)
def test_brave_http_errors(
    monkeypatch: pytest.MonkeyPatch, status: int, expected: str
) -> None:
    monkeypatch.setattr(
        httpx, "Client", _client_factory(lambda r: httpx.Response(status))
    )
    with pytest.raises(ProviderError, match=expected):
        BraveSearchProvider("k").search(SearchQuery(text="q"), 5)


def test_brave_bad_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx,
        "Client",
        _client_factory(lambda r: httpx.Response(200, content=b"not json")),
    )
    with pytest.raises(ProviderError, match="brave_bad_json"):
        BraveSearchProvider("k").search(SearchQuery(text="q"), 5)


def test_brave_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(httpx, "Client", _client_factory(handler))
    with pytest.raises(ProviderError, match="brave_request_failed"):
        BraveSearchProvider("k").search(SearchQuery(text="q"), 5)


def test_brave_empty_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx, "Client", _client_factory(lambda r: httpx.Response(200, json={}))
    )
    assert BraveSearchProvider("k").search(SearchQuery(text="q"), 5) == []


# --------------------------------------------------------------------------- #
# Manual provider
# --------------------------------------------------------------------------- #


def test_manual_provider_passes_unsafe_urls_through() -> None:
    """Unsafe URLs must reach the retriever so it can record RETRIEVAL_BLOCKED."""
    provider = ManualURLProvider(
        ["https://ok.example/a", "  ", "http://169.254.169.254/", ""]
    )
    urls = [c.url for c in provider.all_candidates()]
    assert urls == ["https://ok.example/a", "http://169.254.169.254/"]


def test_manual_provider_search_respects_limit() -> None:
    provider = ManualURLProvider([f"https://x.example/{i}" for i in range(5)])
    assert len(provider.search(SearchQuery(text="ignored"), 2)) == 2


# --------------------------------------------------------------------------- #
# Query planner
# --------------------------------------------------------------------------- #


def _subject() -> Subject:
    return Subject(
        names=[Name(value="Jane Example", is_primary=True)],
        locations=[LocationHint(city="London", country="UK")],
        employers=[OrganisationHint(name="Acme Corp")],
        usernames=["janeex"],
        personal_domains=["janeexample.com"],
        emails=[SecretField(value="jane@example.com", display=mask_email("jane@example.com"))],
        phones=[SecretField(value="+44 20 7946 0958", display=mask_phone("+44 20 7946 0958"))],
    )


def test_planner_covers_expected_shapes() -> None:
    plan = plan_queries(_subject(), Settings())
    texts = [q.as_query().text for q in plan.queries]
    assert '"Jane Example"' in texts
    assert '"Jane Example" London' in texts
    assert '"Jane Example" Acme Corp' in texts
    assert '"Jane Example" filetype:pdf' in texts
    assert '"janeex"' in texts
    assert "site:janeexample.com" in texts


def test_planner_flags_sensitive_queries() -> None:
    plan = plan_queries(_subject(), Settings())
    sensitive = [q for q in plan.queries if q.sensitive]
    assert plan.sensitive_count == len(sensitive) == 1
    assert {q.rationale for q in sensitive} == {"email"}


def test_planner_never_sends_a_phone_number() -> None:
    """Searching a phone number would disclose it to the provider."""
    subject = _subject()
    assert subject.phones, "fixture must have a phone to make this meaningful"
    texts = " ".join(q.as_query().text for q in plan_queries(subject, Settings()).queries)
    assert "7946" not in texts
    assert not any(q.rationale == "phone" for q in plan_queries(subject, Settings()).queries)


def test_planner_respects_budget() -> None:
    plan = plan_queries(_subject(), Settings(max_queries=3))
    assert len(plan.queries) == 3


def test_planner_handles_nameless_subject() -> None:
    plan = plan_queries(Subject(usernames=["solo"]), Settings())
    assert [q.as_query().text for q in plan.queries] == ['"solo"']


def test_planner_empty_subject_produces_nothing() -> None:
    assert plan_queries(Subject(), Settings()).queries == []
