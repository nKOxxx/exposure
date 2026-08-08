"""SearXNG provider: the keyless discovery path."""

from __future__ import annotations

import httpx
import pytest

from exposure.discovery import ProviderError, SearchQuery
from exposure.discovery.providers import SearXNGProvider
from exposure.discovery.providers.searxng import validate_instance_url


def _client_factory(handler):  # type: ignore[no-untyped-def]
    real_client = httpx.Client

    def factory(*args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    return factory


# --------------------------------------------------------------------------- #
# Instance URL validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://127.0.0.1:8888", "http://127.0.0.1:8888"),
        ("https://searx.example/", "https://searx.example"),
        ("  https://searx.example//  ", "https://searx.example"),
    ],
)
def test_valid_instance_urls(url: str, expected: str) -> None:
    assert validate_instance_url(url) == expected


@pytest.mark.parametrize(
    "url,reason",
    [
        ("", "searxng_url_missing"),
        ("   ", "searxng_url_missing"),
        ("ftp://searx.example", "searxng_url_bad_scheme"),
        ("file:///etc/passwd", "searxng_url_bad_scheme"),
        ("javascript:alert(1)", "searxng_url_bad_scheme"),
        ("https://", "searxng_url_missing_host"),
    ],
)
def test_invalid_instance_urls(url: str, reason: str) -> None:
    with pytest.raises(ProviderError, match=reason):
        validate_instance_url(url)


def test_self_hosted_loopback_is_allowed() -> None:
    """A self-hosted instance normally listens on loopback.

    The SSRF boundary applies to discovered URLs, not to an endpoint the user
    deliberately configured.
    """
    provider = SearXNGProvider("http://127.0.0.1:8888")
    assert provider.id == "searxng"


# --------------------------------------------------------------------------- #
# Searching
# --------------------------------------------------------------------------- #


def test_parses_results(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"results": [
            {"url": "https://a.example/1", "title": "A", "content": "first"},
            {"url": "https://b.example/2", "title": "B", "content": "second"},
            {"title": "no url — skipped"},
        ]})

    monkeypatch.setattr(httpx, "Client", _client_factory(handler))
    results = SearXNGProvider("https://searx.example").search(
        SearchQuery(text='"Jane Example"'), 10
    )
    assert [r.url for r in results] == ["https://a.example/1", "https://b.example/2"]
    assert results[0].provider == "searxng"
    assert results[0].snippet == "first"
    assert "format=json" in str(seen["url"])
    assert "/search" in str(seen["url"])


def test_respects_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "Client", _client_factory(
        lambda r: httpx.Response(200, json={"results": [
            {"url": f"https://x.example/{i}"} for i in range(10)]})
    ))
    assert len(SearXNGProvider("https://searx.example").search(SearchQuery(text="q"), 3)) == 3


def test_empty_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "Client", _client_factory(
        lambda r: httpx.Response(200, json={})))
    assert SearXNGProvider("https://searx.example").search(SearchQuery(text="q"), 5) == []


@pytest.mark.parametrize(
    "status,reason",
    [
        (403, "searxng_json_api_blocked"),
        (429, "searxng_json_api_blocked"),
        (500, "searxng_http_500"),
    ],
)
def test_http_errors(monkeypatch: pytest.MonkeyPatch, status: int, reason: str) -> None:
    monkeypatch.setattr(httpx, "Client", _client_factory(
        lambda r: httpx.Response(status)))
    with pytest.raises(ProviderError, match=reason):
        SearXNGProvider("https://searx.example").search(SearchQuery(text="q"), 5)


def test_html_response_means_json_api_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Most public instances return an HTML page instead of JSON."""
    monkeypatch.setattr(httpx, "Client", _client_factory(
        lambda r: httpx.Response(200, content=b"<html><body>results</body></html>")))
    with pytest.raises(ProviderError, match="searxng_json_api_disabled"):
        SearXNGProvider("https://searx.example").search(SearchQuery(text="q"), 5)


def test_unreachable_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "Client", _client_factory(handler))
    with pytest.raises(ProviderError, match="searxng_request_failed"):
        SearXNGProvider("http://127.0.0.1:8888").search(SearchQuery(text="q"), 5)


def test_self_hosted_round_trip_over_real_loopback() -> None:
    """Exercise real sockets, not a mock transport.

    A self-hosted instance listens on loopback, which the retriever's SSRF
    policy would refuse. This proves the provider path genuinely reaches it.
    """
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs, urlparse

    payload = {"results": [{"url": "https://found.example/p", "title": "T", "content": "c"}]}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            query = parse_qs(urlparse(self.path).query)
            assert query.get("format") == ["json"]
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        results = SearXNGProvider(f"http://127.0.0.1:{server.server_port}").search(
            SearchQuery(text="q"), 5
        )
        assert [r.url for r in results] == ["https://found.example/p"]
        assert results[0].provider == "searxng"
    finally:
        server.shutdown()
