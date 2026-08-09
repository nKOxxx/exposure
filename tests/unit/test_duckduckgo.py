"""DuckDuckGo provider: the keyless, zero-setup default.

ddgs is stubbed so these never touch the network. A real-network smoke test is
in ``test_search_live.py`` (opt-in).
"""

from __future__ import annotations

import os
import sys
import types

import pytest

from exposure.discovery import ProviderError, SearchQuery
from exposure.discovery.providers import DuckDuckGoProvider


def _install_fake_ddgs(monkeypatch: pytest.MonkeyPatch, rows=None, raises=None) -> dict:
    """Install a fake ``ddgs`` module exposing DDGS().text()."""
    calls: dict = {}

    class FakeDDGS:
        def __init__(self, *a, **k):
            calls["init"] = (a, k)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def text(self, query, max_results=10):
            calls["query"] = query
            calls["max_results"] = max_results
            if raises is not None:
                raise raises
            return rows or []

    module = types.ModuleType("ddgs")
    module.DDGS = FakeDDGS
    monkeypatch.setitem(sys.modules, "ddgs", module)
    return calls


def test_parses_results(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_fake_ddgs(monkeypatch, rows=[
        {"href": "https://a.example/1", "title": "A", "body": "first"},
        {"href": "https://b.example/2", "title": "B", "body": "second"},
        {"title": "no href — skipped"},
    ])
    results = DuckDuckGoProvider().search(SearchQuery(text='"Jane Example"'), 10)
    assert [r.url for r in results] == ["https://a.example/1", "https://b.example/2"]
    assert results[0].provider == "duckduckgo"
    assert results[0].snippet == "first"
    assert calls["query"] == '"Jane Example"'


def test_respects_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_ddgs(monkeypatch, rows=[{"href": f"https://x/{i}"} for i in range(20)])
    assert len(DuckDuckGoProvider().search(SearchQuery(text="q"), 3)) == 3


def test_rate_limit_is_classified(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_ddgs(monkeypatch, raises=RuntimeError("RatelimitException: 429"))
    with pytest.raises(ProviderError, match="duckduckgo_rate_limited"):
        DuckDuckGoProvider().search(SearchQuery(text="q"), 5)


def test_timeout_is_classified(monkeypatch: pytest.MonkeyPatch) -> None:
    class TimeoutException(Exception):
        pass

    _install_fake_ddgs(monkeypatch, raises=TimeoutException("slow"))
    with pytest.raises(ProviderError, match="duckduckgo_timeout"):
        DuckDuckGoProvider().search(SearchQuery(text="q"), 5)


def test_generic_failure_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_ddgs(monkeypatch, raises=ValueError("boom"))
    with pytest.raises(ProviderError, match="duckduckgo_failed:ValueError"):
        DuckDuckGoProvider().search(SearchQuery(text="q"), 5)


def test_missing_library_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulate ddgs not being importable.
    monkeypatch.setitem(sys.modules, "ddgs", None)
    with pytest.raises(ProviderError, match="duckduckgo_library_missing"):
        DuckDuckGoProvider().search(SearchQuery(text="q"), 5)


def test_content_field_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_ddgs(monkeypatch, rows=[{"url": "https://a/1", "content": "snip"}])
    results = DuckDuckGoProvider().search(SearchQuery(text="q"), 5)
    assert results[0].url == "https://a/1" and results[0].snippet == "snip"


@pytest.mark.skipif(
    os.environ.get("EXPOSURE_LIVE") != "1",
    reason="hits the live DuckDuckGo endpoint; set EXPOSURE_LIVE=1 to run",
)
def test_live_duckduckgo_returns_results() -> None:
    """Opt-in real-network smoke test. May be rate-limited; that's acceptable."""
    from exposure.discovery.provider import ProviderError

    try:
        results = DuckDuckGoProvider().search(SearchQuery(text='"Ada Lovelace" London'), 5)
    except ProviderError as exc:
        pytest.skip(f"DuckDuckGo unavailable right now: {exc}")
    assert results, "expected at least one live result"
    assert all(r.url.startswith("http") for r in results)
