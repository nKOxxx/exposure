from __future__ import annotations

import pytest

from exposure.retrieval.canonicalize import canonical_url, registrable_domain, resolve_redirect


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://Example.com:443/path/", "https://example.com/path"),
        ("http://example.com:80/", "http://example.com/"),
        ("https://example.com/a?utm_source=x&q=1#frag", "https://example.com/a?q=1"),
        ("https://example.com", "https://example.com/"),
    ],
)
def test_canonical_url(url: str, expected: str) -> None:
    assert canonical_url(url) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://www.bbc.co.uk/news", "bbc.co.uk"),
        ("sub.example.com", "example.com"),
        ("https://github.com/nKOxxx", "github.com"),
    ],
)
def test_registrable_domain(value: str, expected: str) -> None:
    assert registrable_domain(value) == expected


def test_resolve_relative_redirect() -> None:
    assert resolve_redirect("https://example.com/a/b", "../c") == "https://example.com/c"
