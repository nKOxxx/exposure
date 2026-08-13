"""The standard-library HTML parser remains a working fallback.

selectolax is a hard dependency today, so the stdlib path is dormant in normal
runs. It is the guaranteed floor if selectolax is unavailable or chokes on a
document, so it is exercised explicitly rather than left to rot.
"""

from __future__ import annotations

import pytest

from exposure.extraction import html as html_mod
from exposure.extraction.html import parse_html

DOC = b"""
<html><head><title>Jane Example &amp; Co</title>
<meta property="og:title" content="OG Title">
<meta name="description" content="desc">
<script type="application/ld+json">{"@type":"Person","name":"Jane Example"}</script>
<style>.x{color:red}</style>
</head><body>
<script>var leak='secret@evil.com';</script>
<p>Visible text with jane@example.com</p>
<a href="https://github.com/janeex">gh</a>
</body></html>
"""


@pytest.fixture
def stdlib_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the stdlib path by removing the fast parser."""
    monkeypatch.setattr(html_mod, "HTMLParserFast", None)


def test_fallback_extracts_the_same_essentials(stdlib_only: None) -> None:
    parsed = parse_html(DOC)
    assert parsed.title == "Jane Example & Co"
    assert "Visible text" in parsed.text
    assert parsed.meta["og:title"] == "OG Title"
    assert parsed.meta["description"] == "desc"
    assert any(n.get("name") == "Jane Example" for n in parsed.jsonld)
    assert "https://github.com/janeex" in parsed.links


def test_fallback_drops_script_and_style(stdlib_only: None) -> None:
    parsed = parse_html(DOC)
    assert "secret@evil.com" not in parsed.text
    assert "color:red" not in parsed.text


def test_both_parsers_agree_on_essentials() -> None:
    """The fast path and the fallback must not disagree about what a page says."""
    fast = parse_html(DOC)
    original = html_mod.HTMLParserFast
    try:
        html_mod.HTMLParserFast = None  # type: ignore[assignment]
        slow = parse_html(DOC)
    finally:
        html_mod.HTMLParserFast = original  # type: ignore[assignment]

    assert fast.title == slow.title
    assert fast.meta == slow.meta
    assert fast.links == slow.links
    assert [n.get("name") for n in fast.jsonld] == [n.get("name") for n in slow.jsonld]
    for needle in ("Visible text", "jane@example.com"):
        assert needle in fast.text and needle in slow.text
    assert "secret@evil.com" not in fast.text and "secret@evil.com" not in slow.text


def test_fallback_survives_malformed_markup(stdlib_only: None) -> None:
    parsed = parse_html(b"<html><body><p>unclosed <a href=")
    assert isinstance(parsed.text, str)


def test_fallback_handles_latin1(stdlib_only: None) -> None:
    parsed = parse_html("<html><body><p>caf\xe9</p></body></html>".encode("latin-1"))
    assert "caf" in parsed.text


def test_fast_parser_handles_broken_jsonld() -> None:
    parsed = parse_html(
        b'<html><head><script type="application/ld+json">{bad json,</script></head>'
        b"<body><p>fine</p></body></html>"
    )
    assert parsed.jsonld == []
    assert "fine" in parsed.text
