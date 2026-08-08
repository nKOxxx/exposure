"""Deeper extraction coverage: link handling, HTML edge cases, PDF, metadata."""

from __future__ import annotations

import pytest

from exposure.domain.enums import ObservationType
from exposure.domain.models import LocationHint, Name, OrganisationHint, Subject
from exposure.extraction import extract_document
from exposure.extraction.base import Extracted, snippet_around
from exposure.extraction.html import parse_html
from exposure.extraction.metadata import extract_metadata
from exposure.extraction.pdf import pdf_to_text
from exposure.extraction.pii import extract_pii
from exposure.extraction.semantic import semantic_extract
from exposure.extraction.social import parse_social
from exposure.extraction.tokens import extract_subject_tokens

# --------------------------------------------------------------------------- #
# PII from links (the previously untested branch)
# --------------------------------------------------------------------------- #


def test_mailto_and_tel_links() -> None:
    parsed = parse_html(
        b'<html><body><a href="mailto:press@example.com?subject=hi">mail</a>'
        b'<a href="tel:+442079460958">call</a>'
        b'<a href="mailto:broken">bad</a>'
        b'<a href="tel:123">too short</a></body></html>'
    )
    items = extract_pii(parsed)
    emails = [i for i in items if i.type == ObservationType.EMAIL]
    phones = [i for i in items if i.type == ObservationType.PHONE]
    assert [e.value_normalized for e in emails] == ["press@example.com"]
    assert phones and phones[0].value_normalized == "+442079460958"
    assert all(i.is_sensitive for i in emails + phones)
    # Masked in the display value.
    assert "press@example.com" not in emails[0].display_value


def test_social_links_yield_platform_and_username() -> None:
    parsed = parse_html(
        b'<html><body>'
        b'<a href="https://www.linkedin.com/in/janeexample">li</a>'
        b'<a href="https://github.com/janeex">gh</a>'
        b'<a href="https://example.org/not-social">other</a>'
        b'</body></html>'
    )
    items = extract_pii(parsed)
    socials = {i.display_value for i in items if i.type == ObservationType.SOCIAL_LINK}
    usernames = {i.value_normalized for i in items if i.type == ObservationType.USERNAME}
    assert "LinkedIn: janeexample" in socials
    assert "GitHub: janeex" in socials
    assert {"janeexample", "janeex"} <= usernames


def test_implausible_phone_is_ignored() -> None:
    parsed = parse_html(b"<html><body><p>Call 12345 or 1234567890123456789</p></body></html>")
    assert not [i for i in extract_pii(parsed) if i.type == ObservationType.PHONE]


def test_dob_requires_context() -> None:
    """Only birth-announced dates are kept; bare dates are not collected."""
    with_ctx = parse_html(b"<html><body><p>Date of birth: 3 May 1980</p></body></html>")
    without = parse_html(b"<html><body><p>Published 3 May 1980</p></body></html>")
    assert any(i.type == ObservationType.DATE_OF_BIRTH for i in extract_pii(with_ctx))
    types = {i.type for i in extract_pii(without)}
    assert ObservationType.DATE_OF_BIRTH not in types
    # A bare date maps to no finding, so it is never persisted (spec P2).
    assert ObservationType.DATE not in types


@pytest.mark.parametrize(
    "text,expected",
    [
        (b"<p>Call us on +44 20 7946 0958</p>", True),
        (b"<p>Telephone: 020 7946 0958</p>", True),
        (b"<p>Published 2026-08-05 and 2026-07-28</p>", False),   # ISO dates
        (b"<p>Lived 1815-1852 in London</p>", False),             # year range
        (b"<p>MIT Press. ISBN 978-0-262-26542-3.</p>", False),    # ISBN
        (b"<p>A study of Intelligence 020 7946 0958</p>", False),  # 'tel' inside a word
    ],
)
def test_phone_detection_precision(text: bytes, expected: bool) -> None:
    parsed = parse_html(b"<html><body>" + text + b"</body></html>")
    found = any(i.type == ObservationType.PHONE for i in extract_pii(parsed))
    assert found is expected


def test_duplicate_values_are_deduped() -> None:
    parsed = parse_html(
        b"<html><body><p>a@b.com</p><p>a@b.com</p><p>a@b.com</p></body></html>"
    )
    assert len([i for i in extract_pii(parsed) if i.type == ObservationType.EMAIL]) == 1


# --------------------------------------------------------------------------- #
# HTML parser edge cases
# --------------------------------------------------------------------------- #


def test_script_and_style_content_is_dropped() -> None:
    parsed = parse_html(
        b"<html><head><style>.x{color:red}</style></head><body>"
        b"<script>var leak='secret@evil.com';</script>"
        b"<noscript>nojs@evil.com</noscript>"
        b"<p>visible@example.com</p></body></html>"
    )
    assert "secret@evil.com" not in parsed.text
    assert "nojs@evil.com" not in parsed.text
    assert "visible@example.com" in parsed.text


def test_meta_and_opengraph() -> None:
    parsed = parse_html(
        b'<html><head><meta property="og:title" content="OG Title">'
        b'<meta name="description" content="desc"></head><body></body></html>'
    )
    assert parsed.meta["og:title"] == "OG Title"
    assert parsed.meta["description"] == "desc"
    assert extract_metadata(parsed)[0].display_value == "OG Title"


def test_jsonld_graph_and_malformed() -> None:
    good = parse_html(
        b'<html><head><script type="application/ld+json">'
        b'{"@graph":[{"@type":"Person","name":"Jane Example"}]}</script></head><body></body></html>'
    )
    assert any(n.get("@type") == "Person" for n in good.jsonld)

    bad = parse_html(
        b'<html><head><script type="application/ld+json">{not json,</script></head>'
        b"<body><p>fine</p></body></html>"
    )
    assert bad.jsonld == []
    assert "fine" in bad.text


def test_jsonld_list_payload() -> None:
    parsed = parse_html(
        b'<html><head><script type="application/ld+json">'
        b'[{"@type":"Person","name":"A B"},{"@type":"Organization","name":"Acme"}]'
        b"</script></head><body></body></html>"
    )
    items = extract_metadata(parsed)
    assert any(i.type == ObservationType.NAME for i in items)
    assert any(i.type == ObservationType.ORGANISATION for i in items)


def test_latin1_fallback_decoding() -> None:
    parsed = parse_html("<html><body><p>caf\xe9</p></body></html>".encode("latin-1"))
    assert "caf" in parsed.text


def test_person_with_list_type_and_string_address() -> None:
    parsed = parse_html(
        b'<html><head><script type="application/ld+json">'
        b'{"@type":["Person","Thing"],"name":"Jane Example",'
        b'"address":"10 Downing St, London","birthDate":"1980-05-03",'
        b'"telephone":"+44 20 7946 0958","email":"mailto:jane@example.com",'
        b'"sameAs":["https://twitter.com/janeex","not-a-url"]}'
        b"</script></head><body></body></html>"
    )
    items = extract_metadata(parsed)
    kinds = {i.type for i in items}
    assert ObservationType.POSTAL_ADDRESS in kinds
    assert ObservationType.DATE_OF_BIRTH in kinds
    assert ObservationType.SOCIAL_LINK in kinds
    email = next(i for i in items if i.type == ObservationType.EMAIL)
    assert email.value_normalized == "jane@example.com"  # mailto: stripped


def test_organization_without_name_is_skipped() -> None:
    parsed = parse_html(
        b'<html><head><script type="application/ld+json">'
        b'{"@type":"Organization"}</script></head><body></body></html>'
    )
    assert not [i for i in extract_metadata(parsed) if i.type == ObservationType.ORGANISATION]


# --------------------------------------------------------------------------- #
# social / tokens / base helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://www.linkedin.com/in/jane", ("LinkedIn", "jane")),
        ("https://x.com/@handle", ("Twitter/X", "handle")),
        ("https://t.me/channel", ("Telegram", "channel")),
        ("https://youtube.com/watch", ("YouTube", None)),
        ("https://unknown.example/jane", None),
    ],
)
def test_parse_social(url: str, expected: tuple[str, str | None] | None) -> None:
    assert parse_social(url) == expected


def test_www_prefix_stripped_not_characters() -> None:
    # Regression: lstrip("www.") would mangle hosts beginning with w/./
    assert parse_social("https://www.github.com/wanda")[0] == "GitHub"


def test_subject_tokens_match_literally() -> None:
    subject = Subject(
        names=[Name(value="Jane Example", is_primary=True)],
        locations=[LocationHint(city="London", country="UK")],
        employers=[OrganisationHint(name="Acme Corp")],
        usernames=["janeex"],
        personal_domains=["janeexample.com"],
    )
    parsed = parse_html(
        b"<html><body><p>Jane Example of Acme Corp in London, see janeexample.com, "
        b"handle janeex</p></body></html>"
    )
    found = {i.type for i in extract_subject_tokens(parsed, subject)}
    assert {
        ObservationType.NAME, ObservationType.LOCATION,
        ObservationType.EMPLOYER, ObservationType.USERNAME, ObservationType.URL,
    } <= found


def test_subject_tokens_ignore_short_values() -> None:
    subject = Subject(names=[Name(value="Jo", is_primary=True)], usernames=["ab"])
    parsed = parse_html(b"<html><body><p>Jo and ab</p></body></html>")
    assert extract_subject_tokens(parsed, subject) == []


def test_snippet_around_handles_missing_needle() -> None:
    assert snippet_around("some text", "absent").startswith("absent")
    windowed = snippet_around("x" * 300 + "NEEDLE" + "y" * 300, "NEEDLE")
    assert windowed.startswith("…") and windowed.endswith("…")


# --------------------------------------------------------------------------- #
# PDF + semantic layers
# --------------------------------------------------------------------------- #


def test_pdf_text_extraction() -> None:
    pytest.importorskip("pypdf")
    import io

    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    # A blank PDF yields empty text but must not raise.
    assert pdf_to_text(buf.getvalue()) == ""


def test_malformed_pdf_returns_empty() -> None:
    assert pdf_to_text(b"%PDF-1.4 not really a pdf") == ""


def test_pdf_content_type_routes_through_extractor() -> None:
    result = extract_document("application/pdf", b"%PDF-1.4 broken", None)
    assert result.items == []


def test_semantic_layer_is_inert_without_provider() -> None:
    parsed = parse_html(b"<html><body><p>Jane joined Acme as CFO in 2021.</p></body></html>")
    assert semantic_extract(parsed) == []
    assert semantic_extract(parsed, ai_provider=object()) == []


def test_extracted_dataclass_defaults() -> None:
    item = Extracted(
        type=ObservationType.OTHER, value_normalized="v", display_value="V",
        evidence_snippet="s",
    )
    assert item.extractor == "deterministic" and item.meta == {}
