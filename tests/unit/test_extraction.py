from __future__ import annotations

from exposure.domain.enums import ObservationType
from exposure.domain.models import LocationHint, Name, OrganisationHint, Subject
from exposure.extraction import extract_document


def _subject() -> Subject:
    return Subject(
        names=[Name(value="Jane Example", is_primary=True)],
        locations=[LocationHint(city="London", country="UK")],
        employers=[OrganisationHint(name="Acme Corp")],
    )


HTML = b"""
<html><head><title>Jane Example</title>
<script type="application/ld+json">
{"@type":"Person","name":"Jane Example","jobTitle":"CFO",
 "worksFor":{"@type":"Organization","name":"Acme Corp"},
 "email":"jane@example.com","telephone":"+44 20 7946 0958",
 "address":{"streetAddress":"10 Downing St","addressLocality":"London"},
 "sameAs":["https://github.com/janeexample"]}
</script></head>
<body><p>Contact jane@example.com. Born on 3 May 1980. 221 Baker Street London</p></body></html>
"""


def test_extracts_expected_types() -> None:
    res = extract_document("text/html", HTML, _subject())
    types = {i.type for i in res.items}
    assert ObservationType.EMAIL in types
    assert ObservationType.PHONE in types
    assert ObservationType.EMPLOYER in types
    assert ObservationType.DATE_OF_BIRTH in types
    assert ObservationType.POSTAL_ADDRESS in types


def test_sensitive_values_are_masked() -> None:
    res = extract_document("text/html", HTML, _subject())
    email = next(i for i in res.items if i.type == ObservationType.EMAIL)
    assert email.is_sensitive
    assert email.display_value != "jane@example.com"
    assert email.display_value.endswith("@example.com")


def test_every_item_has_evidence_snippet() -> None:
    res = extract_document("text/html", HTML, _subject())
    assert all(i.evidence_snippet for i in res.items)


def test_malformed_html_does_not_crash() -> None:
    res = extract_document("text/html", b"<html><body><p>unclosed <a href=", _subject())
    assert isinstance(res.items, list)


def test_plain_text_and_unknown_type() -> None:
    res = extract_document("text/plain", b"email me at x@y.com", None)
    assert any(i.type == ObservationType.EMAIL for i in res.items)
    res2 = extract_document("application/octet-stream", b"\x00\x01", None)
    assert res2.items == []
