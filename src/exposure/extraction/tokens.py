"""Known-subject-token extraction (spec section 11A: "known subject tokens").

Because raw pages are discarded after extraction, the resolver can only compare
*observations* to the subject. This pass guarantees that when a subject's name,
location, employer, username, or domain literally appears on the page, a
corresponding observation is emitted with an evidence snippet. It performs no
inference — only literal, case-insensitive presence checks.
"""

from __future__ import annotations

from exposure.domain.enums import ObservationType
from exposure.domain.models import Subject
from exposure.extraction.base import Extracted, snippet_around
from exposure.extraction.html import ParsedHTML

_EXTRACTOR = "subject_tokens"
_VERSION = "1.0"


def _contains(haystack: str, needle: str) -> bool:
    return len(needle) >= 3 and needle.lower() in haystack


def extract_subject_tokens(parsed: ParsedHTML, subject: Subject) -> list[Extracted]:
    text = parsed.text
    hay = text.lower()
    out: list[Extracted] = []
    seen: set[tuple[str, str]] = set()

    def add(otype: ObservationType, value: str, display: str) -> None:
        key = (otype.value, value.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(
            Extracted(
                type=otype,
                value_normalized=value.lower(),
                display_value=display,
                evidence_snippet=snippet_around(text, value),
                extractor=_EXTRACTOR,
                extractor_version=_VERSION,
                meta={"matched": "subject"},
            )
        )

    for name in subject.names:
        if _contains(hay, name.value):
            add(ObservationType.NAME, name.value, name.value)

    for loc in subject.locations:
        for part in (loc.city, loc.country):
            if part and _contains(hay, part):
                add(ObservationType.LOCATION, part, part)

    for emp in subject.employers:
        if _contains(hay, emp.name):
            add(ObservationType.EMPLOYER, emp.name, emp.name)

    for username in subject.usernames:
        if _contains(hay, username):
            add(ObservationType.USERNAME, username, username)

    for domain in subject.personal_domains:
        if _contains(hay, domain):
            add(ObservationType.URL, domain, domain)

    return out
