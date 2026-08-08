"""Structured-metadata extraction: JSON-LD Person/Organization and OpenGraph.

These are the highest-precision signals on a page because the publisher labelled
them. We map them directly to observation candidates.
"""

from __future__ import annotations

from typing import Any

from exposure.domain.enums import ObservationType
from exposure.extraction.base import Extracted
from exposure.extraction.html import ParsedHTML
from exposure.extraction.social import parse_social
from exposure.security.redaction import mask_email, mask_phone

_EXTRACTOR = "metadata"
_VERSION = "1.0"


def _as_list(value: object) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _person_type(item: dict[str, Any]) -> bool:
    t = item.get("@type")
    types = t if isinstance(t, list) else [t]
    return any(str(x).lower() == "person" for x in types)


def _org_type(item: dict[str, Any]) -> bool:
    t = item.get("@type")
    types = t if isinstance(t, list) else [t]
    return any(str(x).lower() in {"organization", "corporation"} for x in types)


def extract_metadata(parsed: ParsedHTML) -> list[Extracted]:
    items: list[Extracted] = []

    title = parsed.title or parsed.meta.get("og:title")
    if title:
        items.append(
            Extracted(
                type=ObservationType.PAGE_TITLE,
                value_normalized=title.strip().lower(),
                display_value=title.strip(),
                evidence_snippet=title.strip()[:160],
                extractor=_EXTRACTOR,
                extractor_version=_VERSION,
            )
        )

    for node in parsed.jsonld:
        if _person_type(node):
            items.extend(_from_person(node))
        elif _org_type(node):
            name = node.get("name")
            if isinstance(name, str) and name.strip():
                items.append(
                    Extracted(
                        type=ObservationType.ORGANISATION,
                        value_normalized=name.strip().lower(),
                        display_value=name.strip(),
                        evidence_snippet=f"schema.org Organization: {name.strip()}",
                        extractor=_EXTRACTOR,
                        extractor_version=_VERSION,
                    )
                )
    return items


def _from_person(node: dict[str, Any]) -> list[Extracted]:
    out: list[Extracted] = []

    def add(
        otype: ObservationType, value: str, display: str, snippet: str, sensitive: bool = False
    ) -> None:
        out.append(
            Extracted(
                type=otype,
                value_normalized=value.strip().lower(),
                display_value=display.strip(),
                evidence_snippet=snippet[:160],
                is_sensitive=sensitive,
                extractor=_EXTRACTOR,
                extractor_version=_VERSION,
            )
        )

    for name in _as_list(node.get("name")):
        if isinstance(name, str) and name.strip():
            add(ObservationType.NAME, name, name, f"schema.org Person name: {name}")

    for title in _as_list(node.get("jobTitle")):
        if isinstance(title, str) and title.strip():
            add(ObservationType.JOB_TITLE, title, title, f"jobTitle: {title}")

    for employer in _as_list(node.get("worksFor")):
        emp_name = employer.get("name") if isinstance(employer, dict) else employer
        if isinstance(emp_name, str) and emp_name.strip():
            add(ObservationType.EMPLOYER, emp_name, emp_name, f"worksFor: {emp_name}")

    for email in _as_list(node.get("email")):
        if isinstance(email, str) and "@" in email:
            clean = email.replace("mailto:", "").strip()
            add(ObservationType.EMAIL, clean, mask_email(clean), "schema.org email", sensitive=True)

    for phone in _as_list(node.get("telephone")):
        if isinstance(phone, str) and phone.strip():
            add(
                ObservationType.PHONE,
                "".join(c for c in phone if c.isdigit() or c == "+"),
                mask_phone(phone),
                "schema.org telephone",
                sensitive=True,
            )

    for bd in _as_list(node.get("birthDate")):
        if isinstance(bd, str) and bd.strip():
            add(ObservationType.DATE_OF_BIRTH, bd, bd, f"birthDate: {bd}", sensitive=True)

    addr = node.get("address")
    for a in _as_list(addr):
        text = _format_address(a)
        if text:
            add(ObservationType.POSTAL_ADDRESS, text, text, f"schema.org address: {text}", True)

    for same in _as_list(node.get("sameAs")):
        if isinstance(same, str) and same.startswith("http"):
            social = parse_social(same)
            if social:
                platform, username = social
                label = f"{platform}: {username}" if username else platform
                add(ObservationType.SOCIAL_LINK, same, label, f"sameAs: {same}")
    return out


def _format_address(addr: object) -> str:
    if isinstance(addr, str):
        return addr.strip()
    if isinstance(addr, dict):
        parts = [
            addr.get("streetAddress"),
            addr.get("addressLocality"),
            addr.get("addressRegion"),
            addr.get("postalCode"),
            addr.get("addressCountry"),
        ]
        return ", ".join(str(p).strip() for p in parts if p)
    return ""
