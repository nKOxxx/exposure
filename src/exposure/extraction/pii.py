"""Deterministic PII extraction from visible text and links (spec section 11A).

This is the preferred extraction layer: no model, fully reproducible, and each
item carries a minimal evidence snippet. The semantic (LLM) layer only runs when
this layer is insufficient, and even then its output is a candidate until
validated.
"""

from __future__ import annotations

import re

from exposure.domain.enums import ObservationType
from exposure.extraction.base import Extracted, snippet_around
from exposure.extraction.html import ParsedHTML
from exposure.extraction.social import parse_social
from exposure.security.redaction import mask_email, mask_phone

_EXTRACTOR = "pii"
_VERSION = "1.0"

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<![\w])\+?\d[\d\s().\-]{6,}\d(?![\w])")
_DATE_RE = re.compile(
    r"\b(\d{1,2}[ /\-](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[ /\-]\d{2,4}"
    r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[ ]\d{1,2},?[ ]\d{2,4}"
    r"|\d{4}-\d{2}-\d{2}"
    r"|\d{1,2}/\d{1,2}/\d{2,4})\b",
    re.IGNORECASE,
)
_DOB_CONTEXT_RE = re.compile(r"(date of birth|born on|born|d\.?o\.?b\.?)", re.IGNORECASE)
_POSTAL_RE = re.compile(
    r"\b\d{1,5}\s+[A-Z][A-Za-z.'\-]+(?:\s+[A-Z][A-Za-z.'\-]+){0,4}\s+"
    r"(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Square|Sq)\b",
)


# Digit runs that are dates, not phone numbers. Live testing against real pages
# showed ISO dates ("2026-08-05") and date ranges dominating phone matches.
_DATE_SHAPED_RE = re.compile(
    r"^\(?\d{4}[-/.]\d{1,2}[-/.]\d{1,2}\)?$"      # 2026-08-05
    r"|^\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}$"          # 05-08-2026
    r"|^\d{4}[-–]\d{4}$"                            # 1815-1852
)

# A phone must look like a phone: either written internationally (leading +) or
# announced by nearby context. Precision over recall (spec section 10).
# Word boundaries matter: without them "Intelligence" contains "tel" and an ISBN
# in a citation gets read as a telephone number (found by live testing).
_PHONE_CONTEXT_RE = re.compile(
    r"\b(tel|telephone|phone|mobile|cell|call|fax|whatsapp|contact)\b", re.IGNORECASE
)

# Identifier prefixes whose digit runs are never phone numbers.
_NON_PHONE_PREFIX_RE = re.compile(
    r"\b(isbn|issn|doi|ean|upc|vat|iban|swift|bic|asin|pmid|arxiv)\b[:\s]*$",
    re.IGNORECASE,
)


def _phone_is_plausible(raw: str) -> bool:
    digits = [c for c in raw if c.isdigit()]
    if not 7 <= len(digits) <= 15:
        return False
    if _DATE_SHAPED_RE.match(raw.strip()):
        return False
    # Reject runs that are mostly separators (typically tables of numbers).
    separators = sum(1 for c in raw if c in " .-()")
    return separators <= len(digits)


def extract_pii(parsed: ParsedHTML) -> list[Extracted]:
    text = parsed.text
    out: list[Extracted] = []
    seen: set[tuple[str, str]] = set()

    def add(item: Extracted) -> None:
        key = (item.type.value, item.value_normalized)
        if key in seen:
            return
        seen.add(key)
        out.append(item)

    # Emails
    for m in _EMAIL_RE.finditer(text):
        raw = m.group(0)
        add(
            Extracted(
                type=ObservationType.EMAIL,
                value_normalized=raw.lower(),
                display_value=mask_email(raw),
                evidence_snippet=snippet_around(text, raw),
                is_sensitive=True,
                extractor=_EXTRACTOR,
                extractor_version=_VERSION,
            )
        )

    # Phones. A bare digit run in prose is almost never a phone number, so we
    # require an international "+" prefix or an explicit nearby cue.
    for m in _PHONE_RE.finditer(text):
        raw = m.group(0).strip()
        if not _phone_is_plausible(raw):
            continue
        context = text[max(0, m.start() - 40) : m.start()]
        if _NON_PHONE_PREFIX_RE.search(context):
            continue  # ISBN/DOI/IBAN-style identifier, not a phone
        if not raw.startswith("+") and not _PHONE_CONTEXT_RE.search(context):
            continue
        normalized = "".join(c for c in raw if c.isdigit() or c == "+")
        add(
            Extracted(
                type=ObservationType.PHONE,
                value_normalized=normalized,
                display_value=mask_phone(raw),
                evidence_snippet=snippet_around(text, raw),
                is_sensitive=True,
                extractor=_EXTRACTOR,
                extractor_version=_VERSION,
            )
        )

    # Dates of birth. Only dates announced as a birth date are retained: a bare
    # date maps to no finding category and no resolution signal, so persisting
    # every date on a page would collect data the product cannot use
    # (spec P2, section 9). Live testing found 246 such rows on two articles.
    for m in _DATE_RE.finditer(text):
        raw = m.group(0)
        context = text[max(0, m.start() - 40) : m.start()]
        if not _DOB_CONTEXT_RE.search(context):
            continue
        add(
            Extracted(
                type=ObservationType.DATE_OF_BIRTH,
                value_normalized=raw.lower(),
                display_value=raw,
                evidence_snippet=snippet_around(text, raw),
                is_sensitive=True,
                extractor=_EXTRACTOR,
                extractor_version=_VERSION,
            )
        )

    # Postal-address-like structures
    for m in _POSTAL_RE.finditer(text):
        raw = m.group(0)
        add(
            Extracted(
                type=ObservationType.POSTAL_ADDRESS,
                value_normalized=" ".join(raw.lower().split()),
                display_value=raw,
                evidence_snippet=snippet_around(text, raw),
                is_sensitive=True,
                extractor=_EXTRACTOR,
                extractor_version=_VERSION,
            )
        )

    # Links: mailto/tel and social profiles
    for href in parsed.links:
        low = href.lower()
        if low.startswith("mailto:"):
            addr = href[7:].split("?", 1)[0]
            if "@" in addr:
                add(
                    Extracted(
                        type=ObservationType.EMAIL,
                        value_normalized=addr.lower(),
                        display_value=mask_email(addr),
                        evidence_snippet=f"mailto link: {mask_email(addr)}",
                        is_sensitive=True,
                        extractor=_EXTRACTOR,
                        extractor_version=_VERSION,
                    )
                )
        elif low.startswith("tel:"):
            raw = href[4:]
            if _phone_is_plausible(raw):
                add(
                    Extracted(
                        type=ObservationType.PHONE,
                        value_normalized="".join(c for c in raw if c.isdigit() or c == "+"),
                        display_value=mask_phone(raw),
                        evidence_snippet=f"tel link: {mask_phone(raw)}",
                        is_sensitive=True,
                        extractor=_EXTRACTOR,
                        extractor_version=_VERSION,
                    )
                )
        elif low.startswith("http"):
            social = parse_social(href)
            if social:
                platform, username = social
                label = f"{platform}: {username}" if username else platform
                add(
                    Extracted(
                        type=ObservationType.SOCIAL_LINK,
                        value_normalized=href.lower(),
                        display_value=label,
                        evidence_snippet=f"link: {href}",
                        extractor=_EXTRACTOR,
                        extractor_version=_VERSION,
                    )
                )
                if username:
                    add(
                        Extracted(
                            type=ObservationType.USERNAME,
                            value_normalized=username.lower(),
                            display_value=username,
                            evidence_snippet=f"{platform} handle in {href}",
                            extractor=_EXTRACTOR,
                            extractor_version=_VERSION,
                        )
                    )
    return out
