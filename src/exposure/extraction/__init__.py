"""Extraction: turn a retrieved document into observation candidates.

Layer A (deterministic) is always run: HTML/metadata/PII/subject-token
extraction. Layer B (semantic/LLM) is optional and off by default.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from exposure.domain.models import Subject
from exposure.extraction.base import Extracted
from exposure.extraction.html import ParsedHTML, parse_html
from exposure.extraction.metadata import extract_metadata
from exposure.extraction.pdf import pdf_to_text
from exposure.extraction.pii import extract_pii
from exposure.extraction.tokens import extract_subject_tokens
from exposure.retrieval.limits import HTML_TYPES, PDF_TYPES, TEXT_TYPES


@dataclass(slots=True)
class ExtractionResult:
    title: str | None
    items: list[Extracted] = field(default_factory=list)


def extract_document(
    content_type: str,
    body: bytes,
    subject: Subject | None = None,
) -> ExtractionResult:
    """Extract observation candidates from a retrieved document body."""
    parsed: ParsedHTML
    if content_type in HTML_TYPES:
        parsed = parse_html(body)
    elif content_type in PDF_TYPES:
        text = pdf_to_text(body)
        parsed = ParsedHTML(title=None, text=text)
    elif content_type in TEXT_TYPES:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            text = body.decode("latin-1", errors="replace")
        parsed = ParsedHTML(title=None, text=text)
    else:
        parsed = ParsedHTML()

    items: list[Extracted] = []
    items.extend(extract_metadata(parsed))
    items.extend(extract_pii(parsed))
    if subject is not None:
        items.extend(extract_subject_tokens(parsed, subject))

    return ExtractionResult(title=parsed.title, items=_dedupe(items))


def _dedupe(items: list[Extracted]) -> list[Extracted]:
    seen: set[tuple[str, str]] = set()
    out: list[Extracted] = []
    for item in items:
        key = (item.type.value, item.value_normalized)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


__all__ = ["ExtractionResult", "extract_document", "Extracted"]
