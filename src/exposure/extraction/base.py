"""Shared types for extraction.

An ``Extracted`` item is an observation candidate: a fact plus the minimal
snippet that evidences it. The scan pipeline attaches a ``source_id`` and
version metadata to turn it into a persisted :class:`Observation`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from exposure.domain.enums import ObservationType


@dataclass(slots=True)
class Extracted:
    type: ObservationType
    value_normalized: str
    display_value: str
    evidence_snippet: str
    is_sensitive: bool = False
    extractor: str = "deterministic"
    extractor_version: str = "1.0"
    meta: dict[str, str] = field(default_factory=dict)


def snippet_around(text: str, needle: str, width: int = 80) -> str:
    """Return a short window of ``text`` centred on ``needle`` (minimal evidence)."""
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return needle[: width * 2]
    start = max(0, idx - width)
    end = min(len(text), idx + len(needle) + width)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{text[start:end].strip()}{suffix}"
