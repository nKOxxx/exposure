"""Semantic (LLM) extraction layer — spec section 11B.

Runs only when deterministic extraction is insufficient AND the user has enabled
AI. Its output is always a *candidate* until validated; it never bypasses the
deterministic layer. With AI off (the default) this returns nothing, so the
product is fully functional without any model.
"""

from __future__ import annotations

from exposure.extraction.base import Extracted
from exposure.extraction.html import ParsedHTML


def semantic_extract(parsed: ParsedHTML, *, ai_provider: object | None = None) -> list[Extracted]:
    # AI is off by default; the deterministic path already produced observations.
    if ai_provider is None:
        return []
    # Reserved for the M7 AI provider. Even when wired, the provider receives a
    # sanitized packet and returns schema-validated candidates only.
    return []
