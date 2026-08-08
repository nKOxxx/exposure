"""Redaction and masking helpers.

Two distinct jobs:

* ``mask_email`` / ``mask_phone`` produce the *display* form of a sensitive
  identifier for the UI and exports (e.g. ``n•••••@domain.com``).
* ``redact`` scrubs free text before it is written to a log so that raw
  emails, phones, and long digit strings never reach the log sink
  (spec section 22).
"""

from __future__ import annotations

import re
from typing import Any

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Phone-like: at least 7 digits, allowing spaces, dashes, parens, dots, +.
_PHONE_RE = re.compile(r"(?<![\w])\+?[\d][\d\s().\-]{6,}\d(?![\w])")
_LONG_DIGITS_RE = re.compile(r"\b\d{7,}\b")

_MASK_DOT = "•"


def mask_email(value: str) -> str:
    """``nikola@example.com`` -> ``n•••••@example.com`` (domain preserved)."""
    value = value.strip()
    if "@" not in value:
        return _MASK_DOT * max(len(value), 3)
    local, _, domain = value.partition("@")
    if not local:
        return f"{_MASK_DOT * 3}@{domain}"
    head = local[0]
    return f"{head}{_MASK_DOT * max(len(local) - 1, 3)}@{domain}"


def mask_phone(value: str) -> str:
    """Keep only the last two digits: ``+971 50 123 4512`` -> ``+••• •• ••12``."""
    digits = [c for c in value if c.isdigit()]
    if len(digits) <= 2:
        return _MASK_DOT * max(len(value), 3)
    keep = "".join(digits[-2:])
    plus = "+" if value.lstrip().startswith("+") else ""
    return f"{plus}{_MASK_DOT * (len(digits) - 2)}{keep}"


def redact(text: str | None) -> str:
    """Return ``text`` with emails, phones, and long digit runs masked.

    Used for anything that might reach a log or an error message.
    """
    if not text:
        return ""
    out = _EMAIL_RE.sub("[email]", text)
    out = _PHONE_RE.sub("[phone]", out)
    out = _LONG_DIGITS_RE.sub("[digits]", out)
    return out


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Redact string values in a shallow mapping (used for structured logs)."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, str):
            result[key] = redact(value)
        else:
            result[key] = value
    return result
