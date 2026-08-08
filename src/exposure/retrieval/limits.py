"""Response type and size limits (spec sections 8, 9).

Guards against oversized responses and decompression bombs by counting bytes as
they are *decoded* and aborting past the cap, and by rejecting content types we
do not process.
"""

from __future__ import annotations

import httpx

# Content types we are willing to parse.
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
TEXT_TYPES = frozenset({"text/plain"})
PDF_TYPES = frozenset({"application/pdf"})
ALLOWED_TYPES = HTML_TYPES | TEXT_TYPES | PDF_TYPES


class ResponseTooLarge(Exception):
    """Raised when a response exceeds its byte cap."""


class UnsupportedContentType(Exception):
    """Raised when a response is a type we do not process."""


def parse_content_type(header: str | None) -> str:
    if not header:
        return ""
    return header.split(";", 1)[0].strip().lower()


def cap_for(content_type: str, max_html: int, max_pdf: int) -> int:
    if content_type in PDF_TYPES:
        return max_pdf
    return max_html


def read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    """Read a streaming response, aborting if decoded size exceeds ``max_bytes``.

    Counting *decoded* bytes (httpx decompresses in ``iter_bytes``) is what makes
    this a decompression-bomb defense: a 1 KB gzip that expands to 1 GB is cut
    off at the cap.
    """
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > max_bytes:
            response.close()
            raise ResponseTooLarge(f"exceeded {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)
