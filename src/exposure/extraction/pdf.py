"""Best-effort PDF text extraction (optional ``pdf`` extra).

If ``pypdf`` is not installed we degrade gracefully to an empty text body rather
than failing the scan — the source is still recorded.
"""

from __future__ import annotations

import io

try:
    import pypdf

    _HAVE_PYPDF = True
except Exception:  # pragma: no cover - optional dependency
    pypdf = None  # type: ignore[assignment]
    _HAVE_PYPDF = False


def pdf_to_text(body: bytes, max_pages: int = 50) -> str:
    if not _HAVE_PYPDF:
        return ""
    try:
        reader = pypdf.PdfReader(io.BytesIO(body))
        parts: list[str] = []
        for page in reader.pages[:max_pages]:
            parts.append(page.extract_text() or "")
        return "\n".join(parts)
    except Exception:  # a malformed PDF must not crash the pipeline
        return ""
