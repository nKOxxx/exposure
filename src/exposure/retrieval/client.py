"""The secure retriever: the only component allowed to fetch remote URLs.

Every URL and every response is treated as hostile. Redirects are followed
manually so each hop is re-validated (scheme/host here, IP at connect time in the
guarded backend). Proxy environment variables are ignored (``trust_env=False``)
so a hostile ``HTTP_PROXY`` cannot redirect our egress.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import httpx

from exposure.config import Settings
from exposure.domain.enums import SourceStatus
from exposure.retrieval.canonicalize import resolve_redirect
from exposure.retrieval.limits import (
    ALLOWED_TYPES,
    ResponseTooLarge,
    UnsupportedContentType,
    cap_for,
    parse_content_type,
    read_capped,
)
from exposure.retrieval.network_policy import GuardedTransport
from exposure.security.validation import UrlPolicyError, validate_url_syntax

_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_USER_AGENT = "Exposure/0.2 (+https://github.com/nKOxxx/exposure; personal exposure scan)"


@dataclass(slots=True)
class RetrievedDocument:
    final_url: str
    status_code: int
    content_type: str
    body: bytes
    content_hash: str


class RetrievalError(Exception):
    """A retrieval failure with an explicit, non-lossy status (spec section 35)."""

    def __init__(self, status: SourceStatus, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


class SecureRetriever:
    """Synchronous SSRF-safe HTTP client. Run inside a worker thread."""

    def __init__(
        self, settings: Settings, transport: httpx.BaseTransport | None = None
    ) -> None:
        self._settings = settings
        limits = httpx.Limits(
            max_connections=settings.global_concurrency,
            max_keepalive_connections=settings.per_domain_concurrency,
        )
        timeout = httpx.Timeout(
            connect=settings.connect_timeout_s,
            read=settings.total_timeout_s,
            write=settings.total_timeout_s,
            pool=settings.total_timeout_s,
        )
        # In production the guarded transport is mandatory. Tests may inject a
        # MockTransport to exercise redirect/limit handling without real egress;
        # note that the guarded backend's IP pinning is covered by its own unit
        # tests, and fetch() still re-validates every redirect URL regardless of
        # transport.
        self._client = httpx.Client(
            transport=transport or GuardedTransport(verify=True, limits=limits),
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": _USER_AGENT, "Accept-Encoding": "gzip, deflate"},
            max_redirects=0,
        )

    def __enter__(self) -> SecureRetriever:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def fetch(self, url: str) -> RetrievedDocument:
        """Fetch ``url`` safely, following validated redirects. Raises RetrievalError."""
        try:
            current = validate_url_syntax(url)
        except UrlPolicyError as exc:
            raise RetrievalError(SourceStatus.RETRIEVAL_BLOCKED, str(exc)) from exc

        for _ in range(self._settings.max_redirects + 1):
            try:
                with self._client.stream("GET", current) as response:
                    if response.status_code in _REDIRECT_CODES:
                        location = response.headers.get("location")
                        if not location:
                            raise RetrievalError(SourceStatus.ERROR, "redirect_without_location")
                        nxt = resolve_redirect(str(response.url), location)
                        try:
                            current = validate_url_syntax(nxt)
                        except UrlPolicyError as exc:
                            raise RetrievalError(
                                SourceStatus.RETRIEVAL_BLOCKED, f"redirect_{exc}"
                            ) from exc
                        continue

                    return self._finalize(response)
            except httpx.TimeoutException as exc:
                raise RetrievalError(SourceStatus.TIMEOUT, "timeout") from exc
            except UrlPolicyError as exc:  # raised inside the guarded backend
                raise RetrievalError(SourceStatus.RETRIEVAL_BLOCKED, str(exc)) from exc
            except RetrievalError:
                raise
            except httpx.HTTPError as exc:
                raise RetrievalError(SourceStatus.ERROR, type(exc).__name__) from exc

        raise RetrievalError(SourceStatus.ERROR, "too_many_redirects")

    def _finalize(self, response: httpx.Response) -> RetrievedDocument:
        content_type = parse_content_type(response.headers.get("content-type"))
        if content_type and content_type not in ALLOWED_TYPES:
            raise RetrievalError(SourceStatus.UNSUPPORTED_TYPE, content_type)

        cap = cap_for(content_type, self._settings.max_html_bytes, self._settings.max_pdf_bytes)

        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > cap:
            raise RetrievalError(SourceStatus.TOO_LARGE, "content_length")

        try:
            body = read_capped(response, cap)
        except ResponseTooLarge as exc:
            raise RetrievalError(SourceStatus.TOO_LARGE, str(exc)) from exc
        except UnsupportedContentType as exc:
            raise RetrievalError(SourceStatus.UNSUPPORTED_TYPE, str(exc)) from exc

        return RetrievedDocument(
            final_url=str(response.url),
            status_code=response.status_code,
            content_type=content_type or "application/octet-stream",
            body=body,
            content_hash=hashlib.sha256(body).hexdigest(),
        )
