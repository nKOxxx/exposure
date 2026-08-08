"""SSRF and retrieval-boundary tests (spec sections 8, 28, 42).

These are release-gate tests: the retriever must never be able to reach a
private network address, directly or via redirect or DNS rebinding.
"""

from __future__ import annotations

import gzip

import httpx
import pytest

from exposure.config import Settings
from exposure.domain.enums import SourceStatus
from exposure.retrieval.client import RetrievalError, SecureRetriever
from exposure.retrieval.limits import ResponseTooLarge, read_capped
from exposure.retrieval.network_policy import resolve_and_validate
from exposure.security.validation import (
    UrlPolicyError,
    is_blocked_address,
    validate_url_syntax,
)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com",
        "data:text/html,hi",
        "javascript:alert(1)",
        "ws://example.com",
        "wss://example.com",
        "mailto:a@b.com",
    ],
)
def test_rejects_dangerous_schemes(url: str) -> None:
    with pytest.raises(UrlPolicyError):
        validate_url_syntax(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://metadata.google.internal/",
    ],
)
def test_rejects_private_and_metadata_literals(url: str) -> None:
    with pytest.raises(UrlPolicyError):
        validate_url_syntax(url)


def test_accepts_public_https() -> None:
    assert validate_url_syntax("https://example.com/path") == "https://example.com/path"


@pytest.mark.parametrize(
    "ip,blocked",
    [
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("192.168.0.1", True),
        ("169.254.169.254", True),
        ("::1", True),
        ("fc00::1", True),
        ("fe80::1", True),
        ("::ffff:10.0.0.1", True),  # IPv4-mapped private must be caught
    ],
)
def test_is_blocked_address(ip: str, blocked: bool) -> None:
    assert is_blocked_address(ip) is blocked


def test_dns_rebinding_defense(monkeypatch: pytest.MonkeyPatch) -> None:
    """If a hostname resolves to a private IP, we must refuse to connect."""
    import exposure.retrieval.network_policy as np

    monkeypatch.setattr(np, "_getaddrinfo", lambda host, port: ["10.0.0.7"])
    with pytest.raises(UrlPolicyError, match="dns_resolves_to_blocked"):
        resolve_and_validate("evil.example.com", 443)


def test_dns_mixed_answer_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    import exposure.retrieval.network_policy as np

    # A public + private mix is treated as hostile (fail-closed).
    monkeypatch.setattr(np, "_getaddrinfo", lambda host, port: ["93.184.216.34", "127.0.0.1"])
    with pytest.raises(UrlPolicyError):
        resolve_and_validate("mixed.example.com", 443)


def test_dns_public_answer_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    import exposure.retrieval.network_policy as np

    monkeypatch.setattr(np, "_getaddrinfo", lambda host, port: ["93.184.216.34"])
    assert resolve_and_validate("example.com", 443) == "93.184.216.34"


def _settings() -> Settings:
    return Settings(max_html_bytes=1024, max_redirects=3)


def test_redirect_to_private_is_blocked() -> None:
    """A 302 pointing at a private address must abort with RETRIEVAL_BLOCKED."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://169.254.169.254/"})

    retriever = SecureRetriever(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(RetrievalError) as excinfo:
        retriever.fetch("https://example.com/start")
    assert excinfo.value.status == SourceStatus.RETRIEVAL_BLOCKED
    retriever.close()


def test_redirect_loop_terminates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://example.com/next"})

    retriever = SecureRetriever(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(RetrievalError) as excinfo:
        retriever.fetch("https://example.com/start")
    assert excinfo.value.status == SourceStatus.ERROR
    assert excinfo.value.reason == "too_many_redirects"
    retriever.close()


def test_oversized_response_rejected() -> None:
    big = b"a" * (2 * 1024 * 1024)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, content=big)

    retriever = SecureRetriever(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(RetrievalError) as excinfo:
        retriever.fetch("https://example.com/big")
    assert excinfo.value.status == SourceStatus.TOO_LARGE
    retriever.close()


def test_unsupported_content_type_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/zip"}, content=b"x")

    retriever = SecureRetriever(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(RetrievalError) as excinfo:
        retriever.fetch("https://example.com/file")
    assert excinfo.value.status == SourceStatus.UNSUPPORTED_TYPE
    retriever.close()


def test_decompression_bomb_defense() -> None:
    """A tiny gzip that expands past the cap is aborted while reading."""
    payload = gzip.compress(b"a" * (5 * 1024 * 1024))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html", "content-encoding": "gzip"},
            content=payload,
        )

    retriever = SecureRetriever(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(RetrievalError) as excinfo:
        retriever.fetch("https://example.com/bomb")
    assert excinfo.value.status == SourceStatus.TOO_LARGE
    retriever.close()


def test_read_capped_direct() -> None:
    resp = httpx.Response(200, content=b"x" * 100)
    with pytest.raises(ResponseTooLarge):
        read_capped(resp, 10)
