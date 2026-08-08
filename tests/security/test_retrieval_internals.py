"""Retrieval internals: network policy, limits, and client edge cases."""

from __future__ import annotations

import httpx
import pytest

from exposure.config import Settings
from exposure.domain.enums import SourceStatus
from exposure.retrieval.client import RetrievalError, SecureRetriever
from exposure.retrieval.limits import (
    cap_for,
    parse_content_type,
)
from exposure.retrieval.network_policy import (
    GuardedBackend,
    GuardedTransport,
    resolve_and_validate,
)
from exposure.security.validation import UrlPolicyError, registrable_domain

# --------------------------------------------------------------------------- #
# network policy
# --------------------------------------------------------------------------- #


def test_public_ip_literal_passes_through() -> None:
    assert resolve_and_validate("93.184.216.34", 443) == "93.184.216.34"


def test_blocked_hostname_rejected() -> None:
    for host in ("localhost", "foo.localhost", "metadata.google.internal"):
        with pytest.raises(UrlPolicyError, match="blocked_hostname"):
            resolve_and_validate(host, 80)


def test_blocked_ip_literal_rejected() -> None:
    with pytest.raises(UrlPolicyError, match="blocked_ip_literal"):
        resolve_and_validate("10.1.2.3", 80)


def test_dns_failure_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    import exposure.retrieval.network_policy as np

    def boom(host: str, port: int) -> list[str]:
        raise OSError("nxdomain")

    monkeypatch.setattr(np, "_getaddrinfo", boom)
    with pytest.raises(UrlPolicyError, match="dns_resolution_failed"):
        resolve_and_validate("nope.example", 443)


def test_dns_empty_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    import exposure.retrieval.network_policy as np

    monkeypatch.setattr(np, "_getaddrinfo", lambda h, p: [])
    with pytest.raises(UrlPolicyError, match="dns_no_records"):
        resolve_and_validate("empty.example", 443)


def test_guarded_backend_pins_to_validated_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """connect_tcp must be called with the resolved IP, not the hostname."""
    import exposure.retrieval.network_policy as np

    monkeypatch.setattr(np, "_getaddrinfo", lambda h, p: ["93.184.216.34"])
    seen: dict[str, object] = {}

    def fake_super_connect(self, host, port, timeout=None, local_address=None,
                           socket_options=None):  # type: ignore[no-untyped-def]
        seen["host"] = host
        seen["port"] = port
        return object()

    monkeypatch.setattr(np.httpcore.SyncBackend, "connect_tcp", fake_super_connect)
    GuardedBackend().connect_tcp("example.com", 443)
    assert seen == {"host": "93.184.216.34", "port": 443}


def test_guarded_backend_refuses_private_target(monkeypatch: pytest.MonkeyPatch) -> None:
    import exposure.retrieval.network_policy as np

    monkeypatch.setattr(np, "_getaddrinfo", lambda h, p: ["127.0.0.1"])
    with pytest.raises(UrlPolicyError):
        GuardedBackend().connect_tcp("rebind.example", 80)


def test_guarded_transport_installs_guarded_backend() -> None:
    transport = GuardedTransport()
    assert isinstance(transport._pool._network_backend, GuardedBackend)
    transport.close()


# --------------------------------------------------------------------------- #
# limits helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "header,expected",
    [
        ("text/html; charset=utf-8", "text/html"),
        ("TEXT/HTML", "text/html"),
        (None, ""),
        ("", ""),
    ],
)
def test_parse_content_type(header: str | None, expected: str) -> None:
    assert parse_content_type(header) == expected


def test_cap_for_pdf_vs_html() -> None:
    assert cap_for("application/pdf", 5, 15) == 15
    assert cap_for("text/html", 5, 15) == 5
    assert cap_for("", 5, 15) == 5


# --------------------------------------------------------------------------- #
# client edge cases
# --------------------------------------------------------------------------- #


def _retriever(handler) -> SecureRetriever:  # type: ignore[no-untyped-def]
    return SecureRetriever(
        Settings(max_html_bytes=4096, max_redirects=3),
        transport=httpx.MockTransport(handler),
    )


def test_relative_redirect_is_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<p>ok</p>")

    r = _retriever(handler)
    doc = r.fetch("https://example.com/start")
    assert doc.final_url.endswith("/final") and doc.status_code == 200
    r.close()


def test_redirect_without_location_is_an_error() -> None:
    r = _retriever(lambda req: httpx.Response(302))
    with pytest.raises(RetrievalError) as exc:
        r.fetch("https://example.com/x")
    assert exc.value.reason == "redirect_without_location"
    r.close()


def test_declared_content_length_over_cap_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html", "content-length": "999999"},
            content=b"x" * 10,
        )

    r = _retriever(handler)
    with pytest.raises(RetrievalError) as exc:
        r.fetch("https://example.com/big")
    assert exc.value.status == SourceStatus.TOO_LARGE and exc.value.reason == "content_length"
    r.close()


def test_timeout_is_reported_as_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    r = _retriever(handler)
    with pytest.raises(RetrievalError) as exc:
        r.fetch("https://example.com/slow")
    assert exc.value.status == SourceStatus.TIMEOUT
    r.close()


def test_transport_error_is_reported_as_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    r = _retriever(handler)
    with pytest.raises(RetrievalError) as exc:
        r.fetch("https://example.com/down")
    assert exc.value.status == SourceStatus.ERROR
    r.close()


def test_missing_content_type_is_accepted() -> None:
    r = _retriever(lambda req: httpx.Response(200, content=b"plain bytes"))
    doc = r.fetch("https://example.com/x")
    assert doc.content_type == "application/octet-stream"
    r.close()


def test_content_hash_is_stable() -> None:
    r = _retriever(
        lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text="<p>a</p>")
    )
    assert r.fetch("https://example.com/a").content_hash == r.fetch(
        "https://example.com/a"
    ).content_hash
    r.close()


def test_context_manager_closes() -> None:
    with _retriever(
        lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text="ok")
    ) as r:
        assert r.fetch("https://example.com/x").status_code == 200


def test_registrable_domain_reexport() -> None:
    assert registrable_domain("https://sub.example.co.uk/p") == "example.co.uk"
