"""SessionGuard unit coverage (Host / Origin / token decisions)."""

from __future__ import annotations

import pytest

from exposure.security.session import SessionGuard


@pytest.fixture
def guard() -> SessionGuard:
    return SessionGuard("127.0.0.1", 8799)


def test_token_is_random_and_long() -> None:
    a, b = SessionGuard("127.0.0.1", 1).token, SessionGuard("127.0.0.1", 1).token
    assert a != b and len(a) >= 32


@pytest.mark.parametrize(
    "host,ok",
    [
        ("127.0.0.1:8799", True),
        ("localhost:8799", True),
        ("[::1]:8799", True),
        ("127.0.0.2:8799", True),      # any loopback literal on our port
        ("127.0.0.1:9999", False),     # wrong port
        ("evil.example:8799", False),
        ("127.0.0.1", False),          # no port
        ("", False),
        (None, False),
        ("127.0.0.1:notaport", False),
    ],
)
def test_host_validation(guard: SessionGuard, host: str | None, ok: bool) -> None:
    assert guard.host_ok(host) is ok


@pytest.mark.parametrize(
    "origin,ok",
    [
        (None, True),                                   # same-origin navigation
        ("http://127.0.0.1:8799", True),
        ("http://localhost:8799", True),
        ("http://[::1]:8799", True),
        ("null", False),
        ("https://evil.example", False),
        ("http://127.0.0.1:1234", False),               # wrong port
        ("https://127.0.0.1:8799", False),              # wrong scheme
        ("http://evil.example:8799", False),
    ],
)
def test_origin_validation(guard: SessionGuard, origin: str | None, ok: bool) -> None:
    assert guard.origin_ok(origin) is ok


def test_token_validation(guard: SessionGuard) -> None:
    assert guard.token_ok(guard.token) is True
    assert guard.token_ok("wrong") is False
    assert guard.token_ok(None) is False
    assert guard.token_ok("") is False


def test_get_requires_only_host(guard: SessionGuard) -> None:
    assert guard.check("GET", "127.0.0.1:8799", None, None) == (True, "ok")


def test_mutation_requires_origin_and_token(guard: SessionGuard) -> None:
    assert guard.check("POST", "127.0.0.1:8799", None, None)[1] == "bad_session"
    assert guard.check(
        "POST", "127.0.0.1:8799", "https://evil.example", guard.token
    )[1] == "bad_origin"
    assert guard.check("POST", "127.0.0.1:8799", None, guard.token) == (True, "ok")
    assert guard.check(
        "POST", "127.0.0.1:8799", "http://127.0.0.1:8799", guard.token
    ) == (True, "ok")


def test_bad_host_short_circuits(guard: SessionGuard) -> None:
    assert guard.check("GET", "evil.example:8799", None, guard.token)[1] == "bad_host"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "delete"])
def test_all_mutating_methods_are_guarded(guard: SessionGuard, method: str) -> None:
    assert guard.check(method, "127.0.0.1:8799", None, None)[0] is False


def test_explicit_token_can_be_supplied() -> None:
    g = SessionGuard("127.0.0.1", 1, token="fixed-token")
    assert g.token == "fixed-token" and g.token_ok("fixed-token")
