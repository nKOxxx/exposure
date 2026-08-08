"""Local application security: Host/Origin/CSRF and headers (spec sections 20, 30)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from exposure.app.main import create_app
from exposure.app.service import Service
from exposure.config import Settings
from exposure.security.session import SessionGuard
from exposure.storage.database import Database


@pytest.fixture
def guarded(settings: Settings, db: Database):
    svc = Service(settings, db)
    guard = SessionGuard(settings.host, settings.port)
    app = create_app(settings, svc, guard)
    client = TestClient(app, base_url=f"http://127.0.0.1:{settings.port}")
    return client, guard


def test_index_injects_token_and_sets_csp(guarded) -> None:
    client, guard = guarded
    r = client.get("/")
    assert r.status_code == 200
    assert guard.token in r.text and "%%SESSION_TOKEN%%" not in r.text
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self' 'unsafe-inline'" in csp
    # No external origins allowed in connect-src.
    assert "http://" not in csp and "https://" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"


def test_bad_host_rejected(guarded) -> None:
    client, guard = guarded
    r = client.get("/api/v1/health", headers={"host": "evil.example", "x-exposure-session": guard.token})
    assert r.status_code == 403
    assert r.json()["error"] == "forbidden:bad_host"


def test_mutation_requires_token(guarded) -> None:
    client, _ = guarded
    r = client.post("/api/v1/subjects", json={"name": "X"})
    assert r.status_code == 403
    assert r.json()["error"] == "forbidden:bad_session"


def test_mutation_rejects_wrong_token(guarded) -> None:
    client, _ = guarded
    r = client.post("/api/v1/subjects", json={"name": "X"}, headers={"x-exposure-session": "nope"})
    assert r.status_code == 403


def test_mutation_rejects_cross_origin(guarded) -> None:
    client, guard = guarded
    r = client.post(
        "/api/v1/subjects",
        json={"name": "X"},
        headers={"x-exposure-session": guard.token, "origin": "https://evil.example"},
    )
    assert r.status_code == 403
    assert r.json()["error"] == "forbidden:bad_origin"


def test_valid_mutation_succeeds(guarded) -> None:
    client, guard = guarded
    r = client.post(
        "/api/v1/subjects",
        json={"name": "Jane"},
        headers={
            "x-exposure-session": guard.token,
            "origin": f"http://127.0.0.1:{client.base_url.port}",
        },
    )
    assert r.status_code == 200


def test_no_arbitrary_fetch_endpoint(guarded) -> None:
    client, guard = guarded
    # The spec forbids a generic /fetch?url= crawler endpoint.
    r = client.get("/api/v1/fetch?url=http://169.254.169.254/",
                   headers={"x-exposure-session": guard.token})
    assert r.status_code == 404
