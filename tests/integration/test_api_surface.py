"""Every API endpoint is reachable and returns the documented shape."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from exposure.app.main import create_app
from exposure.app.service import Service
from exposure.config import Settings
from exposure.security.session import SessionGuard
from exposure.storage.database import Database
from tests.conftest import make_mock_retriever_factory

PROFILE = """
<html><head><title>Jane Example</title></head><body>
<p>Jane Example, London. jane@example.com. 221 Baker Street London.</p>
</body></html>
"""


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html"}, text=PROFILE)


@pytest.fixture
def client(settings: Settings, db: Database) -> TestClient:
    svc = Service(settings, db, retriever_factory=make_mock_retriever_factory(_handler))
    guard = SessionGuard(settings.host, settings.port)
    app = create_app(settings, svc, guard)
    c = TestClient(app, base_url=f"http://127.0.0.1:{settings.port}")
    c.headers.update({"X-Exposure-Session": guard.token})
    return c


@pytest.fixture
def seeded(client: TestClient):  # type: ignore[no-untyped-def]
    import time

    sid = client.post(
        "/api/v1/subjects",
        json={"name": "Jane Example", "city": "London", "country": "UK",
              "emails": ["jane@example.com"]},
    ).json()["id"]
    scan_id = client.post(
        f"/api/v1/subjects/{sid}/scans", json={"manual_urls": ["https://b.example/p"]}
    ).json()["scan_id"]
    for _ in range(100):
        if client.get(f"/api/v1/scans/{scan_id}").json()["status"] != "RUNNING":
            break
        time.sleep(0.05)
    findings = client.get(f"/api/v1/findings?subject_id={sid}").json()
    return sid, findings


def test_health(client: TestClient) -> None:
    assert client.get("/api/v1/health").json() == {"status": "ok"}


def test_subject_endpoints(client: TestClient) -> None:
    created = client.post("/api/v1/subjects", json={"name": "Jane Example"})
    assert created.status_code == 200
    sid = created.json()["id"]

    assert client.get("/api/v1/subjects").json()[0]["id"] == sid
    assert client.get(f"/api/v1/subjects/{sid}").json()["primary_name"] == "Jane Example"
    assert client.get(f"/api/v1/subjects/{sid}/dashboard").json()["total"] == 0
    assert client.get(f"/api/v1/subjects/{sid}/scan-plan").json()
    assert client.delete(f"/api/v1/subjects/{sid}").json() == {"deleted": sid}
    assert client.get(f"/api/v1/subjects/{sid}").status_code == 404


def test_findings_endpoints(client: TestClient, seeded) -> None:  # type: ignore[no-untyped-def]
    sid, findings = seeded
    assert findings
    fid = findings[0]["id"]

    assert client.get("/api/v1/findings").status_code == 200
    assert client.get(f"/api/v1/findings/{fid}").json()["what"]
    assert client.get(f"/api/v1/findings/{fid}/remediation-routes").json()
    assert client.post(
        f"/api/v1/findings/{fid}/decision", json={"decision": "me"}
    ).json()["identity_state"] == "CONFIRMED"
    assert client.get("/api/v1/findings/ghost").status_code == 404


def test_case_endpoints(client: TestClient, seeded) -> None:  # type: ignore[no-untyped-def]
    _, findings = seeded
    fid = findings[0]["id"]
    routes = client.get(f"/api/v1/findings/{fid}/remediation-routes").json()

    created = client.post(
        "/api/v1/cases",
        json={"finding_id": fid, "registry_route_id": routes[0]["registry_id"]},
    ).json()
    cid = created["case"]["id"]

    assert client.get("/api/v1/cases").json()
    assert client.get(f"/api/v1/cases/{cid}").json()["id"] == cid
    assert client.post(
        f"/api/v1/cases/{cid}/events", json={"target_state": "REQUEST_PREPARED"}
    ).status_code == 200
    assert client.post(f"/api/v1/cases/{cid}/verify").status_code == 200
    # Invalid transition surfaces as a 400, not a 500.
    assert client.post(
        f"/api/v1/cases/{cid}/events", json={"target_state": "DISCOVERED"}
    ).status_code == 400


def test_provider_endpoints(client: TestClient) -> None:
    listed = client.get("/api/v1/settings/providers").json()
    assert {p["id"] for p in listed} == {"brave", "ai"}

    updated = client.put(
        "/api/v1/settings/providers/brave", json={"enabled": True, "api_key": "sk-x"}
    ).json()
    assert updated["enabled"] is True and updated["has_key"] is True
    assert "sk-x" not in str(updated)


def test_export_endpoints(client: TestClient, seeded) -> None:  # type: ignore[no-untyped-def]
    sid, _ = seeded
    written = client.post(f"/api/v1/exports?subject_id={sid}").json()
    assert written["json"].endswith(".json")
    report = client.get(f"/api/v1/exports/report?subject_id={sid}").json()
    assert report["provenance"]["app"] and report["findings"]


def test_delete_all_endpoint(client: TestClient, seeded) -> None:  # type: ignore[no-untyped-def]
    assert client.post("/api/v1/danger/delete-all").json() == {"deleted": "all"}


def test_validation_error_is_422(client: TestClient) -> None:
    assert client.post("/api/v1/subjects", json={}).status_code == 422
    assert client.post("/api/v1/subjects", json={"name": "x", "bogus": 1}).status_code == 422


def test_unknown_route_is_404(client: TestClient) -> None:
    assert client.get("/api/v1/nope").status_code == 404
