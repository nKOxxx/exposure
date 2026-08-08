"""The full v0.2 acceptance loop over the HTTP API (spec section 41), offline."""

from __future__ import annotations

import time

import httpx
import pytest
from fastapi.testclient import TestClient

from exposure.app.main import create_app
from exposure.app.service import Service
from exposure.config import Settings
from exposure.security.session import SessionGuard
from exposure.storage.database import Database
from tests.conftest import make_mock_retriever_factory

PROFILE_HTML = """
<html><head><title>Jane Example</title></head><body>
<p>Jane Example, London. Email jane@example.com. 221 Baker Street London.</p>
</body></html>
"""


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html"}, text=PROFILE_HTML)


@pytest.fixture
def client(settings: Settings, db: Database):
    svc = Service(settings, db, retriever_factory=make_mock_retriever_factory(_handler))
    guard = SessionGuard(settings.host, settings.port)
    app = create_app(settings, svc, guard)
    c = TestClient(app, base_url=f"http://127.0.0.1:{settings.port}")
    c.headers.update({"X-Exposure-Session": guard.token})
    return c


def test_acceptance_loop(client: TestClient) -> None:
    # Define myself
    r = client.post("/api/v1/subjects", json={"name": "Jane Example", "city": "London",
                                              "country": "UK", "emails": ["jane@example.com"]})
    assert r.status_code == 200
    sid = r.json()["id"]

    # Review what would leave my machine
    plan = client.get(f"/api/v1/subjects/{sid}/scan-plan").json()
    assert any('"Jane Example"' in q["text"] for q in plan)

    # Run scan (background) and poll to completion
    r = client.post(f"/api/v1/subjects/{sid}/scans",
                    json={"use_search": False, "manual_urls": ["https://broker.example/profile"]})
    scan_id = r.json()["scan_id"]
    for _ in range(100):
        scan = client.get(f"/api/v1/scans/{scan_id}").json()
        if scan["status"] != "RUNNING":
            break
        time.sleep(0.05)
    assert scan["status"] == "COMPLETE"

    # See findings
    findings = client.get(f"/api/v1/findings?subject_id={sid}").json()
    assert findings
    fid = findings[0]["id"]

    # Finding detail answers the five questions
    detail = client.get(f"/api/v1/findings/{fid}").json()
    for key in ("what", "why_it_is_you", "why_it_matters", "priority_reason", "how_we_check"):
        assert detail[key]

    # Confirm identity
    assert client.post(f"/api/v1/findings/{fid}/decision", json={"decision": "me"}).status_code == 200

    # Choose a remediation route
    routes = client.get(f"/api/v1/findings/{fid}/remediation-routes").json()
    assert routes
    route = routes[0]

    # Create a case and get a locally-generated draft
    case_resp = client.post("/api/v1/cases", json={"finding_id": fid,
                            "registry_route_id": route["registry_id"]}).json()
    case_id = case_resp["case"]["id"]
    assert case_resp["draft"]["body"]
    assert "not legal advice" in case_resp["draft"]["disclaimer"]

    # Mark submitted, then verify (re-fetch)
    client.post(f"/api/v1/cases/{case_id}/events", json={"target_state": "USER_MARKED_SUBMITTED"})
    v = client.post(f"/api/v1/cases/{case_id}/verify").json()
    assert "verification" in v

    # Export a local report
    exp = client.post(f"/api/v1/exports?subject_id={sid}").json()
    assert exp["json"].endswith(".json") and exp["html"].endswith(".html")

    # Delete everything
    assert client.post("/api/v1/danger/delete-all").status_code == 200


def test_reject_removes_from_actionable(client: TestClient) -> None:
    sid = client.post("/api/v1/subjects", json={"name": "Jane Example",
                      "emails": ["jane@example.com"]}).json()["id"]
    r = client.post(f"/api/v1/subjects/{sid}/scans",
                    json={"manual_urls": ["https://broker.example/profile"]})
    scan_id = r.json()["scan_id"]
    for _ in range(100):
        if client.get(f"/api/v1/scans/{scan_id}").json()["status"] != "RUNNING":
            break
        time.sleep(0.05)
    findings = client.get(f"/api/v1/findings?subject_id={sid}").json()
    fid = findings[0]["id"]
    client.post(f"/api/v1/findings/{fid}/decision", json={"decision": "not_me"})
    detail = client.get(f"/api/v1/findings/{fid}").json()
    assert detail["identity"]["state"] == "REJECTED"
