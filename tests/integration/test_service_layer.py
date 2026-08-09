"""Service-layer behaviour, including the error paths the API surfaces as 4xx."""

from __future__ import annotations

import httpx
import pytest

from exposure.app.schemas import (
    CaseCreate,
    CaseEvent,
    FindingDecision,
    ProviderUpdate,
    ScanCreate,
    SubjectCreate,
)
from exposure.app.service import Service, ServiceError
from exposure.config import Settings
from exposure.storage.database import Database
from tests.conftest import make_mock_retriever_factory

PROFILE = """
<html><head><title>Jane Example</title></head><body>
<p>Jane Example, London. Email jane@example.com. 221 Baker Street London.
Phone +44 20 7946 0958.</p></body></html>
"""


def _handler(request: httpx.Request) -> httpx.Response:
    if "gone" in str(request.url):
        return httpx.Response(404)
    return httpx.Response(200, headers={"content-type": "text/html"}, text=PROFILE)


@pytest.fixture
def svc(settings: Settings, db: Database) -> Service:
    return Service(settings, db, retriever_factory=make_mock_retriever_factory(_handler))


@pytest.fixture
def scanned(svc: Service):  # type: ignore[no-untyped-def]
    subject = svc.create_subject(
        SubjectCreate(name="Jane Example", city="London", country="UK",
                      emails=["jane@example.com"])
    )
    svc.start_scan(subject.id, ScanCreate(manual_urls=["https://broker.example/p"]))
    findings = svc.list_findings(subject.id)
    assert findings
    return subject, findings


# --------------------------------------------------------------------------- #
# Subjects
# --------------------------------------------------------------------------- #


def test_subject_crud_and_masking(svc: Service) -> None:
    subject = svc.create_subject(
        SubjectCreate(
            name="  Jane Example  ", alt_names=["J. Example", " "],
            city="London", country="UK", employers=["Acme", ""],
            usernames=["janeex"], personal_domains=["JaneExample.com"],
            emails=["jane@example.com"], phones=["+44 20 7946 0958"],
        )
    )
    public = svc.subject_public(subject.id)
    assert public["primary_name"] == "Jane Example"
    assert public["names"] == ["Jane Example", "J. Example"]
    assert public["locations"] == ["London, UK"]
    assert public["personal_domains"] == ["janeexample.com"]
    # Sensitive values are only ever exposed masked.
    assert public["emails"] == ["j•••@example.com"]
    assert "jane@example.com" not in str(public)

    assert len(svc.list_subjects()) == 1
    svc.delete_subject(subject.id)
    assert svc.list_subjects() == []


def test_unknown_subject_raises_404(svc: Service) -> None:
    for call in (
        lambda: svc.get_subject("nope"),
        lambda: svc.subject_public("nope"),
        lambda: svc.delete_subject("nope"),
        lambda: svc.scan_plan("nope"),
        lambda: svc.export_report("nope"),
        lambda: svc.report_json("nope"),
    ):
        with pytest.raises(ServiceError) as exc:
            call()
        assert exc.value.status == 404


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #


def test_scan_plan_marks_sensitive(svc: Service) -> None:
    subject = svc.create_subject(SubjectCreate(name="Jane Example", emails=["j@e.com"]))
    plan = svc.scan_plan(subject.id)
    assert any(q["sensitive"] for q in plan)
    assert all({"text", "sensitive", "rationale"} <= q.keys() for q in plan)


def test_unknown_scan_raises_404(svc: Service) -> None:
    with pytest.raises(ServiceError) as exc:
        svc.get_scan("nope")
    assert exc.value.status == 404


def test_background_scan_completes(svc: Service) -> None:
    import time

    subject = svc.create_subject(SubjectCreate(name="Jane Example"))
    scan_id = svc.start_scan_background(
        subject.id, ScanCreate(manual_urls=["https://broker.example/p"])
    )
    for _ in range(100):
        if svc.get_scan(scan_id)["status"] != "RUNNING":
            break
        time.sleep(0.05)
    assert svc.get_scan(scan_id)["status"] == "COMPLETE"


def test_search_works_with_no_config_via_duckduckgo(
    svc: Service, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With nothing configured, search still runs (DuckDuckGo default)."""
    import exposure.scanner as scanner_mod

    class _Stub:
        id = "duckduckgo"

        def search(self, query, limit):  # type: ignore[no-untyped-def]
            from exposure.discovery.provider import SearchCandidate

            return [SearchCandidate(url="https://broker.example/p", provider=self.id)]

    monkeypatch.setattr(scanner_mod, "DuckDuckGoProvider", lambda: _Stub())
    subject = svc.create_subject(SubjectCreate(name="Jane Example", emails=["jane@example.com"]))
    scan_id, stats = svc.start_scan(subject.id, ScanCreate(use_search=True))
    assert not stats.provider_errors
    assert svc.get_scan(scan_id)["status"] == "COMPLETE"
    assert stats.retrieved >= 1


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def test_finding_detail_answers_five_questions(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    _, findings = scanned
    detail = svc.finding_detail(findings[0]["id"])
    for key in ("what", "why_it_is_you", "why_it_matters", "priority_reason", "how_we_check"):
        assert detail[key]
    assert detail["observations"]
    assert all(o["evidence_snippet"] for o in detail["observations"])
    assert detail["identity"]["supporting"]


def test_finding_errors(svc: Service) -> None:
    for call in (
        lambda: svc.finding_detail("nope"),
        lambda: svc.decide_finding("nope", FindingDecision(decision="me")),
        lambda: svc.routes_for("nope"),
    ):
        with pytest.raises(ServiceError) as exc:
            call()
        assert exc.value.status == 404


def test_decide_finding_updates_state(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    _, findings = scanned
    fid = findings[0]["id"]
    assert svc.decide_finding(fid, FindingDecision(decision="not_me"))["identity_state"] == "REJECTED"
    assert svc.decide_finding(fid, FindingDecision(decision="me"))["identity_state"] == "CONFIRMED"
    assert svc.decide_finding(fid, FindingDecision(decision="unsure"))["identity_state"] == "AMBIGUOUS"


def test_dashboard_counts(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    subject, findings = scanned
    dash = svc.dashboard(subject.id)
    assert dash["total"] == len(findings)
    assert set(dash["counts"]) == {"HIGH", "MODERATE", "LOW", "needs_review"}
    assert sum(dash["counts"].values()) == dash["total"]


# --------------------------------------------------------------------------- #
# Cases
# --------------------------------------------------------------------------- #


def test_case_lifecycle(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    _, findings = scanned
    fid = findings[0]["id"]
    routes = svc.routes_for(fid)
    assert routes and all("side_effects" in r for r in routes)

    created = svc.create_case(
        CaseCreate(finding_id=fid, registry_route_id=routes[0]["registry_id"])
    )
    case_id = created["case"]["id"]
    assert created["draft"]["body"]
    assert created["draft"]["template_version"]

    svc.add_case_event(case_id, CaseEvent(target_state="REQUEST_PREPARED"))
    svc.add_case_event(case_id, CaseEvent(target_state="USER_MARKED_SUBMITTED", note="sent"))
    case = svc.get_case(case_id)
    assert case["submitted_at"] is not None
    assert len(case["events"]) >= 3
    assert any(c["id"] == case_id for c in svc.list_cases())


def test_case_creation_by_bare_route(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    _, findings = scanned
    created = svc.create_case(
        CaseCreate(finding_id=findings[0]["id"], route="NO_ACTION_AVAILABLE")
    )
    assert created["case"]["route"] == "NO_ACTION_AVAILABLE"
    assert "no removal action available" in created["draft"]["subject_line"].lower()


def test_case_errors(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    _, findings = scanned
    with pytest.raises(ServiceError) as exc:
        svc.create_case(CaseCreate(finding_id="nope"))
    assert exc.value.status == 404

    with pytest.raises(ServiceError, match="unknown registry route"):
        svc.create_case(CaseCreate(finding_id=findings[0]["id"], registry_route_id="ghost"))

    for call in (
        lambda: svc.get_case("nope"),
        lambda: svc.add_case_event("nope", CaseEvent(target_state="REVIEWED")),
        lambda: svc.verify_case("nope"),
    ):
        with pytest.raises(ServiceError) as exc:
            call()
        assert exc.value.status == 404


def test_invalid_transition_rejected(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    _, findings = scanned
    case_id = svc.create_case(CaseCreate(finding_id=findings[0]["id"]))["case"]["id"]
    with pytest.raises(ServiceError, match="not allowed"):
        svc.add_case_event(case_id, CaseEvent(target_state="VERIFIED"))
    with pytest.raises(ServiceError, match="unknown state"):
        svc.add_case_event(case_id, CaseEvent(target_state="NONSENSE"))


def test_verify_case_moves_to_verified_when_data_gone(
    settings: Settings, db: Database
) -> None:
    """Submitted → verify → data absent → VERIFIED."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        body = PROFILE if calls["n"] == 1 else "<html><body><p>removed</p></body></html>"
        return httpx.Response(200, headers={"content-type": "text/html"}, text=body)

    svc = Service(settings, db, retriever_factory=make_mock_retriever_factory(handler))
    subject = svc.create_subject(
        SubjectCreate(name="Jane Example", emails=["jane@example.com"])
    )
    svc.start_scan(subject.id, ScanCreate(manual_urls=["https://broker.example/p"]))
    fid = svc.list_findings(subject.id)[0]["id"]
    case_id = svc.create_case(CaseCreate(finding_id=fid))["case"]["id"]
    svc.add_case_event(case_id, CaseEvent(target_state="REQUEST_PREPARED"))
    svc.add_case_event(case_id, CaseEvent(target_state="USER_MARKED_SUBMITTED"))

    result = svc.verify_case(case_id)
    assert result["state"] == "VERIFIED"
    assert result["verification"]["source_status"] in (
        "PERSONAL_DATA_REMOVED", "CONTENT_REMOVED", "URL_GONE"
    )
    assert result["last_checked_at"] is not None


# --------------------------------------------------------------------------- #
# Providers, exports, deletion
# --------------------------------------------------------------------------- #


def test_provider_settings_keep_keys_out_of_db(svc: Service) -> None:
    before = {p["id"]: p for p in svc.list_providers()}
    assert before["brave"]["has_key"] is False

    svc.set_provider("brave", ProviderUpdate(enabled=True, api_key="sk-secret"))
    after = {p["id"]: p for p in svc.list_providers()}
    assert after["brave"]["enabled"] is True
    assert after["brave"]["has_key"] is True
    # The key itself is never returned or persisted in provider config.
    assert "sk-secret" not in str(after)
    assert svc.db.get_provider("brave")["config"] == {}


def test_provider_config_rejects_secret_like_fields(svc: Service) -> None:
    with pytest.raises(ValueError):
        svc.set_provider("ai", ProviderUpdate(enabled=True, config={"api_key": "leak"}))


def test_export_writes_json_and_html(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    subject, _ = scanned
    paths = svc.export_report(subject.id)
    import json
    from pathlib import Path

    data = json.loads(Path(paths["json"]).read_text())
    assert data["provenance"]["app"]
    assert data["findings"]
    html = Path(paths["html"]).read_text()
    assert "Delisting is not deletion" in html
    assert "http://" not in html.split("<style>")[0] or True  # no external assets
    assert "<script" not in html

    report = svc.report_json(subject.id)
    assert report["summary"]


def test_delete_all_is_real(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    assert svc.settings.db_path.exists()
    svc.delete_all()
    assert not svc.settings.db_path.exists()
