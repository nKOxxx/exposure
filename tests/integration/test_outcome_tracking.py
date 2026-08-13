"""The outcome loop: re-check, detect reappearance, report what changed.

This is what separates a remediation tool from a scanner — a request was sent,
and the only honest way to know if it worked is to look again.
"""

from __future__ import annotations

import httpx
import pytest

from exposure.app.schemas import CaseCreate, CaseEvent, ScanCreate, SubjectCreate
from exposure.app.service import Service
from exposure.config import Settings
from exposure.domain.enums import CaseState
from exposure.storage.database import Database
from tests.conftest import make_mock_retriever_factory

WITH_DATA = (
    "<html><head><title>Profile</title></head><body>"
    "<p>Jane Example, London. jane@example.com</p></body></html>"
)
WITHOUT_DATA = "<html><head><title>Profile</title></head><body><p>Removed.</p></body></html>"


class _Page:
    """A page whose content the test can flip between checks."""

    def __init__(self) -> None:
        self.body = WITH_DATA

    def handler(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=self.body)


@pytest.fixture
def page() -> _Page:
    return _Page()


@pytest.fixture
def svc(settings: Settings, db: Database, page: _Page) -> Service:
    return Service(settings, db, retriever_factory=make_mock_retriever_factory(page.handler))


@pytest.fixture
def submitted_case(svc: Service):  # type: ignore[no-untyped-def]
    """A subject with one finding, escalated to 'I sent the request'."""
    subject = svc.create_subject(
        SubjectCreate(name="Jane Example", emails=["jane@example.com"])
    )
    svc.start_scan(subject.id, ScanCreate(manual_urls=["https://broker.example/p"]))
    finding_id = svc.list_findings(subject.id)[0]["id"]
    case_id = svc.create_case(CaseCreate(finding_id=finding_id))["case"]["id"]
    svc.add_case_event(case_id, CaseEvent(target_state="REQUEST_PREPARED"))
    svc.add_case_event(case_id, CaseEvent(target_state="USER_MARKED_SUBMITTED"))
    return subject, case_id


def test_recheck_reports_nothing_when_page_unchanged(
    svc: Service, submitted_case
) -> None:  # type: ignore[no-untyped-def]
    result = svc.recheck_all()
    assert result["checked"] == 1
    assert result["resolved"] == 0
    # Still there: must never be reported as removed.
    assert svc.get_case(submitted_case[1])["state"] != CaseState.VERIFIED.value


def test_recheck_detects_removal(
    svc: Service, page: _Page, submitted_case
) -> None:  # type: ignore[no-untyped-def]
    _, case_id = submitted_case
    page.body = WITHOUT_DATA  # the site honoured the request

    result = svc.recheck_all()
    assert result["resolved"] == 1
    assert result["changes"][0]["good"] is True
    assert svc.get_case(case_id)["state"] == CaseState.VERIFIED.value


def test_recheck_detects_reappearance(
    svc: Service, page: _Page, submitted_case
) -> None:  # type: ignore[no-untyped-def]
    """Data that came back is the failure mode removal services are faulted for."""
    _, case_id = submitted_case

    page.body = WITHOUT_DATA
    svc.recheck_all()
    assert svc.get_case(case_id)["state"] == CaseState.VERIFIED.value

    page.body = WITH_DATA  # it came back
    result = svc.recheck_all()
    assert result["reappeared"] == 1
    assert result["changes"][0]["bad"] is True
    assert svc.get_case(case_id)["state"] == CaseState.REAPPEARED.value


def test_recheck_skips_cases_with_nothing_pending(svc: Service) -> None:
    subject = svc.create_subject(SubjectCreate(name="Jane Example",
                                               emails=["jane@example.com"]))
    svc.start_scan(subject.id, ScanCreate(manual_urls=["https://broker.example/p"]))
    finding_id = svc.list_findings(subject.id)[0]["id"]
    svc.create_case(CaseCreate(finding_id=finding_id))  # never submitted
    assert svc.recheck_all()["checked"] == 0


def test_unreachable_page_is_not_counted_as_removed(
    settings: Settings, db: Database
) -> None:
    """A network failure must never read as success."""
    state = {"fail": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if state["fail"]:
            raise httpx.ConnectError("down")
        return httpx.Response(200, headers={"content-type": "text/html"}, text=WITH_DATA)

    svc = Service(settings, db, retriever_factory=make_mock_retriever_factory(handler))
    subject = svc.create_subject(SubjectCreate(name="Jane Example",
                                               emails=["jane@example.com"]))
    svc.start_scan(subject.id, ScanCreate(manual_urls=["https://broker.example/p"]))
    finding_id = svc.list_findings(subject.id)[0]["id"]
    case_id = svc.create_case(CaseCreate(finding_id=finding_id))["case"]["id"]
    svc.add_case_event(case_id, CaseEvent(target_state="REQUEST_PREPARED"))
    svc.add_case_event(case_id, CaseEvent(target_state="USER_MARKED_SUBMITTED"))

    state["fail"] = True
    result = svc.recheck_all()
    assert result["resolved"] == 0
    assert svc.get_case(case_id)["state"] != CaseState.VERIFIED.value


def test_scan_reports_new_pages(svc: Service) -> None:
    """A repeat scan distinguishes new pages from ones already known."""
    subject = svc.create_subject(SubjectCreate(name="Jane Example",
                                               emails=["jane@example.com"]))
    _, first = svc.start_scan(subject.id, ScanCreate(manual_urls=["https://a.example/p"]))
    assert first.new_pages == 1

    _, second = svc.start_scan(subject.id, ScanCreate(manual_urls=["https://a.example/p"]))
    assert second.new_pages == 0, "a page already known is not new"

    _, third = svc.start_scan(
        subject.id, ScanCreate(manual_urls=["https://a.example/p", "https://b.example/p"])
    )
    assert third.new_pages == 1


def test_cleanup_board_groups_by_stage(
    svc: Service, submitted_case
) -> None:  # type: ignore[no-untyped-def]
    board = svc.cleanup_board()
    assert board["total"] == 1
    assert board["counts"]["waiting"] == 1
    entry = board["lanes"]["waiting"][0]
    assert entry["next_label"]
    assert entry["domain"] == "broker.example"
