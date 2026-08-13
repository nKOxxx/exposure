"""Findings must be page-centric, show real values, and not double up."""

from __future__ import annotations

import httpx
import pytest

from exposure.app.schemas import ScanCreate, SubjectCreate
from exposure.app.service import Service
from exposure.config import Settings
from exposure.storage.database import Database
from tests.conftest import make_mock_retriever_factory

# One page that mentions the subject AND several other people, which is the
# normal shape of a real page.
PAGE = """
<html><head><title>Team page</title></head><body>
<p>Jane Example, London. Contact jane@example.com.</p>
<a href="https://github.com/janehandle">Jane</a>
<a href="https://github.com/someoneelse">Bob</a>
<a href="mailto:bob@other.example">Bob mail</a>
<p>221 Baker Street London</p>
</body></html>
"""


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html"}, text=PAGE)


@pytest.fixture
def svc(settings: Settings, db: Database) -> Service:
    return Service(settings, db, retriever_factory=make_mock_retriever_factory(_handler))


@pytest.fixture
def scanned(svc: Service):  # type: ignore[no-untyped-def]
    subject = svc.create_subject(
        SubjectCreate(
            name="Jane Example", city="London", country="UK",
            emails=["jane@example.com"], usernames=["janehandle"],
        )
    )
    svc.start_scan(subject.id, ScanCreate(manual_urls=["https://team.example/p"]))
    return subject


def test_only_the_subjects_own_identifiers_are_reported(
    svc: Service, scanned
) -> None:  # type: ignore[no-untyped-def]
    """Other people's handles and emails on the page must not be reported."""
    values = {
        item["value"]
        for page in svc.grouped_findings(scanned.id)
        for item in page["items"]
    }
    blob = " ".join(values).lower()
    assert "someoneelse" not in blob, "another person's username was reported as the subject's"
    assert "bob@other.example" not in blob
    assert "b•••@other.example" not in blob
    # The subject's own handle is still reported.
    assert any("janehandle" in v for v in values)


def test_findings_are_grouped_by_page_with_values(
    svc: Service, scanned
) -> None:  # type: ignore[no-untyped-def]
    pages = svc.grouped_findings(scanned.id)
    assert len(pages) == 1, "one scanned page should produce one card"
    page = pages[0]
    assert page["url"] == "https://team.example/p"
    assert page["domain"] == "team.example"
    assert page["title"]
    assert page["items"], "a card must show what was actually found"
    assert all({"label", "value", "category"} <= i.keys() for i in page["items"])
    assert len(page["finding_ids"]) >= 1


def test_sensitive_values_are_masked_in_cards(
    svc: Service, scanned
) -> None:  # type: ignore[no-untyped-def]
    for page in svc.grouped_findings(scanned.id):
        for item in page["items"]:
            if item["sensitive"]:
                assert item["value"] != "jane@example.com"


def test_rescanning_does_not_duplicate_findings(
    svc: Service, scanned
) -> None:  # type: ignore[no-untyped-def]
    before = len(svc.list_findings(scanned.id))
    svc.start_scan(scanned.id, ScanCreate(manual_urls=["https://team.example/p"]))
    after = len(svc.list_findings(scanned.id))
    assert after == before, "re-scanning the same page must supersede, not accumulate"
    assert len(svc.grouped_findings(scanned.id)) == 1


def test_unreviewed_pages_sort_first(svc: Service, scanned) -> None:  # type: ignore[no-untyped-def]
    pages = svc.grouped_findings(scanned.id)
    needs = [p["needs_review"] for p in pages]
    assert needs == sorted(needs, reverse=True)
