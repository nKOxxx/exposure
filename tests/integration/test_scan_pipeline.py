"""End-to-end scan pipeline, offline, via a mocked retriever."""

from __future__ import annotations

import httpx

from exposure.app.schemas import SubjectCreate
from exposure.app.service import Service
from exposure.config import Settings
from exposure.domain.enums import MatchState
from exposure.storage.database import Database
from tests.conftest import make_mock_retriever_factory

PROFILE_HTML = """
<html><head><title>Jane Example — Acme Corp</title></head>
<body>
<p>Jane Example, CFO at Acme Corp, London.</p>
<p>Email jane@example.com, phone +44 20 7946 0958.</p>
<p>Home: 221 Baker Street London</p>
</body></html>
"""

NAMESAKE_HTML = """
<html><head><title>Jane Example</title></head>
<body><p>Jane Example is a marine biologist based in Sydney, Australia.</p></body></html>
"""


def _handler(request: httpx.Request) -> httpx.Response:
    path = str(request.url)
    if "profile" in path:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=PROFILE_HTML)
    if "namesake" in path:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=NAMESAKE_HTML)
    return httpx.Response(404)


def _service(settings: Settings, db: Database) -> Service:
    return Service(settings, db, retriever_factory=make_mock_retriever_factory(_handler))


def test_full_scan_creates_findings(settings: Settings, db: Database) -> None:
    svc = _service(settings, db)
    subject = svc.create_subject(
        SubjectCreate(
            name="Jane Example",
            city="London",
            country="UK",
            employers=["Acme Corp"],
            emails=["jane@example.com"],
        )
    )
    from exposure.app.schemas import ScanCreate

    scan_id, stats = svc.start_scan(
        subject.id,
        ScanCreate(
            use_search=False,
            manual_urls=[
                "https://broker.example/profile/jane",
                "https://news.example/namesake/story",
            ],
        ),
    )
    scan = svc.get_scan(scan_id)
    assert scan["status"] == "COMPLETE"
    assert stats.retrieved == 2

    findings = svc.list_findings(subject.id)
    cats = {f["category"] for f in findings}
    # The profile (email match => HIGH_CONFIDENCE) yields real findings.
    assert "CONTACT_EMAIL" in cats
    assert "HOME_ADDRESS" in cats
    # HOME_ADDRESS should be high priority (address + phone on the same page).
    addr = next(f for f in findings if f["category"] == "HOME_ADDRESS")
    assert addr["identity_state"] == MatchState.HIGH_CONFIDENCE.value
    assert addr["priority"] in ("HIGH", "CRITICAL")


def test_namesake_is_not_high_confidence(settings: Settings, db: Database) -> None:
    """A same-name person in a different city must not be auto-confirmed."""
    svc = _service(settings, db)
    subject = svc.create_subject(SubjectCreate(name="Jane Example", city="London", country="UK"))
    from exposure.app.schemas import ScanCreate

    svc.start_scan(subject.id, ScanCreate(manual_urls=["https://news.example/namesake/story"]))
    findings = svc.list_findings(subject.id)
    # Either no findings, or all flagged needs-review — never HIGH_CONFIDENCE.
    assert all(f["identity_state"] != "HIGH_CONFIDENCE" for f in findings)


def test_blocked_url_is_recorded_not_dropped(settings: Settings, db: Database) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=PROFILE_HTML)

    svc = Service(settings, db, retriever_factory=make_mock_retriever_factory(handler))
    subject = svc.create_subject(SubjectCreate(name="Jane Example"))
    from exposure.app.schemas import ScanCreate

    # A private URL must be blocked and counted, not silently ignored.
    _, stats = svc.start_scan(
        subject.id, ScanCreate(manual_urls=["http://169.254.169.254/", "https://ok.example/profile"])
    )
    assert stats.blocked >= 1
