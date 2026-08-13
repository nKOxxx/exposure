"""Scanner paths not covered by the happy-path pipeline test.

Covers the search-provider branch, per-scan budgets, deduplication, and the
"identity anchor required" rule.
"""

from __future__ import annotations

import httpx
import pytest

from exposure.config import Settings
from exposure.discovery.provider import ProviderError, SearchCandidate
from exposure.domain.models import LocationHint, Name, SecretField, Subject
from exposure.scanner import Scanner, ScanOptions
from exposure.security.redaction import mask_email
from exposure.storage.database import Database
from tests.conftest import make_mock_retriever_factory

PROFILE = (
    "<html><head><title>Jane Example</title></head><body>"
    "<p>Jane Example, London. jane@example.com</p></body></html>"
)
UNRELATED = "<html><head><title>Weather</title></head><body><p>It rained.</p></body></html>"


def _handler(request: httpx.Request) -> httpx.Response:
    body = UNRELATED if "unrelated" in str(request.url) else PROFILE
    return httpx.Response(200, headers={"content-type": "text/html"}, text=body)


class _StubProvider:
    id = "stub"

    def __init__(self, urls: list[str], fail: bool = False) -> None:
        self._urls = urls
        self._fail = fail
        self.queries: list[str] = []

    def search(self, query, limit):  # type: ignore[no-untyped-def]
        self.queries.append(query.text)
        if self._fail:
            raise ProviderError("stub_boom")
        return [SearchCandidate(url=u, provider=self.id, query=query.text)
                for u in self._urls[:limit]]


def _subject(db: Database) -> Subject:
    """Create and persist a subject (scans carry a foreign key to it)."""
    return db.create_subject(
        Subject(
            names=[Name(value="Jane Example", is_primary=True)],
            locations=[LocationHint(city="London", country="UK")],
            emails=[
                SecretField(value="jane@example.com", display=mask_email("jane@example.com"))
            ],
        )
    )


def _scanner(db: Database, settings: Settings) -> Scanner:
    return Scanner(db, settings, make_mock_retriever_factory(_handler))


def _install_provider(monkeypatch: pytest.MonkeyPatch, provider: _StubProvider) -> None:
    import exposure.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "BraveSearchProvider", lambda key: provider)


def test_search_path_runs_queries_and_marks_from_search(
    db: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    db.secrets.set_api_key("brave", "sk-test")
    provider = _StubProvider(["https://found.example/profile"])
    _install_provider(monkeypatch, provider)

    _, stats = _scanner(db, settings).run(_subject(db), ScanOptions(use_search=True))
    assert stats.queries_run > 0
    assert stats.retrieved == 1
    assert stats.findings > 0
    # Sensitive (email) queries are skipped unless explicitly opted in.
    assert stats.sensitive_skipped == 1
    assert all("jane@example.com" not in q for q in provider.queries)


def test_sensitive_queries_only_with_optin(
    db: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    db.secrets.set_api_key("brave", "sk-test")
    provider = _StubProvider(["https://found.example/profile"])
    _install_provider(monkeypatch, provider)

    _, stats = _scanner(db, settings).run(
        _subject(db), ScanOptions(use_search=True, include_sensitive=True)
    )
    assert stats.sensitive_skipped == 0
    assert any("jane@example.com" in q for q in provider.queries)


def test_provider_failure_marks_scan_incomplete(
    db: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    db.secrets.set_api_key("brave", "sk-test")
    _install_provider(monkeypatch, _StubProvider([], fail=True))

    scan_id, stats = _scanner(db, settings).run(_subject(db), ScanOptions(use_search=True))
    assert stats.provider_errors
    assert db.get_scan(scan_id)["status"] == "INCOMPLETE"


def test_provider_construction_failure_is_recorded(
    db: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    import exposure.scanner as scanner_mod

    db.secrets.set_api_key("brave", "sk-test")

    def boom(key: str):  # type: ignore[no-untyped-def]
        raise ProviderError("brave_unauthorized")

    monkeypatch.setattr(scanner_mod, "BraveSearchProvider", boom)
    _, stats = _scanner(db, settings).run(_subject(db), ScanOptions(use_search=True))
    assert "brave_unauthorized" in stats.provider_errors


def test_duplicate_urls_are_deduped(db: Database, settings: Settings) -> None:
    _, stats = _scanner(db, settings).run(
        _subject(db),
        ScanOptions(manual_urls=[
            "https://a.example/profile",
            "https://a.example/profile/",   # same canonical URL
            "https://a.example/profile?utm_source=x",
        ]),
    )
    assert stats.candidates == 1 and stats.retrieved == 1


def test_document_budget_is_enforced(db: Database, settings: Settings) -> None:
    settings.max_documents_per_scan = 2
    _, stats = _scanner(db, settings).run(
        _subject(db),
        ScanOptions(manual_urls=[f"https://x{i}.example/profile" for i in range(6)]),
    )
    assert stats.retrieved == 2


def test_byte_budget_is_enforced(db: Database, settings: Settings) -> None:
    settings.max_scan_bytes = 1  # first document immediately exhausts the budget
    _, stats = _scanner(db, settings).run(
        _subject(db),
        ScanOptions(manual_urls=[f"https://x{i}.example/profile" for i in range(4)]),
    )
    assert stats.retrieved == 1


def test_candidate_url_cap(db: Database, settings: Settings) -> None:
    settings.max_candidate_urls = 3
    _, stats = _scanner(db, settings).run(
        _subject(db),
        ScanOptions(manual_urls=[f"https://x{i}.example/profile" for i in range(10)]),
    )
    assert stats.candidates == 3


def test_source_without_identity_anchor_yields_no_findings(
    db: Database, settings: Settings
) -> None:
    scan_id, stats = _scanner(db, settings).run(
        _subject(db), ScanOptions(manual_urls=["https://unrelated.example/page"])
    )
    assert stats.retrieved == 1
    assert stats.findings == 0
    # The source is still recorded — failure is never silent absence.
    assert db.find_source_by_canonical(scan_id, "https://unrelated.example/page")


def test_malformed_candidate_url_is_skipped(db: Database, settings: Settings) -> None:
    _, stats = _scanner(db, settings).run(
        _subject(db), ScanOptions(manual_urls=["http://[oops", "https://ok.example/profile"])
    )
    assert stats.retrieved == 1


def test_scan_error_is_recorded_on_the_row(
    db: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner = _scanner(db, settings)

    def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("pipeline exploded")

    monkeypatch.setattr(scanner, "_gather_candidates", boom)
    subject = _subject(db)
    scan_id = scanner.begin(subject)
    with pytest.raises(RuntimeError):
        scanner.run_existing(scan_id, subject, ScanOptions())
    row = db.get_scan(scan_id)
    assert row["status"] == "ERROR" and row["error"] == "RuntimeError"


def test_stats_serialize_for_the_api(db: Database, settings: Settings) -> None:
    _, stats = _scanner(db, settings).run(
        _subject(db), ScanOptions(manual_urls=["https://a.example/profile"])
    )
    payload = stats.as_dict()
    assert set(payload) == {
        "queries_planned", "queries_run", "sensitive_skipped", "candidates",
        "retrieved", "rendered", "blocked", "failed", "bytes_downloaded",
        "findings", "provider_errors", "phase", "progress_pct",
    }
    # A finished scan reports 100% so the progress bar always completes.
    assert payload["phase"] == "done"
    assert payload["progress_pct"] == 100
