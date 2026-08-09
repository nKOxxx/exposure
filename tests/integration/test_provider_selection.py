"""Which search provider a scan uses, and how a missing one is reported."""

from __future__ import annotations

import httpx
import pytest

from exposure.app.schemas import ProviderUpdate, ScanCreate, SubjectCreate
from exposure.app.service import Service, ServiceError
from exposure.config import Settings
from exposure.discovery.provider import ProviderError
from exposure.discovery.providers import (
    BraveSearchProvider,
    DuckDuckGoProvider,
    SearXNGProvider,
)
from exposure.domain.models import Name, Subject
from exposure.scanner import Scanner, ScanOptions
from exposure.storage.database import Database
from tests.conftest import make_mock_retriever_factory


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html"},
                          text="<html><head><title>x</title></head><body>x</body></html>")


def _scanner(db: Database, settings: Settings) -> Scanner:
    return Scanner(db, settings, make_mock_retriever_factory(_handler))


def _subject(db: Database) -> Subject:
    return db.create_subject(Subject(names=[Name(value="Jane Example", is_primary=True)]))


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #


def test_defaults_to_duckduckgo_with_nothing_configured(
    db: Database, settings: Settings
) -> None:
    """Search must work out of the box: DuckDuckGo is the keyless default."""
    assert isinstance(_scanner(db, settings)._select_provider(), DuckDuckGoProvider)


def test_brave_used_when_key_present(db: Database, settings: Settings) -> None:
    db.secrets.set_api_key("brave", "sk-test")
    assert isinstance(_scanner(db, settings)._select_provider(), BraveSearchProvider)


def test_searxng_preferred_over_brave(db: Database, settings: Settings) -> None:
    """Keyless and self-hostable wins over the paid third-party API."""
    db.secrets.set_api_key("brave", "sk-test")
    db.set_provider("searxng", "search", True, {"base_url": "http://127.0.0.1:8888"})
    assert isinstance(_scanner(db, settings)._select_provider(), SearXNGProvider)


def test_disabled_searxng_falls_back_to_brave(db: Database, settings: Settings) -> None:
    db.secrets.set_api_key("brave", "sk-test")
    db.set_provider("searxng", "search", False, {"base_url": "http://127.0.0.1:8888"})
    assert isinstance(_scanner(db, settings)._select_provider(), BraveSearchProvider)


def test_enabled_searxng_without_url_is_an_explicit_error(
    db: Database, settings: Settings
) -> None:
    db.set_provider("searxng", "search", True, {})
    with pytest.raises(ProviderError, match="searxng_url_missing"):
        _scanner(db, settings)._select_provider()


def test_duckduckgo_rate_limit_reports_incomplete(
    db: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rate-limited default provider must read as incomplete, not 'no findings'."""
    import exposure.scanner as scanner_mod

    class _RateLimited:
        id = "duckduckgo"

        def search(self, query, limit):  # type: ignore[no-untyped-def]
            raise ProviderError("duckduckgo_rate_limited")

    monkeypatch.setattr(scanner_mod, "DuckDuckGoProvider", lambda: _RateLimited())
    scan_id, stats = _scanner(db, settings).run(_subject(db), ScanOptions(use_search=True))
    assert "duckduckgo_rate_limited" in stats.provider_errors
    assert db.get_scan(scan_id)["status"] == "INCOMPLETE"


def test_duckduckgo_results_flow_into_a_scan(
    db: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    import exposure.scanner as scanner_mod

    class _Stub:
        id = "duckduckgo"

        def search(self, query, limit):  # type: ignore[no-untyped-def]
            from exposure.discovery.provider import SearchCandidate

            return [SearchCandidate(url="https://found.example/p", provider=self.id)]

    monkeypatch.setattr(scanner_mod, "DuckDuckGoProvider", lambda: _Stub())
    _, stats = _scanner(db, settings).run(_subject(db), ScanOptions(use_search=True))
    assert stats.queries_run > 0 and stats.retrieved == 1
    assert not stats.provider_errors


def test_searxng_results_flow_into_a_scan(
    db: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    import exposure.scanner as scanner_mod

    class _Stub:
        id = "searxng"

        def search(self, query, limit):  # type: ignore[no-untyped-def]
            from exposure.discovery.provider import SearchCandidate

            return [SearchCandidate(url="https://found.example/p", provider=self.id)]

    monkeypatch.setattr(scanner_mod, "SearXNGProvider", lambda url: _Stub())
    db.set_provider("searxng", "search", True, {"base_url": "http://127.0.0.1:8888"})

    _, stats = _scanner(db, settings).run(_subject(db), ScanOptions(use_search=True))
    assert stats.queries_run > 0 and stats.retrieved == 1
    assert not stats.provider_errors


# --------------------------------------------------------------------------- #
# Settings surface
# --------------------------------------------------------------------------- #


def test_providers_listed_with_key_requirement(service: Service) -> None:
    provs = {p["id"]: p for p in service.list_providers()}
    assert set(provs) == {"duckduckgo", "searxng", "brave", "ai"}
    assert provs["duckduckgo"]["always_available"] is True
    assert provs["duckduckgo"]["needs_key"] is False
    assert provs["searxng"]["needs_key"] is False
    assert provs["brave"]["needs_key"] is True


def test_active_provider_defaults_to_duckduckgo(service: Service) -> None:
    assert service.active_search_provider() == "duckduckgo"


def test_active_provider_prefers_brave_key(service: Service) -> None:
    service.db.secrets.set_api_key("brave", "sk-test")
    assert service.active_search_provider() == "brave"


def test_configuring_searxng_persists_url(service: Service) -> None:
    service.set_provider(
        "searxng", ProviderUpdate(enabled=True, config={"base_url": "http://127.0.0.1:8888/"})
    )
    provs = {p["id"]: p for p in service.list_providers()}
    assert provs["searxng"]["enabled"] is True
    assert provs["searxng"]["config"]["base_url"] == "http://127.0.0.1:8888"  # normalized


def test_bad_searxng_url_is_rejected_at_configuration_time(service: Service) -> None:
    for bad in ("", "ftp://nope", "not a url"):
        with pytest.raises(ServiceError) as exc:
            service.set_provider("searxng", ProviderUpdate(enabled=True,
                                                           config={"base_url": bad}))
        assert exc.value.status == 400


def test_disabling_searxng_skips_url_validation(service: Service) -> None:
    result = service.set_provider("searxng", ProviderUpdate(enabled=False, config={}))
    assert result["enabled"] is False


def test_searxng_url_is_not_treated_as_a_secret(service: Service) -> None:
    """It is configuration, not a credential — it belongs in the database."""
    service.set_provider(
        "searxng", ProviderUpdate(enabled=True, config={"base_url": "http://127.0.0.1:8888"})
    )
    stored = service.db.get_provider("searxng")
    assert stored is not None
    assert stored["config"]["base_url"] == "http://127.0.0.1:8888"


def test_scan_via_api_uses_duckduckgo_by_default(
    service: Service, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With nothing configured, an API-triggered scan still searches (via DDG)."""
    import exposure.scanner as scanner_mod

    class _Stub:
        id = "duckduckgo"

        def search(self, query, limit):  # type: ignore[no-untyped-def]
            from exposure.discovery.provider import SearchCandidate

            return [SearchCandidate(url="https://found.example/p", provider=self.id)]

    monkeypatch.setattr(scanner_mod, "DuckDuckGoProvider", lambda: _Stub())
    subject = service.create_subject(SubjectCreate(name="Jane Example"))
    _, stats = service.start_scan(subject.id, ScanCreate(use_search=True))
    assert stats.queries_run > 0
    assert not stats.provider_errors
