"""App wiring, export edge cases, and registry loading fallbacks."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from exposure.app.main import create_app
from exposure.config import Settings
from exposure.export import build_report, render_html
from exposure.extraction import extract_document
from exposure.remediation.registry import load_registry
from exposure.storage.database import Database


def test_create_app_builds_its_own_dependencies(tmp_path: Path) -> None:
    """create_app() with no service/guard wires a working app on its own."""
    settings = Settings(workspace=tmp_path / "ws", port=8877)
    app = create_app(settings)
    client = TestClient(app, base_url="http://127.0.0.1:8877")
    token = app.state.guard.token
    assert client.get("/api/v1/health", headers={"X-Exposure-Session": token}).status_code == 200
    created = client.post(
        "/api/v1/subjects", json={"name": "Jane"}, headers={"X-Exposure-Session": token}
    )
    assert created.status_code == 200
    app.state.service.db.close()


def test_report_for_subject_with_no_findings(settings: Settings, db: Database) -> None:
    from exposure.domain.models import Name, Subject

    subject = db.create_subject(Subject(names=[Name(value="Jane", is_primary=True)]))
    report = build_report(db, subject.id)
    assert report["findings"] == [] and report["cases"] == []
    html = render_html(report)
    assert "No findings." in html
    assert "Delisting is not deletion" in html


def test_report_for_unknown_subject_raises(db: Database) -> None:
    with pytest.raises(ValueError, match="unknown subject"):
        build_report(db, "ghost")


def test_html_report_escapes_hostile_content(settings: Settings, db: Database) -> None:
    """A hostile page title must not inject markup into the exported report."""
    report = {
        "generated_at": "2026-08-08T00:00:00+00:00",
        "subject": {"id": "s", "primary_name": "<script>alert(1)</script>", "created_at": "x"},
        "provenance": {"app": "0.2.0"},
        "summary": {"HIGH": 1, "MODERATE": 0, "LOW": 0, "needs_review": 0},
        "findings": [
            {
                "id": "f", "category": "HOME_ADDRESS", "priority": "HIGH",
                "dimensions": {}, "identity": {"state": "CONFIRMED", "confidence": 1.0},
                "explanation_codes": [], "summary": "<img src=x onerror=alert(1)>",
                "source": {"url": "https://e.com/p", "domain": "e.com",
                           "title": None, "retrieved_at": None},
            }
        ],
        "cases": [],
    }
    html = render_html(report)
    # Hostile markup survives only as inert escaped text, never as a live tag.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img" not in html
    assert "&lt;img" in html


def test_registry_loads_from_explicit_directory(tmp_path: Path) -> None:
    src = load_registry()
    assert len(src) >= 5
    # An empty directory yields an empty registry rather than raising.
    empty = load_registry(tmp_path)
    assert len(empty) == 0
    assert empty.for_category.__self__ is empty  # bound method sanity


def test_registry_missing_directory_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_registry("/nonexistent/registry/path")


def test_text_plain_latin1_fallback() -> None:
    body = "caf\xe9 j@e.com".encode("latin-1")
    result = extract_document("text/plain", body, None)
    assert any(i.value_normalized == "j@e.com" for i in result.items)
