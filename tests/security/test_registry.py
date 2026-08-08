"""Remediation-registry governance and safety (spec sections 16, 28, 30, 42).

A poisoned registry could send a user to a phishing site, so loading must reject
provenance-free or unsafe entries.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from exposure.remediation import load_registry
from exposure.remediation.registry import RegistryEntry, _load_from_path

_GOOD = """
id: {id}
provider: Test
route_type: SEARCH_DELIST
destination_kind: provider_portal
jurisdictions: [GLOBAL]
applies_to: [CONTACT_EMAIL]
official_url: "{url}"
last_verified: 2026-08-01
expires_after_days: 180
sources: {sources}
"""


def _write(dir: Path, name: str, content: str) -> None:
    (dir / name).write_text(content, encoding="utf-8")


def test_packaged_registry_loads_and_has_provenance() -> None:
    reg = load_registry()
    assert len(reg) >= 5
    for entry in reg.all(include_expired=True):
        assert entry.sources, f"{entry.id} has no provenance source"
        assert not entry.is_expired(), f"{entry.id} is expired — revalidate"


def test_required_routes_present() -> None:
    reg = load_registry()
    ids = {e.id for e in reg.all()}
    for required in (
        "google_personal_info",
        "california_drop",
        "generic_gdpr_erasure",
        "generic_publisher_contact",
        "user_controlled_remove",
    ):
        assert required in ids


def test_entry_without_sources_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "bad.yaml", _GOOD.format(id="x", url="https://ok.example", sources="[]"))
    with pytest.raises(ValidationError):
        _load_from_path(tmp_path)


def test_entry_with_unsafe_url_is_rejected(tmp_path: Path) -> None:
    _write(
        tmp_path, "bad.yaml",
        _GOOD.format(id="x", url="http://169.254.169.254/", sources='["https://ok.example"]'),
    )
    with pytest.raises(ValidationError):
        _load_from_path(tmp_path)


def test_duplicate_ids_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "a.yaml", _GOOD.format(id="dup", url="https://a.example", sources='["https://s"]'))
    _write(tmp_path, "b.yaml", _GOOD.format(id="dup", url="https://b.example", sources='["https://s"]'))
    with pytest.raises(ValueError, match="duplicate"):
        _load_from_path(tmp_path)


def test_expiry_logic() -> None:
    entry = RegistryEntry(
        id="e", provider="p", route_type="SEARCH_DELIST", destination_kind="provider_portal",
        jurisdictions=["GLOBAL"], applies_to=["CONTACT_EMAIL"], official_url="https://ok.example",
        last_verified=date(2020, 1, 1), expires_after_days=180, sources=["https://ok.example"],
    )
    assert entry.is_expired()
    fresh = entry.model_copy(update={"last_verified": date.today() - timedelta(days=10)})
    assert not fresh.is_expired()
