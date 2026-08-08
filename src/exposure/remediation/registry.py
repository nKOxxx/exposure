"""Remediation registry: load and validate removal-route definitions.

The registry is a first-class, governed subsystem (spec section 16). Every entry
must carry an authoritative source and a ``last_verified`` date. A poisoned
registry could direct a user to a phishing site, so loading validates strictly
and refuses malformed or provenance-free entries.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from exposure import REGISTRY_VERSION
from exposure.domain.enums import FindingCategory, RemediationRoute
from exposure.security.validation import UrlPolicyError, validate_url_syntax

_REGISTRY_ANCHOR = "exposure"  # packaged copy lives at exposure/registry


class RegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    provider: str
    route_type: RemediationRoute
    destination_kind: str
    jurisdictions: list[str] = Field(min_length=1)
    applies_to: list[FindingCategory] = Field(min_length=1)
    official_url: str = ""
    portal_url: str | None = None
    verification: dict[str, Any] = Field(default_factory=dict)
    required_inputs: list[str] = Field(default_factory=list)
    side_effects: str = ""
    informational: bool = True
    description: str = ""
    last_verified: date
    expires_after_days: int = 180
    sources: list[str] = Field(default_factory=list)

    @field_validator("official_url", "portal_url")
    @classmethod
    def _urls_must_be_safe(cls, v: str | None) -> str | None:
        if not v:
            return v
        try:
            validate_url_syntax(v)
        except UrlPolicyError as exc:
            raise ValueError(f"unsafe registry URL: {v} ({exc})") from exc
        return v

    @field_validator("sources")
    @classmethod
    def _sources_present_for_provenance(cls, v: list[str]) -> list[str]:
        # Provenance is mandatory (hard release gate): a route without an
        # authoritative source must never be recommended.
        if not v:
            raise ValueError("registry entry requires at least one source (provenance)")
        for s in v:
            validate_url_syntax(s)
        return v

    def is_expired(self, today: date | None = None) -> bool:
        today = today or datetime.now(UTC).date()
        age_days = (today - self.last_verified).days
        return age_days > self.expires_after_days


class Registry:
    def __init__(self, entries: dict[str, RegistryEntry]) -> None:
        self._entries = entries
        self.version = REGISTRY_VERSION

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, entry_id: str) -> RegistryEntry | None:
        return self._entries.get(entry_id)

    def all(self, include_expired: bool = False) -> list[RegistryEntry]:
        entries = list(self._entries.values())
        if include_expired:
            return entries
        return [e for e in entries if not e.is_expired()]

    def for_category(
        self, category: FindingCategory, include_expired: bool = False
    ) -> list[RegistryEntry]:
        return [e for e in self.all(include_expired) if category in e.applies_to]


def _load_from_path(directory: Path) -> dict[str, RegistryEntry]:
    entries: dict[str, RegistryEntry] = {}
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        entry = RegistryEntry.model_validate(data)
        if entry.id in entries:
            raise ValueError(f"duplicate registry id: {entry.id} ({path.name})")
        entries[entry.id] = entry
    return entries


def _candidate_dirs() -> list[Path]:
    candidates: list[Path] = []
    # 1) Packaged copy inside the wheel: exposure/registry/
    try:
        anchor = resources.files(_REGISTRY_ANCHOR) / "registry"
        with resources.as_file(anchor) as p:
            candidates.append(Path(p))
    except (ModuleNotFoundError, FileNotFoundError):
        pass
    # 2) Repo-root registry/ for editable/dev installs
    import exposure

    pkg_file = Path(exposure.__file__).resolve()
    candidates.append(pkg_file.parents[2] / "registry")  # src/exposure/__init__.py -> repo root
    return candidates


def load_registry(directory: str | Path | None = None) -> Registry:
    """Load and validate the registry.

    If ``directory`` is given, load from there (used in tests). Otherwise try the
    packaged copy, then the repo-root ``registry/`` (editable installs).
    """
    if directory is not None:
        return Registry(_load_from_path(Path(directory)))
    for candidate in _candidate_dirs():
        if candidate.is_dir() and any(candidate.glob("*.yaml")):
            return Registry(_load_from_path(candidate))
    raise FileNotFoundError("no registry directory found")
