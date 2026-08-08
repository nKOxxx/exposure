"""The six core domain primitives plus their value objects.

These are Pydantic models so they validate at construction and serialize
cleanly to the API and to exports. Storage uses a thin repository layer over
raw ``sqlite3`` (see ``exposure.storage``) rather than an ORM, keeping the
dependency surface small and the persisted schema fully auditable.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from exposure.domain.enums import (
    CaseState,
    FindingCategory,
    MatchState,
    ObservationType,
    RemediationRoute,
    Severity,
    SignalKind,
    SourceStatus,
    VerificationStatus,
)


def new_id() -> str:
    """Return a fresh opaque identifier (stored/compared as a string)."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Timezone-aware current time in UTC (ISO-8601 UTC everywhere)."""
    return datetime.now(UTC)


class _Base(BaseModel):
    model_config = ConfigDict(use_enum_values=False, extra="forbid")


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #


class Name(_Base):
    value: str
    is_primary: bool = False


class LocationHint(_Base):
    city: str | None = None
    country: str | None = None

    def as_text(self) -> str:
        return ", ".join(p for p in (self.city, self.country) if p)


class OrganisationHint(_Base):
    name: str
    domain: str | None = None
    is_current: bool = True


class SecretField(_Base):
    """A sensitive identifier (email, phone).

    The raw ``value`` lives only in memory and (encrypted) at rest. The API and
    exports carry ``display`` (a masked form). ``value`` is excluded from
    serialization so it cannot leak through the API or into a report.
    """

    value: str = Field(repr=False, exclude=True)
    display: str

    def __str__(self) -> str:  # never print the raw value
        return self.display


class Signal(_Base):
    kind: SignalKind
    name: str
    detail: str
    weight: float = 0.0


class Verification(_Base):
    checked_at: datetime = Field(default_factory=utcnow)
    source_status: VerificationStatus = VerificationStatus.UNKNOWN
    query_used: str | None = None
    provider: str | None = None
    new_content_hash: str | None = None
    note: str | None = None


# --------------------------------------------------------------------------- #
# Primitive 1: Subject
# --------------------------------------------------------------------------- #


class Subject(_Base):
    id: str = Field(default_factory=new_id)
    names: list[Name] = Field(default_factory=list)
    locations: list[LocationHint] = Field(default_factory=list)
    employers: list[OrganisationHint] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    emails: list[SecretField] = Field(default_factory=list)
    phones: list[SecretField] = Field(default_factory=list)
    personal_domains: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)

    @property
    def primary_name(self) -> str | None:
        for n in self.names:
            if n.is_primary:
                return n.value
        return self.names[0].value if self.names else None


# --------------------------------------------------------------------------- #
# Primitive 2: Source
# --------------------------------------------------------------------------- #


class Source(_Base):
    id: str = Field(default_factory=new_id)
    url: str
    canonical_url: str
    registrable_domain: str
    title: str | None = None
    retrieved_at: datetime | None = None
    http_status: int | None = None
    content_type: str | None = None
    content_hash: str | None = None
    status: SourceStatus = SourceStatus.RETRIEVED


# --------------------------------------------------------------------------- #
# Primitive 3: Observation
# --------------------------------------------------------------------------- #


class Observation(_Base):
    id: str = Field(default_factory=new_id)
    source_id: str
    type: ObservationType
    value_normalized: str
    display_value: str
    evidence_snippet: str
    extractor: str
    extractor_version: str
    is_sensitive: bool = False
    observed_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Primitive 4: Match
# --------------------------------------------------------------------------- #


class Match(_Base):
    id: str = Field(default_factory=new_id)
    source_id: str
    subject_id: str
    state: MatchState
    confidence: float
    supporting_signals: list[Signal] = Field(default_factory=list)
    contradicting_signals: list[Signal] = Field(default_factory=list)
    resolution_version: str
    user_overridden: bool = False
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Primitive 5: Finding
# --------------------------------------------------------------------------- #


class Finding(_Base):
    id: str = Field(default_factory=new_id)
    subject_id: str
    source_id: str
    category: FindingCategory
    sensitivity: Severity
    discoverability: Severity
    misuse_potential: Severity
    persistence: Severity
    overall_priority: Severity
    assessment_confidence: float
    identity_confidence: float
    match_state: MatchState
    explanation_codes: list[str] = Field(default_factory=list)
    summary: str = ""
    observation_ids: list[str] = Field(default_factory=list)
    assessment_policy_version: str = ""
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Primitive 6: RemediationCase
# --------------------------------------------------------------------------- #


class RemediationCase(_Base):
    id: str = Field(default_factory=new_id)
    finding_id: str
    route: RemediationRoute
    registry_route_id: str | None = None
    state: CaseState = CaseState.DISCOVERED
    opened_at: datetime = Field(default_factory=utcnow)
    submitted_at: datetime | None = None
    last_checked_at: datetime | None = None
    verification: Verification | None = None
    note: str | None = None
