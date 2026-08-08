"""Domain layer: the six stable primitives and their enumerations.

These are the only primitives that should initially enter the reusable harness
(spec section 6, 43):

    Subject, Source, Observation, Match, Finding, RemediationCase
"""

from __future__ import annotations

from exposure.domain.enums import (
    CaseState,
    FindingCategory,
    MatchState,
    ObservationType,
    RemediationRoute,
    SearchStatus,
    Severity,
    SignalKind,
    SourceStatus,
    VerificationStatus,
)
from exposure.domain.models import (
    Finding,
    LocationHint,
    Match,
    Name,
    Observation,
    OrganisationHint,
    RemediationCase,
    SecretField,
    Signal,
    Source,
    Subject,
    Verification,
)

__all__ = [
    "CaseState",
    "FindingCategory",
    "MatchState",
    "ObservationType",
    "RemediationRoute",
    "SearchStatus",
    "Severity",
    "SignalKind",
    "SourceStatus",
    "VerificationStatus",
    "Finding",
    "LocationHint",
    "Match",
    "Name",
    "Observation",
    "OrganisationHint",
    "RemediationCase",
    "SecretField",
    "Signal",
    "Source",
    "Subject",
    "Verification",
]
