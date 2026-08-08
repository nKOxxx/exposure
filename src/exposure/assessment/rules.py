"""Deterministic exposure-assessment policy (spec section 14).

Four independent dimensions — sensitivity, discoverability, misuse potential,
persistence — plus a derived overall priority. The LLM never produces this
classification; it is reproducible and emits reason codes for every decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from exposure import ASSESSMENT_POLICY_VERSION
from exposure.domain.enums import FindingCategory, MatchState, Severity

S = Severity

# Base dimensions per category: (sensitivity, discoverability, misuse, persistence)
_BASE: dict[FindingCategory, tuple[Severity, Severity, Severity, Severity]] = {
    FindingCategory.HOME_ADDRESS: (S.HIGH, S.MODERATE, S.HIGH, S.MODERATE),
    FindingCategory.CONTACT_PHONE: (S.MODERATE, S.MODERATE, S.HIGH, S.MODERATE),
    FindingCategory.CONTACT_EMAIL: (S.MODERATE, S.MODERATE, S.MODERATE, S.MODERATE),
    FindingCategory.DATE_OF_BIRTH: (S.HIGH, S.LOW, S.HIGH, S.HIGH),
    FindingCategory.PERSONAL_LOCATION: (S.MODERATE, S.MODERATE, S.MODERATE, S.LOW),
    FindingCategory.PROFESSIONAL_PROFILE: (S.LOW, S.HIGH, S.LOW, S.MODERATE),
    FindingCategory.SOCIAL_PROFILE: (S.LOW, S.HIGH, S.LOW, S.MODERATE),
    FindingCategory.USERNAME: (S.LOW, S.MODERATE, S.LOW, S.MODERATE),
    FindingCategory.PERSONAL_DOCUMENT: (S.HIGH, S.LOW, S.HIGH, S.MODERATE),
    FindingCategory.PUBLIC_RECORD: (S.MODERATE, S.MODERATE, S.MODERATE, S.HIGH),
    FindingCategory.COMPANY_RECORD: (S.LOW, S.MODERATE, S.LOW, S.HIGH),
    FindingCategory.IMAGE_REFERENCE: (S.LOW, S.MODERATE, S.LOW, S.MODERATE),
    FindingCategory.OUTDATED_INFORMATION: (S.LOW, S.LOW, S.LOW, S.LOW),
    FindingCategory.INCORRECT_INFORMATION: (S.LOW, S.LOW, S.MODERATE, S.LOW),
    FindingCategory.OTHER_PERSONAL_INFORMATION: (S.LOW, S.LOW, S.LOW, S.LOW),
}

_DEFAULT = (S.LOW, S.LOW, S.LOW, S.LOW)

# Domains the user typically controls themselves (affects route, not priority).
_USER_CONTROLLED_DOMAINS = frozenset(
    {"linkedin.com", "github.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
     "medium.com", "mastodon.social"}
)

_GOV_SUFFIXES = (".gov", ".gov.uk", ".gov.au", ".mil", ".gc.ca", "europa.eu")


def _bump(sev: Severity, steps: int) -> Severity:
    from exposure.domain.enums import _SEVERITY_ORDER

    idx = max(0, min(len(_SEVERITY_ORDER) - 1, sev.rank + steps))
    return _SEVERITY_ORDER[idx]


@dataclass(slots=True)
class AssessmentContext:
    from_search: bool = False
    registrable_domain: str = ""
    categories_on_source: frozenset[FindingCategory] = frozenset()
    match_state: MatchState = MatchState.POSSIBLE


@dataclass(slots=True)
class Assessment:
    sensitivity: Severity
    discoverability: Severity
    misuse_potential: Severity
    persistence: Severity
    overall_priority: Severity
    reason_codes: list[str] = field(default_factory=list)
    policy_version: str = ASSESSMENT_POLICY_VERSION


def assess(category: FindingCategory, ctx: AssessmentContext) -> Assessment:
    sensitivity, discoverability, misuse, persistence = _BASE.get(category, _DEFAULT)
    reasons: list[str] = [f"BASE_{category.value}"]

    # Discoverability: a result surfaced by a search provider is, by definition,
    # discoverable.
    if ctx.from_search:
        discoverability = _bump(discoverability, 1)
        reasons.append("SEARCH_INDEXED")

    # An address becomes materially more dangerous next to a phone number.
    if category == FindingCategory.HOME_ADDRESS and (
        FindingCategory.CONTACT_PHONE in ctx.categories_on_source
    ):
        misuse = _bump(misuse, 1)
        reasons.append("DIRECT_PHONE_PRESENT")

    # Government / public-interest sources are usually not removable.
    is_gov = any(ctx.registrable_domain.endswith(sfx) for sfx in _GOV_SUFFIXES)
    if is_gov:
        reasons.append("GOVERNMENT_SOURCE")

    if ctx.registrable_domain in _USER_CONTROLLED_DOMAINS:
        reasons.append("USER_CONTROLLED")

    # Priority is driven by the worse of sensitivity / misuse, nudged by
    # discoverability.
    priority = max(sensitivity, misuse)
    if discoverability >= Severity.HIGH and priority < Severity.CRITICAL:
        priority = _bump(priority, 1)
        reasons.append("HIGH_DISCOVERABILITY")

    # Category caps.
    if category in (FindingCategory.OUTDATED_INFORMATION,):
        priority = min(priority, Severity.LOW)
        reasons.append("OUTDATED_CAP")
    if category == FindingCategory.PROFESSIONAL_PROFILE and priority > Severity.MODERATE:
        priority = Severity.MODERATE

    # Identity uncertainty caps priority: an unconfirmed match should not sit at
    # the top of the queue.
    if not ctx.match_state.actionable:
        reasons.append("IDENTITY_UNCERTAIN")
        priority = min(priority, Severity.MODERATE)

    return Assessment(
        sensitivity=sensitivity,
        discoverability=discoverability,
        misuse_potential=misuse,
        persistence=persistence,
        overall_priority=priority,
        reason_codes=reasons,
    )
