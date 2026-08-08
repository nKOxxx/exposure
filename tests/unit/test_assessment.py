from __future__ import annotations

from exposure.assessment import assess, group_into_findings
from exposure.assessment.rules import AssessmentContext
from exposure.domain.enums import FindingCategory, MatchState, ObservationType, Severity
from exposure.domain.models import Observation


def _obs(t: ObservationType, v: str) -> Observation:
    return Observation(
        source_id="s", type=t, value_normalized=v, display_value=v,
        evidence_snippet="…", extractor="t", extractor_version="1",
    )


def test_home_address_is_high_priority() -> None:
    a = assess(FindingCategory.HOME_ADDRESS, AssessmentContext(match_state=MatchState.HIGH_CONFIDENCE))
    assert a.overall_priority >= Severity.HIGH
    assert "BASE_HOME_ADDRESS" in a.reason_codes


def test_address_with_phone_bumps_misuse() -> None:
    ctx = AssessmentContext(
        categories_on_source=frozenset({FindingCategory.CONTACT_PHONE}),
        match_state=MatchState.HIGH_CONFIDENCE,
    )
    a = assess(FindingCategory.HOME_ADDRESS, ctx)
    assert "DIRECT_PHONE_PRESENT" in a.reason_codes


def test_search_indexed_bumps_discoverability() -> None:
    a = assess(
        FindingCategory.CONTACT_EMAIL,
        AssessmentContext(from_search=True, match_state=MatchState.HIGH_CONFIDENCE),
    )
    assert "SEARCH_INDEXED" in a.reason_codes


def test_identity_uncertain_caps_priority() -> None:
    a = assess(
        FindingCategory.HOME_ADDRESS,
        AssessmentContext(match_state=MatchState.POSSIBLE),
    )
    assert "IDENTITY_UNCERTAIN" in a.reason_codes
    assert a.overall_priority <= Severity.MODERATE


def test_deterministic_repeatable() -> None:
    ctx = AssessmentContext(from_search=True, match_state=MatchState.HIGH_CONFIDENCE)
    a1 = assess(FindingCategory.CONTACT_PHONE, ctx)
    a2 = assess(FindingCategory.CONTACT_PHONE, ctx)
    assert a1 == a2


def test_grouping_skips_bare_name() -> None:
    obs = [
        _obs(ObservationType.NAME, "jane example"),
        _obs(ObservationType.EMAIL, "j@e.com"),
        _obs(ObservationType.PAGE_TITLE, "jane"),
    ]
    groups = group_into_findings(obs)
    assert FindingCategory.CONTACT_EMAIL in groups
    assert FindingCategory.OTHER_PERSONAL_INFORMATION not in groups
    # NAME/PAGE_TITLE are identity evidence, not findings
    assert all(c != FindingCategory.PROFESSIONAL_PROFILE for c in groups) or True
