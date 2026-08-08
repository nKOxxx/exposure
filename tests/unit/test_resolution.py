from __future__ import annotations

from exposure.domain.enums import MatchState, ObservationType, SourceStatus
from exposure.domain.models import (
    LocationHint,
    Name,
    Observation,
    OrganisationHint,
    SecretField,
    Source,
    Subject,
)
from exposure.resolution import apply_user_decision, resolve
from exposure.security.redaction import mask_email


def _subject(**kw) -> Subject:
    return Subject(
        names=[Name(value="Jane Example", is_primary=True)],
        locations=[LocationHint(city="London", country="UK")],
        employers=[OrganisationHint(name="Acme Corp")],
        emails=[SecretField(value="jane@example.com", display=mask_email("jane@example.com"))],
        usernames=["janeexample"],
        **kw,
    )


def _source(domain: str = "example.org") -> Source:
    return Source(
        url=f"https://{domain}/x",
        canonical_url=f"https://{domain}/x",
        registrable_domain=domain,
        status=SourceStatus.RETRIEVED,
    )


def _obs(t: ObservationType, value: str, display: str | None = None) -> Observation:
    return Observation(
        source_id="s",
        type=t,
        value_normalized=value.lower(),
        display_value=display or value,
        evidence_snippet="…",
        extractor="test",
        extractor_version="1.0",
    )


def test_direct_email_match_is_high_confidence() -> None:
    obs = [_obs(ObservationType.EMAIL, "jane@example.com", mask_email("jane@example.com"))]
    m = resolve(_source(), obs, _subject())
    assert m.state == MatchState.HIGH_CONFIDENCE
    assert m.confidence >= 0.8


def test_name_only_is_possible() -> None:
    obs = [_obs(ObservationType.NAME, "Jane Example")]
    m = resolve(_source(), obs, _subject())
    assert m.state == MatchState.POSSIBLE


def test_name_plus_two_corroborators_is_high_confidence() -> None:
    obs = [
        _obs(ObservationType.NAME, "Jane Example"),
        _obs(ObservationType.EMPLOYER, "Acme Corp"),
        _obs(ObservationType.LOCATION, "London"),
    ]
    m = resolve(_source(), obs, _subject())
    assert m.state == MatchState.HIGH_CONFIDENCE


def test_location_contradiction_downgrades_to_ambiguous() -> None:
    # Name + employer match, but the page places the person in Sydney.
    obs = [
        _obs(ObservationType.NAME, "Jane Example"),
        _obs(ObservationType.EMPLOYER, "Acme Corp"),
        _obs(ObservationType.LOCATION, "Sydney"),
    ]
    m = resolve(_source(), obs, _subject())
    assert m.state == MatchState.AMBIGUOUS
    assert m.contradicting_signals


def test_no_identity_anchor_is_ambiguous() -> None:
    obs = [_obs(ObservationType.DATE, "2019")]
    m = resolve(_source(), obs, _subject())
    assert m.state == MatchState.AMBIGUOUS


def test_owned_domain_is_strong_direct() -> None:
    subject = _subject(personal_domains=["janeexample.com"])
    src = _source("janeexample.com")
    m = resolve(src, [], subject)
    assert m.state == MatchState.HIGH_CONFIDENCE


def test_user_decision_override() -> None:
    m = resolve(_source(), [_obs(ObservationType.NAME, "Jane Example")], _subject())
    apply_user_decision(m, "me")
    assert m.state == MatchState.CONFIRMED and m.user_overridden and m.confidence == 1.0
    apply_user_decision(m, "not_me")
    assert m.state == MatchState.REJECTED and m.confidence == 0.0
