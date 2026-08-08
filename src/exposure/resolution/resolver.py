"""Deterministic identity resolution (spec section 10).

Maps evidence families to a :class:`Match` state and a display confidence. The
rules never simply accumulate positive evidence: contradictions downgrade the
state, and only strong distinctive evidence reaches HIGH_CONFIDENCE. Abstention
(POSSIBLE / AMBIGUOUS) is a successful outcome.
"""

from __future__ import annotations

from exposure.domain.enums import MatchState
from exposure.domain.models import Match, Observation, Source, Subject
from exposure.resolution import policy
from exposure.resolution.signals import SignalSet, compute_signals


def _derive_confidence(s: SignalSet) -> float:
    """Noisy-OR across families, minus contradiction penalties."""
    families: list[float] = []
    if s.has_strong_direct:
        families.append(policy.W_DIRECT_STRONG)
    if s.has_username:
        families.append(policy.W_DIRECT_USERNAME)
    if s.has_name:
        families.append(policy.W_IDENTITY_NAME)
    if s.location_match:
        families.append(policy.W_LOCATION)
    if s.employer_match:
        families.append(policy.W_PROFESSIONAL_EMPLOYER)

    combined = 0.0
    for f in families:
        combined = combined + f - combined * f  # noisy-OR

    penalty = policy.P_LOCATION_CONFLICT if s.location_conflict else 0.0
    return max(0.0, min(1.0, combined - penalty))


def _derive_state(s: SignalSet) -> MatchState:
    corroborators = sum([s.location_match, s.employer_match])

    # Strong distinctive direct identifier: personal email/phone/owned domain.
    if s.has_strong_direct:
        # A contradiction on an otherwise-strong match warrants review.
        return MatchState.POSSIBLE if s.location_conflict else MatchState.HIGH_CONFIDENCE

    # Distinctive username plus any corroboration (or the name).
    if s.has_username and (s.has_name or corroborators >= 1):
        return MatchState.AMBIGUOUS if s.location_conflict else MatchState.HIGH_CONFIDENCE

    # Name plus two independent corroborating families.
    if s.has_name and corroborators >= 2:
        return MatchState.AMBIGUOUS if s.location_conflict else MatchState.HIGH_CONFIDENCE

    # Name plus one corroborator -> plausible but insufficient.
    if s.has_name and corroborators == 1:
        return MatchState.AMBIGUOUS if s.location_conflict else MatchState.POSSIBLE

    # Name only or username only -> namesake/handle risk.
    if s.has_name or s.has_username:
        return MatchState.POSSIBLE

    # No identity anchor at all -> needs human review.
    return MatchState.AMBIGUOUS


def resolve(
    source: Source,
    observations: list[Observation],
    subject: Subject,
) -> Match:
    signals = compute_signals(source, observations, subject)
    state = _derive_state(signals)
    confidence = _derive_confidence(signals)

    # Keep the numeric confidence consistent with the categorical state so the
    # UI never shows "HIGH_CONFIDENCE, 40%".
    if state == MatchState.HIGH_CONFIDENCE:
        confidence = max(confidence, policy.HIGH_CONFIDENCE_MIN)
    elif state == MatchState.POSSIBLE:
        confidence = min(max(confidence, policy.POSSIBLE_MIN), policy.HIGH_CONFIDENCE_MIN - 0.01)
    elif state == MatchState.AMBIGUOUS:
        confidence = min(confidence, policy.POSSIBLE_MIN)

    return Match(
        source_id=source.id,
        subject_id=subject.id,
        state=state,
        confidence=round(confidence, 3),
        supporting_signals=signals.supporting,
        contradicting_signals=signals.contradicting,
        resolution_version=policy.RESOLUTION_VERSION,
    )


def apply_user_decision(match: Match, decision: str) -> Match:
    """Apply an explicit user decision: 'me' | 'not_me' | 'unsure'."""
    mapping = {
        "me": MatchState.CONFIRMED,
        "not_me": MatchState.REJECTED,
        "unsure": MatchState.AMBIGUOUS,
    }
    if decision not in mapping:
        raise ValueError(f"unknown decision: {decision}")
    match.state = mapping[decision]
    match.user_overridden = True
    if decision == "me":
        match.confidence = 1.0
    elif decision == "not_me":
        match.confidence = 0.0
    return match
