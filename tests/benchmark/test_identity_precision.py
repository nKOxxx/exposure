"""Identity-resolution benchmark — release gate: precision >= 98%.

Precision = of the pages the resolver auto-confirms (HIGH_CONFIDENCE or
CONFIRMED), the fraction that truly refer to the subject. Recall is reported but
not gated: the spec explicitly prefers abstention over false confidence
(P5, section 28).
"""

from __future__ import annotations

from collections import defaultdict

import pytest

from exposure.domain.enums import MatchState, SourceStatus
from exposure.domain.models import (
    LocationHint,
    Name,
    Observation,
    OrganisationHint,
    SecretField,
    Source,
    Subject,
)
from exposure.extraction import extract_document
from exposure.resolution import resolve
from exposure.retrieval.canonicalize import registrable_domain
from exposure.security.redaction import mask_email, mask_phone
from tests.benchmark.corpus import CASES, Case

PRECISION_TARGET = 0.98


def _build_subject(spec: dict) -> Subject:
    names = [Name(value=spec["name"], is_primary=True)]
    names += [Name(value=n) for n in spec.get("alt_names", [])]
    return Subject(
        names=names,
        locations=[LocationHint(city=spec.get("city"), country=spec.get("country"))]
        if spec.get("city") or spec.get("country")
        else [],
        employers=[OrganisationHint(name=e) for e in spec.get("employers", [])],
        usernames=spec.get("usernames", []),
        personal_domains=spec.get("personal_domains", []),
        emails=[SecretField(value=e, display=mask_email(e)) for e in spec.get("emails", [])],
        phones=[SecretField(value=p, display=mask_phone(p)) for p in spec.get("phones", [])],
    )


def _resolve_case(case: Case) -> MatchState:
    subject = _build_subject(case.subject)
    source = Source(
        url=case.url,
        canonical_url=case.url,
        registrable_domain=registrable_domain(case.url),
        status=SourceStatus.RETRIEVED,
    )
    extraction = extract_document("text/html", case.html.encode(), subject)
    observations = [
        Observation(
            source_id=source.id,
            type=item.type,
            value_normalized=item.value_normalized,
            display_value=item.display_value,
            evidence_snippet=item.evidence_snippet,
            extractor=item.extractor,
            extractor_version=item.extractor_version,
            is_sensitive=item.is_sensitive,
        )
        for item in extraction.items
    ]
    return resolve(source, observations, subject).state


@pytest.fixture(scope="module")
def outcomes() -> list[tuple[Case, MatchState]]:
    return [(case, _resolve_case(case)) for case in CASES]


def _is_auto(state: MatchState) -> bool:
    return state in (MatchState.HIGH_CONFIDENCE, MatchState.CONFIRMED)


def test_corpus_is_substantial() -> None:
    assert len(CASES) >= 100
    positives = sum(1 for c in CASES if c.is_match)
    assert 0.2 < positives / len(CASES) < 0.8, "corpus should not be class-degenerate"


def test_high_confidence_precision_meets_target(
    outcomes: list[tuple[Case, MatchState]],
) -> None:
    tp = [c for c, s in outcomes if _is_auto(s) and c.is_match]
    fp = [c for c, s in outcomes if _is_auto(s) and not c.is_match]
    total_true = sum(1 for c in CASES if c.is_match)

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    recall = len(tp) / total_true if total_true else 0.0

    print(
        f"\ncorpus={len(CASES)} auto-confirmed={len(tp) + len(fp)} "
        f"precision={precision:.4f} recall={recall:.4f} tp={len(tp)} fp={len(fp)}"
    )
    if fp:
        print("FALSE POSITIVES:")
        for c in fp:
            print(f"  - {c.label} {c.tags}")

    assert precision >= PRECISION_TARGET, (
        f"precision {precision:.4f} < {PRECISION_TARGET}; "
        f"false positives: {[c.label for c in fp]}"
    )
    # The benchmark must actually exercise the auto-confirm path.
    assert len(tp) + len(fp) >= 20


def test_no_namesake_is_auto_confirmed(outcomes: list[tuple[Case, MatchState]]) -> None:
    offenders = [
        c.label for c, s in outcomes if not c.is_match and _is_auto(s)
    ]
    assert not offenders, f"non-matching pages wrongly auto-confirmed: {offenders}"


def test_strong_direct_identifiers_are_found(
    outcomes: list[tuple[Case, MatchState]],
) -> None:
    """Recall guard: pages carrying a strong identifier must be auto-confirmed."""
    missed = [
        c.label
        for c, s in outcomes
        if c.is_match and "direct" in c.tags and not _is_auto(s)
    ]
    assert not missed, f"strong-identifier pages not auto-confirmed: {missed}"


def test_thin_evidence_abstains(outcomes: list[tuple[Case, MatchState]]) -> None:
    """Name-only or city-only evidence must never reach auto-confirm."""
    wrong = [
        c.label
        for c, s in outcomes
        if "abstain-expected" in c.tags and _is_auto(s)
    ]
    assert not wrong, f"thin evidence wrongly auto-confirmed: {wrong}"


def test_no_rejected_states_without_user_input(
    outcomes: list[tuple[Case, MatchState]],
) -> None:
    """REJECTED is a user decision; the resolver alone must not produce it."""
    assert not [c.label for c, s in outcomes if s == MatchState.REJECTED]


def test_outcome_distribution_is_reported(
    outcomes: list[tuple[Case, MatchState]],
) -> None:
    dist: dict[str, int] = defaultdict(int)
    for _, state in outcomes:
        dist[state.value] += 1
    print("\nstate distribution:", dict(sorted(dist.items())))
    assert set(dist) <= {s.value for s in MatchState}
