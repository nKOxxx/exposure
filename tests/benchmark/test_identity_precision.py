"""Identity-resolution precision benchmark — release gate: precision >= 98%.

Precision here = of all pages the resolver marks HIGH_CONFIDENCE (or CONFIRMED),
the fraction that are truly the subject. Recall is reported but not gated: the
spec explicitly prefers abstention over false confidence (P5, section 28).
"""

from __future__ import annotations

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


def _build_subject(spec: dict) -> Subject:
    return Subject(
        names=[Name(value=spec["name"], is_primary=True)],
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


def test_high_confidence_precision_meets_target() -> None:
    tp = fp = 0
    matches_found = 0
    total_true = sum(1 for c in CASES if c.is_match)
    misclassified: list[str] = []

    for case in CASES:
        state = _resolve_case(case)
        auto = state in (MatchState.HIGH_CONFIDENCE, MatchState.CONFIRMED)
        if auto:
            if case.is_match:
                tp += 1
                matches_found += 1
            else:
                fp += 1
                misclassified.append(f"FALSE POSITIVE: {case.label} -> {state.value}")

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = matches_found / total_true if total_true else 0.0

    assert precision >= 0.98, (
        f"precision {precision:.3f} < 0.98\n" + "\n".join(misclassified)
    )
    # Sanity: the benchmark must actually exercise the high-confidence path.
    assert (tp + fp) >= 4, "benchmark did not produce enough high-confidence decisions"
    print(f"precision={precision:.3f} recall={recall:.3f} tp={tp} fp={fp}")


def test_no_namesake_reaches_high_confidence() -> None:
    for case in CASES:
        if not case.is_match:
            state = _resolve_case(case)
            assert state not in (MatchState.HIGH_CONFIDENCE, MatchState.CONFIRMED), (
                f"{case.label} wrongly auto-confirmed as {state.value}"
            )
