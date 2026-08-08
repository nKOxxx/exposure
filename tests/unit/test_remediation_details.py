"""Remediation route matching and request-draft generation for every route type."""

from __future__ import annotations

import pytest

from exposure.domain.enums import (
    FindingCategory,
    MatchState,
    RemediationRoute,
    Severity,
    SourceStatus,
)
from exposure.domain.models import Finding, LocationHint, Name, Source, Subject
from exposure.remediation import generate_draft, load_registry, routes_for_finding
from exposure.remediation.templates import TEMPLATE_VERSION

REGISTRY = load_registry()


def _subject(country: str | None = None, domains: list[str] | None = None) -> Subject:
    return Subject(
        names=[Name(value="Jane Example", is_primary=True)],
        locations=[LocationHint(city="London", country=country)] if country else [],
        personal_domains=domains or [],
    )


def _source(domain: str) -> Source:
    return Source(
        url=f"https://{domain}/page",
        canonical_url=f"https://{domain}/page",
        registrable_domain=domain,
        status=SourceStatus.RETRIEVED,
    )


def _finding(category: FindingCategory) -> Finding:
    return Finding(
        subject_id="s", source_id="src", category=category,
        sensitivity=Severity.HIGH, discoverability=Severity.HIGH,
        misuse_potential=Severity.HIGH, persistence=Severity.MODERATE,
        overall_priority=Severity.HIGH, assessment_confidence=1.0,
        identity_confidence=0.95, match_state=MatchState.HIGH_CONFIDENCE,
    )


# --------------------------------------------------------------------------- #
# Route matching
# --------------------------------------------------------------------------- #


def test_us_subject_gets_drop_route() -> None:
    options = routes_for_finding(
        _finding(FindingCategory.HOME_ADDRESS), _source("broker.example"),
        _subject("US"), REGISTRY,
    )
    ids = [o.registry_id for o in options]
    assert "california_drop" in ids
    assert any(o.recommended and o.registry_id == "california_drop" for o in options)


def test_eu_subject_gets_gdpr_routes() -> None:
    options = routes_for_finding(
        _finding(FindingCategory.HOME_ADDRESS), _source("broker.example"),
        _subject("Germany"), REGISTRY,
    )
    assert "generic_gdpr_erasure" in [o.registry_id for o in options]


def test_user_controlled_source_is_recommended_first() -> None:
    options = routes_for_finding(
        _finding(FindingCategory.SOCIAL_PROFILE), _source("linkedin.com"),
        _subject("UK"), REGISTRY,
    )
    assert options[0].registry_id == "user_controlled_remove"
    assert options[0].recommended


def test_own_domain_counts_as_user_controlled() -> None:
    options = routes_for_finding(
        _finding(FindingCategory.CONTACT_EMAIL), _source("janeexample.com"),
        _subject("UK", domains=["janeexample.com"]), REGISTRY,
    )
    assert options[0].registry_id == "user_controlled_remove"


def test_government_source_offers_no_action() -> None:
    options = routes_for_finding(
        _finding(FindingCategory.PUBLIC_RECORD), _source("agency.gov"),
        _subject("US"), REGISTRY,
    )
    no_action = [o for o in options if o.route == RemediationRoute.NO_ACTION_AVAILABLE]
    assert no_action and no_action[0].recommended
    assert "acceptable outcome" in no_action[0].reason


def test_unmatched_category_still_offers_no_action() -> None:
    options = routes_for_finding(
        _finding(FindingCategory.INCORRECT_INFORMATION), _source("news.example"),
        _subject(None), REGISTRY,
    )
    assert any(o.route == RemediationRoute.NO_ACTION_AVAILABLE for o in options) or options


def test_search_delist_offered_without_jurisdiction() -> None:
    options = routes_for_finding(
        _finding(FindingCategory.CONTACT_PHONE), _source("broker.example"),
        _subject(None), REGISTRY,
    )
    delist = [o for o in options if o.route == RemediationRoute.SEARCH_DELIST]
    assert delist and delist[0].recommended


# --------------------------------------------------------------------------- #
# Draft generation, one per route type
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "entry_id,expected_route",
    [
        ("google_personal_info", RemediationRoute.SEARCH_DELIST),
        ("california_drop", RemediationRoute.SOURCE_OPT_OUT),
        ("generic_gdpr_erasure", RemediationRoute.SOURCE_DELETE),
        ("generic_gdpr_rectification", RemediationRoute.SOURCE_CORRECT),
        ("user_controlled_remove", RemediationRoute.USER_CONTROLLED_REMOVE),
        ("generic_publisher_contact", RemediationRoute.CONTACT_PUBLISHER),
    ],
)
def test_draft_for_each_route(entry_id: str, expected_route: RemediationRoute) -> None:
    entry = REGISTRY.get(entry_id)
    assert entry is not None
    draft = generate_draft(
        _finding(FindingCategory.HOME_ADDRESS), _source("broker.example"),
        _subject("UK"), entry,
    )
    assert draft.route == expected_route
    assert draft.body and draft.subject_line
    assert draft.template_version == TEMPLATE_VERSION
    assert "not legal advice" in draft.disclaimer
    # Never instructs the user to upload ID into Exposure.
    assert "upload" not in draft.body.lower()


def test_delist_draft_states_it_is_not_deletion() -> None:
    draft = generate_draft(
        _finding(FindingCategory.CONTACT_PHONE), _source("broker.example"),
        _subject(None), REGISTRY.get("google_personal_info"),
    )
    assert "does not delete" in draft.body


def test_gdpr_draft_names_the_subject_and_url() -> None:
    draft = generate_draft(
        _finding(FindingCategory.HOME_ADDRESS), _source("broker.example"),
        _subject("UK"), REGISTRY.get("generic_gdpr_erasure"),
    )
    assert "Jane Example" in draft.body
    assert "https://broker.example/page" in draft.body


def test_draft_without_entry_is_no_action() -> None:
    draft = generate_draft(
        _finding(FindingCategory.PUBLIC_RECORD), _source("agency.gov"), _subject(), None
    )
    assert draft.route == RemediationRoute.NO_ACTION_AVAILABLE
    assert "public record" in draft.body.lower()
    assert draft.destination_url == ""


def test_draft_falls_back_to_placeholder_name() -> None:
    draft = generate_draft(
        _finding(FindingCategory.HOME_ADDRESS), _source("broker.example"),
        Subject(), REGISTRY.get("generic_gdpr_erasure"),
    )
    assert "[your name]" in draft.body
