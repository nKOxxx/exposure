"""Match a finding to applicable remediation routes (spec section 15).

There is no generic REMOVE. Routes are ordered by likely usefulness, but the
user always chooses. A ``NO_ACTION_AVAILABLE`` option is offered honestly when a
source is a government / public-interest publisher, because that is an
acceptable answer.
"""

from __future__ import annotations

from dataclasses import dataclass

from exposure.domain.enums import RemediationRoute
from exposure.domain.models import Finding, Source, Subject
from exposure.remediation.registry import Registry, RegistryEntry

# Country hints (very rough) used only to mark a jurisdiction route as relevant.
_EU_EEA_UK = frozenset(
    {
        "uk", "united kingdom", "gb", "gbr", "ireland", "ie", "germany", "de", "france", "fr",
        "spain", "es", "italy", "it", "netherlands", "nl", "sweden", "se", "poland", "pl",
        "portugal", "pt", "belgium", "be", "austria", "at", "denmark", "dk", "finland", "fi",
        "norway", "no", "iceland", "greece", "gr", "czechia", "romania", "eu", "eea",
    }
)
_US = frozenset({"us", "usa", "united states", "united states of america"})
_GOV_SUFFIXES = (".gov", ".gov.uk", ".gov.au", ".mil", ".gc.ca", "europa.eu")
_USER_CONTROLLED_DOMAINS = frozenset(
    {"linkedin.com", "github.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
     "medium.com", "mastodon.social"}
)


@dataclass(slots=True)
class RouteOption:
    route: RemediationRoute
    registry_id: str | None
    provider: str
    recommended: bool
    reason: str
    jurisdiction_relevant: bool
    entry: RegistryEntry | None = None


def _country_set(subject: Subject) -> set[str]:
    out: set[str] = set()
    for loc in subject.locations:
        if loc.country:
            out.add(loc.country.strip().lower())
    return out


def routes_for_finding(
    finding: Finding, source: Source, subject: Subject, registry: Registry
) -> list[RouteOption]:
    domain = (source.registrable_domain or "").lower()
    countries = _country_set(subject)
    user_controlled = domain in _USER_CONTROLLED_DOMAINS or domain in {
        d.lower() for d in subject.personal_domains
    }
    is_gov = any(domain.endswith(sfx) for sfx in _GOV_SUFFIXES)

    options: list[RouteOption] = []
    applicable = {e.id: e for e in registry.for_category(finding.category)}

    def add(entry_id: str, recommended: bool, reason: str, jurisdiction_relevant: bool) -> None:
        entry = applicable.get(entry_id)
        if entry is None:
            return
        options.append(
            RouteOption(
                route=entry.route_type,
                registry_id=entry.id,
                provider=entry.provider,
                recommended=recommended,
                reason=reason,
                jurisdiction_relevant=jurisdiction_relevant,
                entry=entry,
            )
        )

    # 1) If the user controls the source, that is the fastest reliable route.
    if user_controlled:
        add("user_controlled_remove", True, "You appear to control this source directly.", True)

    # 2) Jurisdiction routes.
    if countries & _US:
        add("california_drop", not user_controlled,
            "You indicated a US location; DROP covers registered data brokers.", True)
    if countries & _EU_EEA_UK:
        add("generic_gdpr_erasure", not user_controlled,
            "You indicated an EU/EEA/UK location; GDPR erasure may apply.", True)
        add("generic_gdpr_rectification", False,
            "For outdated/incorrect data, rectification may fit better than deletion.", True)

    # 3) Search delisting reduces discoverability even if the source stays up.
    add("google_personal_info", not (user_controlled or bool(countries)),
        "Delisting reduces how easily this is found via search.", False)

    # 4) Publisher contact always available as a mechanism.
    add("generic_publisher_contact", False,
        "You can ask the site owner directly (no legal claim implied).", False)

    # 5) Honest no-action option for public-interest sources.
    if is_gov or not options:
        options.append(
            RouteOption(
                route=RemediationRoute.NO_ACTION_AVAILABLE,
                registry_id=None,
                provider="(none)",
                recommended=is_gov,
                reason=(
                    "This looks like a government or public-interest source; lawful public "
                    "records are often not removable. This is an acceptable outcome."
                    if is_gov
                    else "No registry route matched this finding's category."
                ),
                jurisdiction_relevant=False,
            )
        )
    return options
