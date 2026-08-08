"""Local request-draft generation (spec section 17).

Requests are generated locally. Nothing is sent automatically, no ID document is
attached, and no legal claim is invented. When legal language is produced, the
template version is recorded so any finding can be traced to the exact wording.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from exposure.domain.enums import RemediationRoute
from exposure.domain.models import Finding, Source, Subject
from exposure.remediation.registry import RegistryEntry

TEMPLATE_VERSION = "1.0"

_DISCLAIMER = (
    "This draft is informational and is not legal advice. Review it before you "
    "submit anything. Exposure does not send this for you and never asks you to "
    "upload identity documents into Exposure."
)


@dataclass(slots=True)
class RequestDraft:
    route: RemediationRoute
    destination_url: str
    subject_line: str
    body: str
    required_inputs: list[str] = field(default_factory=list)
    side_effects: str = ""
    disclaimer: str = _DISCLAIMER
    template_version: str = TEMPLATE_VERSION
    informational: bool = True


def _name(subject: Subject) -> str:
    return subject.primary_name or "[your name]"


def generate_draft(
    finding: Finding, source: Source, subject: Subject, entry: RegistryEntry | None
) -> RequestDraft:
    if entry is None:
        return _no_action_draft(finding, source)

    destination = entry.portal_url or entry.official_url or ""
    detail = finding.category.value.replace("_", " ").lower()

    if entry.route_type == RemediationRoute.SEARCH_DELIST:
        body = (
            f"Use the official tool at {destination} to request removal of the "
            f"search result at:\n\n    {source.url}\n\n"
            f"It exposes your {detail}. Note: delisting affects search results "
            f"only and does not delete the content from the hosting site."
        )
        subject_line = "Remove a search result about me"
    elif entry.route_type == RemediationRoute.SOURCE_OPT_OUT:
        body = (
            f"Submit a deletion request through {destination}. A single verified "
            f"request covers registered data brokers, which reduces exposure of "
            f"your {detail} across many broker listings at once."
        )
        subject_line = "Data-broker deletion request"
    elif entry.route_type in (RemediationRoute.SOURCE_DELETE, RemediationRoute.SOURCE_CORRECT):
        verb = "erase" if entry.route_type == RemediationRoute.SOURCE_DELETE else "correct"
        body = (
            f"To: the data controller of {source.registrable_domain}\n"
            f"Subject: Request to {verb} my personal data\n\n"
            f"Dear Sir or Madam,\n\n"
            f"I am {_name(subject)}. The page at {source.url} contains my personal "
            f"data ({detail}). I request that you {verb} this personal data.\n\n"
            f"Please confirm the action taken and the date. Thank you.\n\n"
            f"{_name(subject)}"
        )
        subject_line = f"Request to {verb} my personal data"
    elif entry.route_type == RemediationRoute.USER_CONTROLLED_REMOVE:
        body = (
            f"This information is on a source you control ({source.registrable_domain}). "
            f"Sign in and edit or remove the {detail} on your profile or page at:\n\n"
            f"    {source.url}\n\n"
            f"This is usually the fastest and most reliable fix."
        )
        subject_line = "Remove information you control"
    else:  # CONTACT_PUBLISHER and others
        body = (
            f"To: the owner of {source.registrable_domain} (see its /contact or /privacy page)\n\n"
            f"Hello,\n\nThe page at {source.url} includes my personal information "
            f"({detail}). Would you please remove it? I am the person referenced. "
            f"Thank you for considering this request.\n\n{_name(subject)}"
        )
        subject_line = "Request to remove my personal information"

    return RequestDraft(
        route=entry.route_type,
        destination_url=destination,
        subject_line=subject_line,
        body=body,
        required_inputs=list(entry.required_inputs),
        side_effects=entry.side_effects,
        informational=entry.informational,
    )


def _no_action_draft(finding: Finding, source: Source) -> RequestDraft:
    return RequestDraft(
        route=RemediationRoute.NO_ACTION_AVAILABLE,
        destination_url="",
        subject_line="No removal action available",
        body=(
            f"The page at {source.url} appears to be a lawful public record or "
            f"public-interest source. There may be no available route to remove "
            f"it, which is an acceptable outcome. You may still request search "
            f"delisting to reduce how easily it is found."
        ),
        side_effects="Public records themselves are typically unaffected by removal requests.",
    )
