"""Signal computation: compare a source's observations to the Subject.

Signals are grouped into evidence families (spec section 10). Correlated signals
within a family are collapsed by the resolver so that three spellings of the same
name do not count as three independent confirmations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from exposure.domain.enums import ObservationType, SignalKind
from exposure.domain.models import Observation, Signal, Source, Subject
from exposure.resolution import policy

_WORD_RE = re.compile(r"[^\w]+", re.UNICODE)


def _norm(text: str) -> str:
    return _WORD_RE.sub(" ", text.lower()).strip()


def _tokens(text: str) -> list[str]:
    return [t for t in _norm(text).split() if t]


def name_match(candidate: str, subject_names: list[str]) -> bool:
    """True if ``candidate`` plausibly denotes one of the subject's names.

    Requires first and last name tokens to both be present. Single-token names
    are ignored as too generic (precision-first).
    """
    cand_tokens = _tokens(candidate)
    if len(cand_tokens) < 2:
        return False
    cand_set = set(cand_tokens)
    for name in subject_names:
        st = _tokens(name)
        if len(st) < 2:
            continue
        if st[0] in cand_set and st[-1] in cand_set:
            return True
    return False


def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def phone_match(candidate: str, subject_phones: list[str]) -> bool:
    cand = _digits(candidate)
    if len(cand) < 7:
        return False
    for phone in subject_phones:
        sp = _digits(phone)
        if not sp:
            continue
        if cand == sp:
            return True
        shared = min(len(cand), len(sp))
        if shared >= 9 and cand[-shared:] == sp[-shared:]:
            return True
    return False


@dataclass(slots=True)
class SignalSet:
    supporting: list[Signal] = field(default_factory=list)
    contradicting: list[Signal] = field(default_factory=list)
    has_strong_direct: bool = False
    has_username: bool = False
    has_name: bool = False
    location_match: bool = False
    employer_match: bool = False
    location_conflict: bool = False


def compute_signals(
    source: Source, observations: list[Observation], subject: Subject
) -> SignalSet:
    result = SignalSet()

    subject_emails = [e.value.lower() for e in subject.emails]
    subject_phones = [p.value for p in subject.phones]
    subject_names = [n.value for n in subject.names]
    subject_usernames = {u.lower() for u in subject.usernames}
    subject_domains = {d.lower() for d in subject.personal_domains}
    subject_cities = {c.lower() for loc in subject.locations if (c := loc.city)}
    subject_countries = {c.lower() for loc in subject.locations if (c := loc.country)}
    subject_locations = subject_cities | subject_countries
    subject_employers = {_norm(e.name) for e in subject.employers}

    # DIRECT — owned domain (from the source itself)
    if source.registrable_domain and source.registrable_domain.lower() in subject_domains:
        result.supporting.append(
            Signal(
                kind=SignalKind.DIRECT,
                name="owned_domain",
                detail=f"source is on your domain {source.registrable_domain}",
                weight=policy.W_DIRECT_STRONG,
            )
        )
        result.has_strong_direct = True

    seen_locations: set[str] = set()

    for obs in observations:
        value = obs.value_normalized
        if obs.type == ObservationType.EMAIL and value in subject_emails:
            result.supporting.append(
                Signal(kind=SignalKind.DIRECT, name="email_match",
                       detail="your email appears here", weight=policy.W_DIRECT_STRONG)
            )
            result.has_strong_direct = True
        elif obs.type == ObservationType.PHONE and phone_match(value, subject_phones):
            result.supporting.append(
                Signal(kind=SignalKind.DIRECT, name="phone_match",
                       detail="your phone number appears here", weight=policy.W_DIRECT_STRONG)
            )
            result.has_strong_direct = True
        elif obs.type == ObservationType.USERNAME and value in subject_usernames:
            if len(value) >= policy.MIN_DISTINCTIVE_USERNAME:
                result.supporting.append(
                    Signal(kind=SignalKind.DIRECT, name="username_match",
                           detail=f"your username '{obs.display_value}' appears here",
                           weight=policy.W_DIRECT_USERNAME)
                )
                result.has_username = True
        elif obs.type in (ObservationType.NAME, ObservationType.PAGE_TITLE):
            if not result.has_name and name_match(obs.display_value, subject_names):
                result.supporting.append(
                    Signal(kind=SignalKind.IDENTITY, name="name_match",
                           detail="your name appears here", weight=policy.W_IDENTITY_NAME)
                )
                result.has_name = True
        elif obs.type == ObservationType.LOCATION:
            if value in subject_locations:
                if not result.location_match:
                    result.supporting.append(
                        Signal(kind=SignalKind.LOCATION, name="location_match",
                               detail=f"location '{obs.display_value}' matches yours",
                               weight=policy.W_LOCATION)
                    )
                    result.location_match = True
            else:
                seen_locations.add(value)
        elif obs.type in (ObservationType.EMPLOYER, ObservationType.ORGANISATION):
            if _norm(obs.display_value) in subject_employers and not result.employer_match:
                result.supporting.append(
                    Signal(kind=SignalKind.PROFESSIONAL, name="employer_match",
                           detail=f"employer '{obs.display_value}' matches yours",
                           weight=policy.W_PROFESSIONAL_EMPLOYER)
                )
                result.employer_match = True

    # CONTRADICTION — a name match plus a location that conflicts with every
    # known subject location, and no matching location (spec worked example).
    if (
        result.has_name
        and subject_locations
        and seen_locations
        and not result.location_match
    ):
        conflict = sorted(seen_locations)[0]
        result.contradicting.append(
            Signal(
                kind=SignalKind.CONTRADICTION,
                name="location_conflict",
                detail=f"page places this person in '{conflict}', which differs from your locations",
                weight=policy.P_LOCATION_CONFLICT,
            )
        )
        result.location_conflict = True

    return result
