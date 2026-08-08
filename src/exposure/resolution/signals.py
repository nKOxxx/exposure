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


# Digits of a phone number treated as identifying. Long enough that an
# accidental collision is negligible, short enough to survive country/trunk
# prefix differences.
_SIGNIFICANT_DIGITS = 9


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
        # Compare a fixed significant suffix rather than the whole shorter
        # number, so the same line written nationally ("020 7946 0958") and
        # internationally ("+44 20 7946 0958") still matches despite the trunk
        # prefix. Nine digits keeps a coincidental collision negligible.
        if (
            len(cand) >= _SIGNIFICANT_DIGITS
            and len(sp) >= _SIGNIFICANT_DIGITS
            and cand[-_SIGNIFICANT_DIGITS:] == sp[-_SIGNIFICANT_DIGITS:]
        ):
            return True
    return False


# Title words that indicate the page title is a site/section label rather than
# the name of a person the page is about.
_NON_PERSON_TITLE_WORDS = frozenset(
    {
        "wikipedia", "home", "welcome", "index", "page", "search", "login", "about",
        "contact", "directory", "staff", "team", "news", "blog", "domain", "domains",
        "reserved", "profile", "profiles", "results", "list", "archive", "help",
        "support", "privacy", "terms", "error", "not", "found", "company", "careers",
    }
)

_TITLE_SEPARATORS = (" - ", " – ", " — ", " | ", " · ", ": ")


def page_topic_name(title: str) -> str | None:
    """Return the person-name the page appears to be *about*, if any.

    Real pages routinely mention people other than their subject. Knowing the
    page's topic lets the resolver tell "this page is about me" from "this page
    mentions me", which is the difference between a match and a namesake-grade
    false positive.
    """
    if not title:
        return None
    head = title.strip()
    for sep in _TITLE_SEPARATORS:
        if sep in head:
            head = head.split(sep, 1)[0].strip()
            break
    tokens = head.split()
    if not 2 <= len(tokens) <= 4:
        return None
    for token in tokens:
        cleaned = token.strip(".,'()")
        if not cleaned or not cleaned[0].isupper() or any(c.isdigit() for c in cleaned):
            return None
        if cleaned.lower() in _NON_PERSON_TITLE_WORDS:
            return None
    return head


@dataclass(slots=True)
class SignalSet:
    supporting: list[Signal] = field(default_factory=list)
    contradicting: list[Signal] = field(default_factory=list)
    has_strong_direct: bool = False
    has_username: bool = False
    has_name: bool = False
    name_in_title: bool = False
    location_match: bool = False
    employer_match: bool = False
    location_conflict: bool = False
    topic_conflict: bool = False


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
    page_title = ""

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
            if obs.type == ObservationType.PAGE_TITLE:
                page_title = obs.display_value
            if name_match(obs.display_value, subject_names):
                if obs.type == ObservationType.PAGE_TITLE:
                    result.name_in_title = True
                if not result.has_name:
                    result.supporting.append(
                        Signal(kind=SignalKind.IDENTITY, name="name_match",
                               detail="your name appears here",
                               weight=policy.W_IDENTITY_NAME)
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

    # CONTRADICTION — the page is about a different person and merely mentions
    # the subject. Found by live testing: a Wikipedia article about one person
    # names many others, and name + shared city + shared organisation was enough
    # to auto-confirm the wrong page.
    if result.has_name and not result.name_in_title:
        topic = page_topic_name(page_title)
        if topic and not name_match(topic, subject_names):
            result.contradicting.append(
                Signal(
                    kind=SignalKind.CONTRADICTION,
                    name="page_topic_conflict",
                    detail=f"this page is about '{topic}'; you are only mentioned on it",
                    weight=policy.P_TOPIC_CONFLICT,
                )
            )
            result.topic_conflict = True

    return result
