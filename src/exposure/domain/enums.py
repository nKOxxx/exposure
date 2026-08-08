"""Enumerations for the Exposure domain.

Kept in one module so that persisted string values have a single source of
truth. Enum *values* are stored in SQLite and appear in exports, so they must
remain stable across releases (spec section 39).
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """A five-level ordinal scale used for every assessment dimension."""

    NONE = "NONE"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    # NOTE: Severity subclasses ``str``, so we must override ALL four rich
    # comparisons — otherwise ``>``/``>=``/``max()`` would fall back to str's
    # lexicographic ordering ("HIGH" < "MODERATE") instead of severity rank.
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_ORDER = [
    Severity.NONE,
    Severity.LOW,
    Severity.MODERATE,
    Severity.HIGH,
    Severity.CRITICAL,
]


class MatchState(StrEnum):
    """Identity-resolution outcome (spec section 10).

    Only CONFIRMED and HIGH_CONFIDENCE may automatically enter the remediation
    priority queue. Everything else requires human review — abstention is a
    successful outcome (P5).
    """

    CONFIRMED = "CONFIRMED"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    POSSIBLE = "POSSIBLE"
    AMBIGUOUS = "AMBIGUOUS"
    REJECTED = "REJECTED"

    @property
    def actionable(self) -> bool:
        return self in (MatchState.CONFIRMED, MatchState.HIGH_CONFIDENCE)


class SignalKind(StrEnum):
    """Evidence families for resolution (spec section 10).

    Signals within the same family are correlated and must not be counted as
    independent confirmations.
    """

    IDENTITY = "IDENTITY"
    LOCATION = "LOCATION"
    PROFESSIONAL = "PROFESSIONAL"
    DIRECT = "DIRECT"
    CONTRADICTION = "CONTRADICTION"


class ObservationType(StrEnum):
    """The kind of fact extracted from a source."""

    NAME = "NAME"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    USERNAME = "USERNAME"
    URL = "URL"
    SOCIAL_LINK = "SOCIAL_LINK"
    LOCATION = "LOCATION"
    EMPLOYER = "EMPLOYER"
    JOB_TITLE = "JOB_TITLE"
    DATE = "DATE"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    POSTAL_ADDRESS = "POSTAL_ADDRESS"
    PAGE_TITLE = "PAGE_TITLE"
    ORGANISATION = "ORGANISATION"
    OTHER = "OTHER"


class FindingCategory(StrEnum):
    """The exposure taxonomy (spec section 13). Intentionally small.

    No speculative categories: no psychological, political, ethnic, religious,
    medical, sexual-orientation, or financial-worth inference.
    """

    CONTACT_EMAIL = "CONTACT_EMAIL"
    CONTACT_PHONE = "CONTACT_PHONE"
    HOME_ADDRESS = "HOME_ADDRESS"
    PERSONAL_LOCATION = "PERSONAL_LOCATION"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    PROFESSIONAL_PROFILE = "PROFESSIONAL_PROFILE"
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    USERNAME = "USERNAME"
    PERSONAL_DOCUMENT = "PERSONAL_DOCUMENT"
    PUBLIC_RECORD = "PUBLIC_RECORD"
    COMPANY_RECORD = "COMPANY_RECORD"
    IMAGE_REFERENCE = "IMAGE_REFERENCE"
    OUTDATED_INFORMATION = "OUTDATED_INFORMATION"
    INCORRECT_INFORMATION = "INCORRECT_INFORMATION"
    OTHER_PERSONAL_INFORMATION = "OTHER_PERSONAL_INFORMATION"


class RemediationRoute(StrEnum):
    """The remediation route taxonomy (spec section 15).

    There is deliberately no generic ``REMOVE``.
    """

    SOURCE_DELETE = "SOURCE_DELETE"
    SOURCE_CORRECT = "SOURCE_CORRECT"
    SOURCE_OPT_OUT = "SOURCE_OPT_OUT"
    SEARCH_DELIST = "SEARCH_DELIST"
    USER_CONTROLLED_REMOVE = "USER_CONTROLLED_REMOVE"
    NO_ACTION_AVAILABLE = "NO_ACTION_AVAILABLE"
    CONTACT_PUBLISHER = "CONTACT_PUBLISHER"  # a mechanism, not an outcome


class CaseState(StrEnum):
    """Remediation case state machine (spec section 18).

    There is deliberately no ``DONE`` state — it would hide what actually
    happened.
    """

    DISCOVERED = "DISCOVERED"
    REVIEWED = "REVIEWED"
    ACTION_SELECTED = "ACTION_SELECTED"
    REQUEST_PREPARED = "REQUEST_PREPARED"
    USER_MARKED_SUBMITTED = "USER_MARKED_SUBMITTED"
    AWAITING_RESPONSE = "AWAITING_RESPONSE"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    VERIFIED = "VERIFIED"
    # Alternative outcomes
    REJECTED = "REJECTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REQUEST_DENIED = "REQUEST_DENIED"
    USER_ABANDONED = "USER_ABANDONED"
    SOURCE_UNREACHABLE = "SOURCE_UNREACHABLE"
    REAPPEARED = "REAPPEARED"


class SourceStatus(StrEnum):
    """Result of attempting to retrieve a source."""

    RETRIEVED = "RETRIEVED"
    RETRIEVAL_BLOCKED = "RETRIEVAL_BLOCKED"
    TIMEOUT = "TIMEOUT"
    TOO_LARGE = "TOO_LARGE"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"
    ERROR = "ERROR"


class VerificationStatus(StrEnum):
    """Outcome of re-checking an original source (spec section 19)."""

    URL_GONE = "URL_GONE"
    CONTENT_REMOVED = "CONTENT_REMOVED"
    PERSONAL_DATA_REMOVED = "PERSONAL_DATA_REMOVED"
    CONTENT_CHANGED = "CONTENT_CHANGED"
    UNCHANGED = "UNCHANGED"
    ACCESS_BLOCKED = "ACCESS_BLOCKED"
    UNKNOWN = "UNKNOWN"


class SearchStatus(StrEnum):
    """Outcome of re-checking search-engine presence (spec section 19).

    Deliberately worded as observation, not proof of universal delisting.
    """

    SEARCH_RESULT_PRESENT = "SEARCH_RESULT_PRESENT"
    SEARCH_RESULT_NOT_OBSERVED = "SEARCH_RESULT_NOT_OBSERVED"
