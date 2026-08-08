"""Remediation case state machine (spec section 18).

Explicit transitions only. There is deliberately no ``DONE`` state — every
terminal state names what actually happened.
"""

from __future__ import annotations

from exposure.domain.enums import CaseState

# Allowed forward transitions. Terminal/alternative outcomes are reachable from
# most active states.
_FORWARD: dict[CaseState, set[CaseState]] = {
    CaseState.DISCOVERED: {CaseState.REVIEWED, CaseState.REJECTED, CaseState.NOT_APPLICABLE},
    CaseState.REVIEWED: {CaseState.ACTION_SELECTED, CaseState.NOT_APPLICABLE, CaseState.REJECTED},
    CaseState.ACTION_SELECTED: {CaseState.REQUEST_PREPARED, CaseState.USER_ABANDONED},
    CaseState.REQUEST_PREPARED: {CaseState.USER_MARKED_SUBMITTED, CaseState.USER_ABANDONED},
    CaseState.USER_MARKED_SUBMITTED: {CaseState.AWAITING_RESPONSE, CaseState.VERIFICATION_PENDING},
    CaseState.AWAITING_RESPONSE: {
        CaseState.SOURCE_CHANGED,
        CaseState.VERIFICATION_PENDING,
        CaseState.REQUEST_DENIED,
        CaseState.SOURCE_UNREACHABLE,
    },
    CaseState.SOURCE_CHANGED: {CaseState.VERIFICATION_PENDING},
    CaseState.VERIFICATION_PENDING: {
        CaseState.VERIFIED,
        CaseState.REAPPEARED,
        CaseState.SOURCE_UNREACHABLE,
        CaseState.AWAITING_RESPONSE,
    },
    CaseState.VERIFIED: {CaseState.REAPPEARED},
    # Alternative/terminal outcomes may re-open to verification if needed.
    CaseState.REQUEST_DENIED: {CaseState.ACTION_SELECTED, CaseState.USER_ABANDONED},
    CaseState.REAPPEARED: {CaseState.ACTION_SELECTED, CaseState.VERIFICATION_PENDING},
    CaseState.SOURCE_UNREACHABLE: {CaseState.VERIFICATION_PENDING, CaseState.USER_ABANDONED},
    CaseState.REJECTED: set(),
    CaseState.NOT_APPLICABLE: set(),
    CaseState.USER_ABANDONED: {CaseState.ACTION_SELECTED},
}


class InvalidTransition(ValueError):
    pass


def can_transition(current: CaseState, target: CaseState) -> bool:
    return target in _FORWARD.get(current, set())


def assert_transition(current: CaseState, target: CaseState) -> None:
    if not can_transition(current, target):
        raise InvalidTransition(f"{current.value} -> {target.value} is not allowed")
