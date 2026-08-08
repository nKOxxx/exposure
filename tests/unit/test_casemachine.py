from __future__ import annotations

import pytest

from exposure.domain.enums import CaseState
from exposure.remediation import InvalidTransition, assert_transition, can_transition


def test_valid_forward_transition() -> None:
    assert can_transition(CaseState.DISCOVERED, CaseState.REVIEWED)
    assert can_transition(CaseState.USER_MARKED_SUBMITTED, CaseState.AWAITING_RESPONSE)


def test_invalid_transition_raises() -> None:
    with pytest.raises(InvalidTransition):
        assert_transition(CaseState.DISCOVERED, CaseState.VERIFIED)


def test_no_done_state() -> None:
    assert not hasattr(CaseState, "DONE")


def test_verified_can_reappear() -> None:
    assert can_transition(CaseState.VERIFIED, CaseState.REAPPEARED)
