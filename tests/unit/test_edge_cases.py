"""Remaining edge cases: masking, comparisons, config, verification, signals."""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from exposure.ai import FindingPacket, OpenAICompatibleProvider
from exposure.assessment import assess
from exposure.assessment.rules import AssessmentContext
from exposure.config import Settings, default_workspace
from exposure.domain.enums import (
    FindingCategory,
    MatchState,
    ObservationType,
    Severity,
    SourceStatus,
    VerificationStatus,
)
from exposure.domain.models import (
    Name,
    Observation,
    SecretField,
    Source,
    Subject,
)
from exposure.extraction.metadata import _format_address
from exposure.remediation.verification import verify_search, verify_source
from exposure.resolution import name_match, phone_match, resolve
from exposure.resolution.resolver import apply_user_decision
from exposure.retrieval.canonicalize import canonical_url
from exposure.retrieval.client import SecureRetriever
from exposure.security.redaction import mask_email, mask_phone, redact_mapping
from exposure.security.validation import (
    UrlPolicyError,
    is_blocked_address,
    validate_url_syntax,
)
from exposure.storage.database import Database

# --------------------------------------------------------------------------- #
# Masking / redaction edge cases
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value,check",
    [
        ("no-at-sign", lambda out: "•" in out and "no-at-sign" not in out),
        ("@example.com", lambda out: out.endswith("@example.com")),
        ("a@b.co", lambda out: out.startswith("a") and out.endswith("@b.co")),
    ],
)
def test_mask_email_edge_cases(value: str, check) -> None:  # type: ignore[no-untyped-def]
    assert check(mask_email(value))


@pytest.mark.parametrize("value", ["1", "", "ab"])
def test_mask_phone_too_short(value: str) -> None:
    assert set(mask_phone(value)) <= {"•"}


def test_mask_phone_preserves_plus() -> None:
    assert mask_phone("+441234567").startswith("+")
    assert not mask_phone("441234567").startswith("+")


def test_redact_mapping_only_touches_strings() -> None:
    out = redact_mapping({"note": "mail me at a@b.com", "count": 3, "ok": True})
    assert out["note"] == "mail me at [email]"
    assert out["count"] == 3 and out["ok"] is True


def test_secret_field_str_is_masked() -> None:
    field = SecretField(value="jane@example.com", display="j•••@example.com")
    assert str(field) == "j•••@example.com"
    assert "jane@example.com" not in field.model_dump_json()


# --------------------------------------------------------------------------- #
# Severity comparison semantics
# --------------------------------------------------------------------------- #


def test_severity_orders_by_rank_not_alphabet() -> None:
    assert Severity.HIGH > Severity.MODERATE      # not lexicographic
    assert Severity.LOW < Severity.MODERATE
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.LOW <= Severity.CRITICAL
    assert max(Severity.LOW, Severity.HIGH, Severity.MODERATE) is Severity.HIGH
    assert min(Severity.HIGH, Severity.NONE) is Severity.NONE


def test_severity_refuses_comparison_with_bare_string() -> None:
    """Silent lexicographic fallback would be a wrong answer, so it must raise."""
    for compare in (
        lambda: Severity.HIGH < "MODERATE",   # type: ignore[operator]
        lambda: Severity.HIGH <= "MODERATE",  # type: ignore[operator]
        lambda: Severity.HIGH > "MODERATE",   # type: ignore[operator]
        lambda: Severity.HIGH >= "MODERATE",  # type: ignore[operator]
    ):
        with pytest.raises(TypeError, match="only ordered against Severity"):
            compare()


def test_severity_equality_with_string_still_works() -> None:
    """Equality keeps str semantics so persisted values compare naturally."""
    assert Severity.HIGH == "HIGH"
    assert Severity.HIGH.value == "HIGH"


def test_match_state_actionable() -> None:
    assert MatchState.CONFIRMED.actionable and MatchState.HIGH_CONFIDENCE.actionable
    assert not MatchState.POSSIBLE.actionable
    assert not MatchState.AMBIGUOUS.actionable
    assert not MatchState.REJECTED.actionable


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


def test_workspace_honours_exposure_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("EXPOSURE_HOME", str(tmp_path / "custom"))
    assert default_workspace() == (tmp_path / "custom").resolve()


def test_workspace_honours_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("EXPOSURE_HOME", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert default_workspace() == (tmp_path / "xdg").resolve() / "exposure"


def test_workspace_defaults_to_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EXPOSURE_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert default_workspace() == Path.home() / ".exposure"


def test_ensure_dirs_tolerates_chmod_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object, **__: object) -> None:
        raise OSError("nope")

    monkeypatch.setattr(os, "chmod", boom)
    settings = Settings(workspace=tmp_path / "ws")
    settings.ensure_dirs()
    assert settings.cache_dir.is_dir() and settings.export_dir.is_dir()


def test_settings_paths_are_under_workspace(tmp_path: Path) -> None:
    s = Settings(workspace=tmp_path / "ws")
    for p in (s.db_path, s.cache_dir, s.export_dir, s.secrets_path, s.log_path):
        assert str(p).startswith(str(s.workspace))


# --------------------------------------------------------------------------- #
# Validation / canonicalization
# --------------------------------------------------------------------------- #


def test_validate_url_rejects_empty_and_hostless() -> None:
    for bad in ("", "   ", "https://"):
        with pytest.raises(UrlPolicyError):
            validate_url_syntax(bad)


def test_scheme_relative_url_rejected() -> None:
    with pytest.raises(UrlPolicyError, match="unsupported_scheme"):
        validate_url_syntax("//example.com/path")


def test_sixtofour_wrapped_private_is_blocked() -> None:
    # 2002:: 6to4 wrapping of 10.0.0.1
    assert is_blocked_address("2002:a00:1::") is True


def test_canonical_url_drops_only_tracking_params() -> None:
    assert canonical_url("https://e.com/p?utm_medium=x") == "https://e.com/p"
    assert canonical_url("https://e.com/p?q=1&fbclid=z") == "https://e.com/p?q=1"
    assert canonical_url("https://e.com/p?") == "https://e.com/p"


# --------------------------------------------------------------------------- #
# Resolution helpers
# --------------------------------------------------------------------------- #


def test_name_match_requires_two_tokens() -> None:
    assert name_match("Jane Example", ["Jane Example"]) is True
    assert name_match("Jane", ["Jane Example"]) is False           # single token
    assert name_match("Jane Example", ["Jane"]) is False           # subject too short
    assert name_match("Example, Jane A.", ["Jane Example"]) is True  # order-insensitive


def test_phone_match_variants() -> None:
    assert phone_match("+44 20 7946 0958", ["442079460958"]) is True
    assert phone_match("020 7946 0958", ["+44 20 7946 0958"]) is True  # shared suffix
    assert phone_match("12345", ["442079460958"]) is False            # too short
    assert phone_match("442079460958", []) is False
    assert phone_match("442079460958", ["not-a-number"]) is False


def test_apply_user_decision_rejects_unknown() -> None:
    source = Source(url="https://e.com/x", canonical_url="https://e.com/x",
                    registrable_domain="e.com", status=SourceStatus.RETRIEVED)
    match = resolve(source, [], Subject(names=[Name(value="Jane Example", is_primary=True)]))
    with pytest.raises(ValueError, match="unknown decision"):
        apply_user_decision(match, "maybe")


# --------------------------------------------------------------------------- #
# Assessment modifiers
# --------------------------------------------------------------------------- #


def test_government_source_reason_code() -> None:
    a = assess(
        FindingCategory.PUBLIC_RECORD,
        AssessmentContext(registrable_domain="agency.gov",
                          match_state=MatchState.HIGH_CONFIDENCE),
    )
    assert "GOVERNMENT_SOURCE" in a.reason_codes


def test_user_controlled_reason_code() -> None:
    a = assess(
        FindingCategory.SOCIAL_PROFILE,
        AssessmentContext(registrable_domain="linkedin.com",
                          match_state=MatchState.HIGH_CONFIDENCE),
    )
    assert "USER_CONTROLLED" in a.reason_codes


def test_outdated_information_is_capped_low() -> None:
    a = assess(
        FindingCategory.OUTDATED_INFORMATION,
        AssessmentContext(from_search=True, match_state=MatchState.CONFIRMED),
    )
    assert a.overall_priority <= Severity.LOW
    assert "OUTDATED_CAP" in a.reason_codes


def test_professional_profile_capped_moderate() -> None:
    a = assess(
        FindingCategory.PROFESSIONAL_PROFILE,
        AssessmentContext(from_search=True, match_state=MatchState.CONFIRMED),
    )
    assert a.overall_priority <= Severity.MODERATE


def test_unknown_category_uses_default() -> None:
    a = assess(
        FindingCategory.OTHER_PERSONAL_INFORMATION,
        AssessmentContext(match_state=MatchState.CONFIRMED),
    )
    assert a.overall_priority <= Severity.LOW


# --------------------------------------------------------------------------- #
# Verification branches
# --------------------------------------------------------------------------- #


def _source() -> Source:
    return Source(url="https://e.com/p", canonical_url="https://e.com/p",
                  registrable_domain="e.com", content_hash="old",
                  status=SourceStatus.RETRIEVED)


def _retriever(settings: Settings, handler) -> SecureRetriever:  # type: ignore[no-untyped-def]
    return SecureRetriever(settings, transport=httpx.MockTransport(handler))


def test_verify_timeout_is_unknown_not_removed(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    r = _retriever(settings, handler)
    v = verify_source(r, _source(), ["jane@example.com"])
    assert v.source_status == VerificationStatus.UNKNOWN and v.note == "timeout"
    r.close()


def test_verify_transport_error_is_unknown(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    r = _retriever(settings, handler)
    assert verify_source(r, _source(), []).source_status == VerificationStatus.UNKNOWN
    r.close()


def test_verify_empty_body_is_content_removed(settings: Settings) -> None:
    r = _retriever(
        settings,
        lambda req: httpx.Response(200, headers={"content-type": "text/html"}, content=b"   "),
    )
    assert verify_source(r, _source(), []).source_status == VerificationStatus.CONTENT_REMOVED
    r.close()


def test_verify_content_changed_when_hash_differs(settings: Settings) -> None:
    r = _retriever(
        settings,
        lambda req: httpx.Response(
            200, headers={"content-type": "text/html"},
            text="<html><body><p>jane@example.com still here, page reworded</p></body></html>",
        ),
    )
    v = verify_source(r, _source(), ["jane@example.com"])
    assert v.source_status == VerificationStatus.CONTENT_CHANGED
    r.close()


def test_verify_410_is_url_gone(settings: Settings) -> None:
    r = _retriever(settings, lambda req: httpx.Response(410))
    assert verify_source(r, _source(), []).source_status == VerificationStatus.URL_GONE
    r.close()


def test_search_verification_provider_failure_is_not_removal() -> None:
    class _Boom:
        id = "boom"

        def search(self, query, limit):  # type: ignore[no-untyped-def]
            raise RuntimeError("provider down")

    from exposure.domain.enums import SearchStatus

    status, v = verify_search(_Boom(), "q", "https://e.com/p")
    # A failed check must never read as "not present".
    assert status == SearchStatus.SEARCH_RESULT_PRESENT
    assert "search_failed" in (v.note or "")


def test_search_verification_observes_present_result() -> None:
    from exposure.discovery.provider import SearchCandidate
    from exposure.domain.enums import SearchStatus

    class _Found:
        id = "stub"

        def search(self, query, limit):  # type: ignore[no-untyped-def]
            return [SearchCandidate(url="https://e.com/p")]

    status, v = verify_search(_Found(), "q", "https://e.com/p")
    assert status == SearchStatus.SEARCH_RESULT_PRESENT
    assert v.provider == "stub"


# --------------------------------------------------------------------------- #
# Misc
# --------------------------------------------------------------------------- #


def test_format_address_variants() -> None:
    assert _format_address("10 Downing St") == "10 Downing St"
    assert _format_address({"streetAddress": "10 Downing St", "addressLocality": "London"}) == (
        "10 Downing St, London"
    )
    assert _format_address(12345) == ""


def test_database_close_is_idempotent(settings: Settings) -> None:
    db = Database(settings)
    db.connect()
    db.close()
    db.close()
    with pytest.raises(RuntimeError, match="not connected"):
        _ = db.conn


def test_observations_for_unknown_source_is_empty(db: Database) -> None:
    assert db.observations_for_source("ghost") == []
    assert db.get_source("ghost") is None
    assert db.get_finding("ghost") is None
    assert db.get_case("ghost") is None
    assert db.get_match_for_source("ghost") is None
    assert db.get_provider("ghost") is None
    assert db.get_scan("ghost") is None


def test_ai_provider_rejects_malformed_transport_response() -> None:
    provider = OpenAICompatibleProvider(
        "http://localhost:11434/v1",
        "m",
        api_key="sk-test",
        transport=httpx.MockTransport(lambda r: httpx.Response(500)),
    )
    packet = FindingPacket(finding_category="CONTACT_EMAIL")
    assert provider.explain(packet) is None


def test_ai_provider_handles_missing_choices() -> None:
    provider = OpenAICompatibleProvider(
        "http://localhost:11434/v1",
        "m",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})),
    )
    assert provider.explain(FindingPacket(finding_category="CONTACT_EMAIL")) is None


def test_observation_requires_evidence() -> None:
    obs = Observation(
        source_id="s", type=ObservationType.EMAIL, value_normalized="a@b.com",
        display_value="a•••@b.com", evidence_snippet="…a@b.com…",
        extractor="pii", extractor_version="1.0", is_sensitive=True,
    )
    assert obs.evidence_snippet and obs.extractor_version
