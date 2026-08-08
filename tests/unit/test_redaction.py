from __future__ import annotations

from exposure.security.redaction import mask_email, mask_phone, redact


def test_mask_email_keeps_domain() -> None:
    out = mask_email("nikola@example.com")
    assert out.endswith("@example.com")
    assert out.startswith("n")
    assert "nikola" not in out


def test_mask_phone_keeps_last_two() -> None:
    out = mask_phone("+971 50 123 4512")
    assert out.endswith("12")
    assert "5012" not in out


def test_redact_scrubs_email_and_phone() -> None:
    text = "Reach jane@example.com or +1 415 555 0132 today"
    out = redact(text)
    assert "jane@example.com" not in out
    assert "5550132" not in out.replace(" ", "")
    assert "[email]" in out and "[phone]" in out


def test_redact_none() -> None:
    assert redact(None) == ""
