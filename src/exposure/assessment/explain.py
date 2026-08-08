"""Deterministic, plain-language explanation of a finding (no LLM).

Answers the five questions a finding must answer (spec section 34). The optional
AI layer may later rephrase this, but the deterministic text is always available
so the product is fully functional with AI off.
"""

from __future__ import annotations

from exposure.assessment.rules import Assessment
from exposure.domain.enums import FindingCategory, MatchState

_WHAT: dict[FindingCategory, str] = {
    FindingCategory.CONTACT_EMAIL: "An email address associated with you appears on this page.",
    FindingCategory.CONTACT_PHONE: "A phone number associated with you appears on this page.",
    FindingCategory.HOME_ADDRESS: "A postal address associated with you appears on this page.",
    FindingCategory.PERSONAL_LOCATION: "Your location is stated on this page.",
    FindingCategory.DATE_OF_BIRTH: "A date of birth associated with you appears on this page.",
    FindingCategory.PROFESSIONAL_PROFILE: "Professional details about you appear on this page.",
    FindingCategory.SOCIAL_PROFILE: "A social-media profile linked to you appears on this page.",
    FindingCategory.USERNAME: "A username you use appears on this page.",
    FindingCategory.PERSONAL_DOCUMENT: "A personal document relating to you appears on this page.",
    FindingCategory.PUBLIC_RECORD: "A public record relating to you appears on this page.",
    FindingCategory.COMPANY_RECORD: "A company record naming you appears on this page.",
    FindingCategory.IMAGE_REFERENCE: "An image reference relating to you appears on this page.",
    FindingCategory.OUTDATED_INFORMATION: "Information about you here appears to be outdated.",
    FindingCategory.INCORRECT_INFORMATION: "Information about you here appears to be incorrect.",
    FindingCategory.OTHER_PERSONAL_INFORMATION: "Other personal information about you appears here.",
}

_WHY: dict[FindingCategory, str] = {
    FindingCategory.CONTACT_EMAIL: "Public email addresses attract spam, phishing, and account-takeover attempts.",
    FindingCategory.CONTACT_PHONE: "A public phone number enables SIM-swap, smishing, and unwanted contact.",
    FindingCategory.HOME_ADDRESS: "A public home address is a physical-safety and identity-theft risk.",
    FindingCategory.PERSONAL_LOCATION: "Location details can enable profiling and unwanted contact.",
    FindingCategory.DATE_OF_BIRTH: "A date of birth is a common identity-verification factor.",
    FindingCategory.PROFESSIONAL_PROFILE: "Professional details are often public but can aid targeted social engineering.",
    FindingCategory.SOCIAL_PROFILE: "Linked profiles let others correlate your accounts.",
    FindingCategory.USERNAME: "A reused username lets others correlate your accounts across sites.",
    FindingCategory.PERSONAL_DOCUMENT: "Exposed documents can contain highly sensitive detail.",
    FindingCategory.PUBLIC_RECORD: "Public records are lawfully published but still aggregate exposure.",
    FindingCategory.COMPANY_RECORD: "Company records are usually lawful but contribute to your public footprint.",
    FindingCategory.IMAGE_REFERENCE: "Images can be correlated with other information about you.",
    FindingCategory.OUTDATED_INFORMATION: "Outdated information can misrepresent you.",
    FindingCategory.INCORRECT_INFORMATION: "Incorrect information can misrepresent you.",
    FindingCategory.OTHER_PERSONAL_INFORMATION: "Any additional personal detail adds to your overall exposure.",
}

_IDENTITY_PHRASE = {
    MatchState.CONFIRMED: "You confirmed this is you.",
    MatchState.HIGH_CONFIDENCE: "Strong, independent evidence indicates this is you.",
    MatchState.POSSIBLE: "There is some evidence this is you, but it is not conclusive.",
    MatchState.AMBIGUOUS: "The evidence is mixed; this needs your review.",
    MatchState.REJECTED: "You marked this as not you.",
}


def summarize(category: FindingCategory) -> str:
    return _WHAT.get(category, _WHAT[FindingCategory.OTHER_PERSONAL_INFORMATION])


def why_it_matters(category: FindingCategory) -> str:
    return _WHY.get(category, _WHY[FindingCategory.OTHER_PERSONAL_INFORMATION])


def identity_reason(match_state: MatchState, supporting: list[str]) -> str:
    base = _IDENTITY_PHRASE.get(match_state, "")
    if supporting:
        return f"{base} Signals: {', '.join(supporting)}."
    return base


def explain_priority(assessment: Assessment) -> str:
    return f"PRIORITY_{assessment.overall_priority.value} because: " + " + ".join(
        assessment.reason_codes
    )
