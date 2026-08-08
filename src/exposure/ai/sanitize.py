"""Build the sanitized packet sent to the LLM (spec section 12).

Only what is required is sent. Sensitive observation values are sent in masked
form. The complete subject profile, other findings, API keys, local paths, and
remediation history are never included.
"""

from __future__ import annotations

from exposure.ai.schemas import FindingPacket, ObservationSummary
from exposure.domain.models import Finding, Observation

# Instruction-injection scaffolding markers to strip from snippets (defense in
# depth; the prompt already frames snippets as untrusted data with no tools).
_INJECTION_MARKERS = ("```", "<|", "|>")


def build_packet(
    finding: Finding,
    page_title: str,
    observations: list[Observation],
    max_snippets: int = 6,
) -> FindingPacket:
    snippets: list[str] = []
    summaries: list[ObservationSummary] = []
    for obs in observations:
        # Use the masked display value for sensitive observations, and neutralize
        # it so injected scaffolding cannot ride along in a display field either.
        summaries.append(
            ObservationSummary(type=obs.type.value, display_value=_neutralize(obs.display_value))
        )
        if not obs.is_sensitive and len(snippets) < max_snippets:
            snippets.append(_neutralize(obs.evidence_snippet))

    return FindingPacket(
        page_title=_neutralize(page_title)[:160],
        finding_category=finding.category.value,
        relevant_snippets=snippets,
        observations=summaries[:20],
    )


def _neutralize(text: str) -> str:
    """Collapse whitespace and strip common injection scaffolding markers."""
    cleaned = " ".join((text or "").split())
    for marker in _INJECTION_MARKERS:
        cleaned = cleaned.replace(marker, " ")
    return cleaned
