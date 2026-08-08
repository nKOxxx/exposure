"""Strict schemas for the AI boundary (spec section 12).

The LLM receives a minimal, sanitized packet and must return output matching
``ExplanationResponse``. Anything else is rejected — invalid output never becomes
a finding.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ObservationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    display_value: str  # already masked for sensitive types


class FindingPacket(BaseModel):
    """The only thing the LLM ever sees. No raw secrets, no full profile."""

    model_config = ConfigDict(extra="forbid")

    page_title: str = ""
    finding_category: str
    relevant_snippets: list[str] = Field(default_factory=list, max_length=8)
    observations: list[ObservationSummary] = Field(default_factory=list, max_length=20)


class ExplanationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation: str = Field(max_length=1200)
    review_questions: list[str] = Field(default_factory=list, max_length=5)
