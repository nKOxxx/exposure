"""Deterministic exposure assessment: four dimensions, priority, reason codes."""

from __future__ import annotations

from exposure.assessment.explain import (
    explain_priority,
    identity_reason,
    summarize,
    why_it_matters,
)
from exposure.assessment.rules import Assessment, AssessmentContext, assess
from exposure.assessment.taxonomy import category_for, group_into_findings

__all__ = [
    "assess",
    "Assessment",
    "AssessmentContext",
    "category_for",
    "group_into_findings",
    "summarize",
    "why_it_matters",
    "identity_reason",
    "explain_priority",
]
