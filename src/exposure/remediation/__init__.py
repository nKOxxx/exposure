"""Remediation: registry, route matching, request drafts, state machine, verify."""

from __future__ import annotations

from exposure.remediation.casemachine import (
    InvalidTransition,
    assert_transition,
    can_transition,
)
from exposure.remediation.registry import Registry, RegistryEntry, load_registry
from exposure.remediation.routes import RouteOption, routes_for_finding
from exposure.remediation.templates import RequestDraft, generate_draft
from exposure.remediation.verification import verify_search, verify_source

__all__ = [
    "load_registry",
    "Registry",
    "RegistryEntry",
    "routes_for_finding",
    "RouteOption",
    "generate_draft",
    "RequestDraft",
    "can_transition",
    "assert_transition",
    "InvalidTransition",
    "verify_source",
    "verify_search",
]
