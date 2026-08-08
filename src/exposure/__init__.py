"""Exposure — a local evidence and remediation engine for personal digital exposure.

Exposure is not an OSINT investigation platform, a people-search engine, an
autonomous deletion bot, a legal decision engine, or a cloud repository of
personal information. It is a local personal exposure-management utility.

Component versions are tracked independently (spec section 39) so that any
finding can be traced back to the exact logic that produced it.
"""

from __future__ import annotations

__all__ = [
    "APP_VERSION",
    "RESOLVER_VERSION",
    "ASSESSMENT_POLICY_VERSION",
    "REGISTRY_VERSION",
    "SCHEMA_VERSION",
]

APP_VERSION = "0.2.0"
RESOLVER_VERSION = "1.0"
ASSESSMENT_POLICY_VERSION = "1.0"
REGISTRY_VERSION = "2026.08.08"
SCHEMA_VERSION = 1
