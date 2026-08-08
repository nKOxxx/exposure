"""Optional AI layer. Off by default; the product is fully functional without it."""

from __future__ import annotations

from exposure.ai.provider import AIProvider, NullProvider, OpenAICompatibleProvider
from exposure.ai.sanitize import build_packet
from exposure.ai.schemas import ExplanationResponse, FindingPacket

__all__ = [
    "AIProvider",
    "NullProvider",
    "OpenAICompatibleProvider",
    "build_packet",
    "ExplanationResponse",
    "FindingPacket",
]
