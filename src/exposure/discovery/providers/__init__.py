"""Concrete discovery providers."""

from __future__ import annotations

from exposure.discovery.providers.brave import BraveSearchProvider
from exposure.discovery.providers.manual import ManualURLProvider

__all__ = ["BraveSearchProvider", "ManualURLProvider"]
