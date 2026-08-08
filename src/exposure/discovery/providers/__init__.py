"""Concrete discovery providers."""

from __future__ import annotations

from exposure.discovery.providers.brave import BraveSearchProvider
from exposure.discovery.providers.manual import ManualURLProvider
from exposure.discovery.providers.searxng import SearXNGProvider

__all__ = ["BraveSearchProvider", "ManualURLProvider", "SearXNGProvider"]
