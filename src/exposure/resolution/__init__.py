"""Identity resolution: evidence-based, contradiction-aware, abstaining."""

from __future__ import annotations

from exposure.resolution.resolver import apply_user_decision, resolve
from exposure.resolution.signals import compute_signals, name_match, phone_match

__all__ = ["resolve", "apply_user_decision", "compute_signals", "name_match", "phone_match"]
