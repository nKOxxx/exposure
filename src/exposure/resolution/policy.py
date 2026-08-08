"""Resolution thresholds and version.

Confidence is derived deterministically from evidence families (see
``resolver``). These thresholds map a derived confidence to a state for display;
the resolver also applies structural rules directly. Precision is favoured over
recall: when in doubt we abstain (spec P5, section 10).
"""

from __future__ import annotations

from exposure import RESOLVER_VERSION

RESOLUTION_VERSION = RESOLVER_VERSION

# Derived-confidence thresholds.
HIGH_CONFIDENCE_MIN = 0.80
POSSIBLE_MIN = 0.35

# Family weights (used to compute a display confidence). Correlated signals in
# the same family are collapsed to a single family contribution.
W_DIRECT_STRONG = 0.97      # personal email / phone / owned domain exact match
W_DIRECT_USERNAME = 0.62    # distinctive username reuse
W_IDENTITY_NAME = 0.50      # full-name match (names are not unique)
W_LOCATION = 0.20
W_PROFESSIONAL_EMPLOYER = 0.35

# Contradiction penalties.
P_LOCATION_CONFLICT = 0.45

# A username must be at least this long to be treated as distinctive.
MIN_DISTINCTIVE_USERNAME = 4
