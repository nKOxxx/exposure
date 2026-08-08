"""Map observations to finding categories (spec section 13).

A finding is one ``(source, category)`` pair backed by the observations that
evidence it. A bare name or page title is identity evidence, not an exposure
finding, so those types do not produce findings on their own.
"""

from __future__ import annotations

from exposure.domain.enums import FindingCategory, ObservationType
from exposure.domain.models import Observation

_OBS_TO_CATEGORY: dict[ObservationType, FindingCategory] = {
    ObservationType.EMAIL: FindingCategory.CONTACT_EMAIL,
    ObservationType.PHONE: FindingCategory.CONTACT_PHONE,
    ObservationType.POSTAL_ADDRESS: FindingCategory.HOME_ADDRESS,
    ObservationType.LOCATION: FindingCategory.PERSONAL_LOCATION,
    ObservationType.DATE_OF_BIRTH: FindingCategory.DATE_OF_BIRTH,
    ObservationType.JOB_TITLE: FindingCategory.PROFESSIONAL_PROFILE,
    ObservationType.EMPLOYER: FindingCategory.PROFESSIONAL_PROFILE,
    ObservationType.ORGANISATION: FindingCategory.PROFESSIONAL_PROFILE,
    ObservationType.SOCIAL_LINK: FindingCategory.SOCIAL_PROFILE,
    ObservationType.USERNAME: FindingCategory.USERNAME,
}


def category_for(obs: Observation) -> FindingCategory | None:
    return _OBS_TO_CATEGORY.get(obs.type)


def group_into_findings(observations: list[Observation]) -> dict[FindingCategory, list[Observation]]:
    groups: dict[FindingCategory, list[Observation]] = {}
    for obs in observations:
        category = category_for(obs)
        if category is None:
            continue
        groups.setdefault(category, []).append(obs)
    return groups
