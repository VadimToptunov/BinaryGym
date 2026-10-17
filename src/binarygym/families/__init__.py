"""Registry of challenge families."""

from __future__ import annotations

from binarygym.errors import BinaryGymError
from binarygym.families.base import ChallengeFamily
from binarygym.families.transformation import TransformationFamily

FAMILIES: dict[str, ChallengeFamily] = {f.name: f for f in (TransformationFamily(),)}


def get_family(name: str) -> ChallengeFamily:
    try:
        return FAMILIES[name]
    except KeyError:
        known = ", ".join(sorted(FAMILIES))
        raise BinaryGymError(f"unknown family {name!r} (known: {known})") from None
