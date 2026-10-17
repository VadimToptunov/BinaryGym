"""Registry of challenge families."""

from __future__ import annotations

from binarygym.errors import BinaryGymError
from binarygym.families.base import ChallengeFamily
from binarygym.families.direct import DirectComparisonFamily
from binarygym.families.state_machine import StateMachineFamily
from binarygym.families.transformation import TransformationFamily

FAMILIES: dict[str, ChallengeFamily] = {
    f.name: f for f in (DirectComparisonFamily(), TransformationFamily(), StateMachineFamily())
}


def get_family(name: str) -> ChallengeFamily:
    try:
        return FAMILIES[name]
    except KeyError:
        known = ", ".join(sorted(FAMILIES))
        raise BinaryGymError(f"unknown family {name!r} (known: {known})") from None
