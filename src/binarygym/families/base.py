"""The ChallengeFamily interface."""

from __future__ import annotations

import string
from typing import Any, Protocol

from binarygym.rng import Rng
from binarygym.spec import ChallengeSpec

DEFAULT_ALPHABET = string.ascii_letters + string.digits + "_"
DEFAULT_SECRET_LENGTH = (8, 16)


class ChallengeFamily(Protocol):
    """A pedagogically coherent challenge structure, parameterized by a seed.

    ``generate`` must be a pure function of ``(seed, version)``: all randomness comes
    from :class:`binarygym.rng.Rng`. Old versions stay available so a recorded
    ``(family, family_version, seed)`` keeps reproducing the same logical challenge.
    """

    name: str
    versions: tuple[int, ...]
    summary: str
    concepts: tuple[str, ...]  # public, family-level; must not reveal instance details

    @property
    def latest_version(self) -> int: ...

    def generate(self, seed: int, version: int | None = None) -> ChallengeSpec: ...

    def solution(self, spec: ChallengeSpec) -> dict[str, Any]:
        """Machine-readable reference solution. Private."""
        ...


def resolve_version(family: ChallengeFamily, version: int | None) -> int:
    from binarygym.errors import BinaryGymError

    chosen = family.latest_version if version is None else version
    if chosen not in family.versions:
        known = ", ".join(map(str, family.versions))
        raise BinaryGymError(f"family {family.name!r} has no version {chosen} (known: {known})")
    return chosen


def generate_secret(rng: Rng, alphabet: str = DEFAULT_ALPHABET,
                    length: tuple[int, int] = DEFAULT_SECRET_LENGTH) -> str:  # fmt: skip
    n = rng.randint(*length)
    return "".join(rng.choice(alphabet) for _ in range(n))
