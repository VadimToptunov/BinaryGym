"""The ChallengeFamily interface."""

from __future__ import annotations

from typing import Any, Protocol

from binarygym.spec import ChallengeSpec


class ChallengeFamily(Protocol):
    """A pedagogically coherent challenge structure, parameterized by a seed.

    ``generate`` must be a pure function of ``seed`` (and the family version):
    all randomness comes from :class:`binarygym.rng.Rng`.
    """

    name: str
    version: int
    summary: str
    concepts: tuple[str, ...]  # public, family-level; must not reveal instance details

    def generate(self, seed: int) -> ChallengeSpec: ...

    def solution(self, spec: ChallengeSpec) -> dict[str, Any]:
        """Machine-readable reference solution. Private."""
        ...
