"""DirectComparisonFamily: the key is stored as-is and compared directly.

The intended beginner challenge: the answer is visible to static inspection
(``strings``, a disassembler's string view) once you find the comparison.
"""

from __future__ import annotations

from typing import Any

from binarygym import difficulty
from binarygym.families.base import DEFAULT_ALPHABET, generate_secret, resolve_version
from binarygym.rng import Rng
from binarygym.spec import GOAL_RECOVER_SECRET, ByteCompareChecker, ChallengeSpec, Secret


class DirectComparisonFamily:
    name = "direct"
    versions: tuple[int, ...] = (1,)
    summary = "Find the key the program compares your input against."
    concepts: tuple[str, ...] = (
        "locating input validation",
        "recovering embedded strings and data",
    )

    @property
    def latest_version(self) -> int:
        return self.versions[-1]

    def generate(self, seed: int, version: int | None = None) -> ChallengeSpec:
        version = resolve_version(self, version)
        rng = Rng.from_seed(seed).fork(f"family/{self.name}/v{version}")
        secret = generate_secret(rng.fork("secret"))
        return ChallengeSpec.create(
            family=self.name,
            family_version=version,
            seed=seed,
            goal=GOAL_RECOVER_SECRET,
            secret=Secret(alphabet=DEFAULT_ALPHABET, value=secret),
            checker=ByteCompareChecker(
                input_length=len(secret), pipeline=(), expected=secret.encode("ascii")
            ),
            difficulty=difficulty.semantic(
                {"transformation_complexity": 0, "structural_complexity": 1}
            ),
        )

    def solution(self, spec: ChallengeSpec) -> dict[str, Any]:
        return {
            "answer": spec.secret.value,
            "input_length": len(spec.secret.value),
            "approach": "The key is stored verbatim; find the comparison and read its operand.",
        }
