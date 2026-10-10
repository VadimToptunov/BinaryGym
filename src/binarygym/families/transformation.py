"""TransformationFamily: input bytes pass through a short pipeline, then are compared.

Exercises: locating the input check, reading a per-byte transformation loop,
and inverting it to recover the key. All primitives are bijections, so exactly
one input is accepted.
"""

from __future__ import annotations

import string
from typing import Any

from binarygym import difficulty
from binarygym.rng import Rng
from binarygym.spec import GOAL_RECOVER_SECRET, ByteCompareChecker, ChallengeSpec, Secret, Target
from binarygym.transforms import TRANSFORM_TYPES, Transform, apply_pipeline, transform_to_dict

ALPHABET = string.ascii_letters + string.digits + "_"
SECRET_LENGTH = (8, 16)
PIPELINE_STEPS = (2, 4)
TARGET = Target(platform="linux", arch="x86_64", language="c")


class TransformationFamily:
    name = "transformation"
    version = 1
    summary = "Recover a key that passes through a short XOR/rotate pipeline before comparison."
    concepts: tuple[str, ...] = (
        "locating input validation",
        "per-byte transformation loops",
        "inverting reversible byte operations",
    )

    def generate(self, seed: int) -> ChallengeSpec:
        rng = Rng.from_seed(seed).fork(f"family/{self.name}/v{self.version}")

        # The generated secret is the authoritative answer; expected = pipeline(secret).
        secret = _generate_secret(rng.fork("secret"))
        pipeline = _generate_pipeline(rng.fork("pipeline"))
        expected = apply_pipeline(pipeline, secret.encode("ascii"))

        return ChallengeSpec.create(
            family=self.name,
            family_version=self.version,
            seed=seed,
            goal=GOAL_RECOVER_SECRET,
            target=TARGET,
            secret=Secret(alphabet=ALPHABET, value=secret),
            checker=ByteCompareChecker(
                input_length=len(secret), pipeline=pipeline, expected=expected
            ),
            difficulty=difficulty.semantic(
                {"transformation_complexity": len(pipeline), "structural_complexity": 1}
            ),
        )

    def solution(self, spec: ChallengeSpec) -> dict[str, Any]:
        checker = spec.checker
        return {
            "answer": spec.secret.value,
            "input_length": checker.input_length,
            "stages": [
                {"order": i, **transform_to_dict(t), "concept": t.concept}
                for i, t in enumerate(checker.pipeline)
            ],
            "comparison": {"kind": "all_bytes_equal", "expected_hex": checker.expected.hex()},
            "approach": "Apply the inverse of each stage in reverse order to the expected bytes.",
        }


def _generate_secret(rng: Rng) -> str:
    length = rng.randint(*SECRET_LENGTH)
    return "".join(rng.choice(ALPHABET) for _ in range(length))


def _generate_pipeline(rng: Rng) -> tuple[Transform, ...]:
    # Alternate ops: two adjacent XORs (or rotates) would collapse into one.
    ops = sorted(TRANSFORM_TYPES)
    steps = rng.randint(*PIPELINE_STEPS)
    current = rng.choice(ops)
    pipeline: list[Transform] = []
    for i in range(steps):
        pipeline.append(TRANSFORM_TYPES[current].generate(rng.fork(f"step/{i}")))
        current = rng.choice([op for op in ops if op != current])
    return tuple(pipeline)
