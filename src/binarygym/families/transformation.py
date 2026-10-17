"""TransformationFamily: input bytes pass through a short pipeline, then are compared.

Exercises: locating the input check, reading transformation code and inverting it
to recover the key. All primitives are bijections, so exactly one input is accepted.

* v1: alternating XOR / rotate (2-4 steps). Kept for reproducibility; note that it
  collapses to one XOR plus one rotate, so it is easier than its step count suggests.
* v2: 3-5 steps drawn from XOR, ADD, rotate, position-keyed XOR, S-box and byte
  permutation, with rules that prevent adjacent steps from collapsing into one.
"""

from __future__ import annotations

from typing import Any

from binarygym import difficulty
from binarygym.families.base import DEFAULT_ALPHABET, generate_secret, resolve_version
from binarygym.rng import Rng
from binarygym.spec import GOAL_RECOVER_SECRET, ByteCompareChecker, ChallengeSpec, Secret
from binarygym.transforms import (
    TRANSFORM_TYPES,
    Transform,
    apply_pipeline,
    transform_to_dict,
)

# Steps in the same group commute or merge with each other when adjacent.
_MERGE_GROUP = {"xor": "xor", "pxor": "xor", "add": "add", "rol": "rol", "sbox": "sbox",
                "perm": "perm"}  # fmt: skip
_AT_MOST_ONCE = frozenset({"sbox", "perm"})


class TransformationFamily:
    name = "transformation"
    versions: tuple[int, ...] = (1, 2)
    summary = "Recover a key that passes through a short pipeline of byte transformations."
    concepts: tuple[str, ...] = (
        "locating input validation",
        "reading byte transformation code",
        "inverting reversible byte operations",
    )

    @property
    def latest_version(self) -> int:
        return self.versions[-1]

    def generate(self, seed: int, version: int | None = None) -> ChallengeSpec:
        version = resolve_version(self, version)
        rng = Rng.from_seed(seed).fork(f"family/{self.name}/v{version}")

        # The generated secret is the authoritative answer; expected = pipeline(secret).
        secret = generate_secret(rng.fork("secret"))
        build = _pipeline_v1 if version == 1 else _pipeline_v2
        pipeline = build(rng.fork("pipeline"), len(secret))
        expected = apply_pipeline(pipeline, secret.encode("ascii"))

        if version == 1:
            dims = {"transformation_complexity": len(pipeline), "structural_complexity": 1}
        else:
            dims = {
                "transformation_complexity": len(pipeline),
                "structural_complexity": 1 + any(t.reorders for t in pipeline),
                "lookup_tables": sum(t.op == "sbox" for t in pipeline),
            }
        return ChallengeSpec.create(
            family=self.name,
            family_version=version,
            seed=seed,
            goal=GOAL_RECOVER_SECRET,
            secret=Secret(alphabet=DEFAULT_ALPHABET, value=secret),
            checker=ByteCompareChecker(
                input_length=len(secret), pipeline=pipeline, expected=expected
            ),
            difficulty=difficulty.semantic(dims),
        )

    def solution(self, spec: ChallengeSpec) -> dict[str, Any]:
        checker = spec.checker
        assert isinstance(checker, ByteCompareChecker)
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


def _pipeline_v1(rng: Rng, length: int) -> tuple[Transform, ...]:
    # Alternate ops: two adjacent XORs (or rotates) would collapse into one.
    ops = ["rol", "xor"]
    steps = rng.randint(2, 4)
    current = rng.choice(ops)
    pipeline: list[Transform] = []
    for i in range(steps):
        pipeline.append(TRANSFORM_TYPES[current].generate(rng.fork(f"step/{i}"), length))
        current = rng.choice([op for op in ops if op != current])
    return tuple(pipeline)


def _pipeline_v2(rng: Rng, length: int) -> tuple[Transform, ...]:
    ops = sorted(TRANSFORM_TYPES)
    steps = rng.randint(3, 5)
    chosen: list[str] = []
    for _ in range(steps):
        allowed = [
            op
            for op in ops
            if not (chosen and _MERGE_GROUP[op] == _MERGE_GROUP[chosen[-1]])
            and not (op in _AT_MOST_ONCE and op in chosen)
        ]
        chosen.append(rng.choice(allowed))
    return tuple(
        TRANSFORM_TYPES[op].generate(rng.fork(f"step/{i}"), length) for i, op in enumerate(chosen)
    )
