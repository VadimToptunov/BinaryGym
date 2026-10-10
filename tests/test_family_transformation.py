from __future__ import annotations

import os
import random
import time
from itertools import pairwise

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from binarygym import reference
from binarygym.families import get_family
from binarygym.rng import MAX_SEED
from binarygym.transforms import apply_pipeline

family = get_family("transformation")


def test_same_seed_same_spec() -> None:
    a, b = family.generate(12345), family.generate(12345)
    assert a == b
    assert a.to_json() == b.to_json()


def test_golden_seed_12345() -> None:
    # Frozen logical challenge. If this changes, bump family_version.
    spec = family.generate(12345)
    assert spec.secret.value == "qtvaRrtz"
    assert spec.checker.expected.hex() == "2b6aea2fe3eb6ae9"
    assert [t.op for t in spec.checker.pipeline] == ["xor", "rol", "xor", "rol"]
    assert spec.challenge_id == "bg-a8de85d2de201eeb"


def test_seeds_produce_varied_challenges() -> None:
    specs = [family.generate(s) for s in range(1000, 1100)]
    assert len({s.secret.value for s in specs}) == 100
    assert len({s.checker.expected for s in specs}) == 100
    assert len({tuple(t.op for t in s.checker.pipeline) for s in specs}) > 1
    assert len({len(s.checker.pipeline) for s in specs}) > 1
    assert len({s.challenge_id for s in specs}) == 100


def test_generation_uses_no_ambient_randomness(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("ambient randomness/time used during generation")

    for name in ("random", "randint", "choice", "getrandbits", "shuffle"):
        monkeypatch.setattr(random, name, forbidden)
    monkeypatch.setattr(os, "urandom", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    family.generate(777)


@settings(max_examples=200)
@given(st.integers(0, MAX_SEED))
def test_every_seed_yields_a_consistent_challenge(seed: int) -> None:
    spec = family.generate(seed)
    secret = spec.secret.value.encode()
    # The generated secret is the authoritative answer and expected derives from it.
    assert apply_pipeline(spec.checker.pipeline, secret) == spec.checker.expected
    assert reference.accepts(spec, secret + b"\n")
    assert 8 <= len(secret) <= 16
    ops = [t.op for t in spec.checker.pipeline]
    assert all(a != b for a, b in pairwise(ops))  # no collapsible neighbours


@given(st.integers(0, 2**32), st.binary(max_size=40))
def test_only_the_secret_is_accepted(seed: int, guess: bytes) -> None:
    spec = family.generate(seed)
    candidate = reference.candidate_from_line(guess)
    assert reference.accepts(spec, guess) == (candidate == spec.secret.value.encode())


def test_solution_is_machine_readable() -> None:
    spec = family.generate(12345)
    sol = family.solution(spec)
    assert sol["answer"] == spec.secret.value
    assert [s["op"] for s in sol["stages"]] == [t.op for t in spec.checker.pipeline]
