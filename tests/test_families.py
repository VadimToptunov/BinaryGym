from __future__ import annotations

import hashlib
import os
import random
import time
from itertools import pairwise

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from binarygym import reference
from binarygym.errors import BinaryGymError
from binarygym.families import FAMILIES, get_family
from binarygym.rng import MAX_SEED
from binarygym.spec import ByteCompareChecker, StateMachineChecker, canonical_json
from binarygym.transforms import apply_pipeline

ALL_VERSIONS = [(name, v) for name, f in sorted(FAMILIES.items()) for v in f.versions]


@pytest.mark.parametrize(("name", "version"), ALL_VERSIONS)
def test_same_seed_same_spec(name: str, version: int) -> None:
    family = get_family(name)
    assert family.generate(12345, version).to_json() == family.generate(12345, version).to_json()


@pytest.mark.parametrize(("name", "version"), ALL_VERSIONS)
def test_seeds_produce_varied_challenges(name: str, version: int) -> None:
    family = get_family(name)
    specs = [family.generate(s, version) for s in range(1000, 1060)]
    assert len({s.secret.value for s in specs}) == 60
    assert len({s.challenge_id for s in specs}) == 60


@pytest.mark.parametrize(("name", "version"), ALL_VERSIONS)
def test_generation_uses_no_ambient_randomness(
    name: str, version: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("ambient randomness/time used during generation")

    for attr in ("random", "randint", "choice", "getrandbits", "shuffle"):
        monkeypatch.setattr(random, attr, forbidden)
    monkeypatch.setattr(os, "urandom", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    get_family(name).generate(777, version)


@pytest.mark.parametrize(("name", "version"), ALL_VERSIONS)
@settings(max_examples=40, deadline=None)
@given(seed=st.integers(0, MAX_SEED), guess=st.binary(max_size=24))
def test_only_the_secret_is_accepted(name: str, version: int, seed: int, guess: bytes) -> None:
    spec = get_family(name).generate(seed, version)
    secret = spec.secret.value.encode()
    assert reference.accepts(spec, secret + b"\n")
    assert reference.accepts(spec, guess) == (reference.candidate_from_line(guess) == secret)
    assert spec.checker.accepted_count() == 1


def test_transformation_v1_is_frozen() -> None:
    # Golden: v1 must keep generating the same logical challenge across releases.
    spec = get_family("transformation").generate(12345, 1)
    assert spec.secret.value == "qtvaRrtz"
    assert isinstance(spec.checker, ByteCompareChecker)
    assert spec.checker.expected.hex() == "2b6aea2fe3eb6ae9"
    assert [t.op for t in spec.checker.pipeline] == ["xor", "rol", "xor", "rol"]


GOLDEN = {  # (family_version, secret, sha256(checker)[:16]) for seed 12345
    "transformation": (2, "CxRg69Telsj", "8bbe4f1a0c051e3b"),
    "direct": (1, "E0TLzINmfoO9J", "e80ededcf7edd9cb"),
    "state_machine": (1, "GV7wVtutWOz4Tby", "1b4384c976d284d6"),
}


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_latest_versions_are_frozen(name: str) -> None:
    # A change here means the logical challenge changed: bump that family's version.
    spec = get_family(name).generate(12345)
    digest = hashlib.sha256(canonical_json(spec.checker.to_dict()).encode()).hexdigest()[:16]
    assert (spec.family_version, spec.secret.value, digest) == GOLDEN[name]


@settings(max_examples=200)
@given(st.integers(0, MAX_SEED))
def test_transformation_v2_pipelines_follow_the_rules(seed: int) -> None:
    spec = get_family("transformation").generate(seed, 2)
    assert isinstance(spec.checker, ByteCompareChecker)
    ops = [t.op for t in spec.checker.pipeline]
    assert 3 <= len(ops) <= 5
    assert ops.count("sbox") <= 1 and ops.count("perm") <= 1
    groups = ["xor" if op in ("xor", "pxor") else op for op in ops]
    assert all(a != b for a, b in pairwise(groups))  # no collapsible neighbours
    secret = spec.secret.value.encode()
    assert apply_pipeline(spec.checker.pipeline, secret) == spec.checker.expected


def test_transformation_v2_uses_every_primitive() -> None:
    ops = set()
    for seed in range(300):
        spec = get_family("transformation").generate(seed)
        assert isinstance(spec.checker, ByteCompareChecker)
        ops |= {t.op for t in spec.checker.pipeline}
    assert ops == {"xor", "add", "rol", "pxor", "sbox", "perm"}


def test_direct_family_embeds_plaintext_by_design() -> None:
    spec = get_family("direct").generate(5)
    assert spec.checker.embeds_plaintext()
    assert isinstance(spec.checker, ByteCompareChecker)
    assert spec.checker.expected == spec.secret.value.encode()


def test_state_machine_hides_the_path() -> None:
    sizes, starts = set(), set()
    for seed in range(50):
        spec = get_family("state_machine").generate(seed)
        checker = spec.checker
        assert isinstance(checker, StateMachineChecker)
        sizes.add(checker.state_count)
        starts.add(checker.start)
        # The machine has real structure: back edges and decoys, not just a straight chain.
        live = sum(1 for row in checker.rows for s in row if s != checker.dead)
        assert live > checker.input_length * 2
    assert len(sizes) > 3 and len(starts) > 5  # numbering is shuffled


def test_state_machine_rejects_wrong_length_walks() -> None:
    # Back edges can reach the accept state with a longer input; the length check stops it.
    spec = get_family("state_machine").generate(3)
    assert not reference.accepts(spec, spec.secret.value.encode() * 2)


@pytest.mark.parametrize("name", sorted(FAMILIES))
def test_solution_is_machine_readable(name: str) -> None:
    family = get_family(name)
    spec = family.generate(12345)
    sol = family.solution(spec)
    assert sol["answer"] == spec.secret.value
    assert sol["input_length"] == len(spec.secret.value)


def test_unknown_version_rejected() -> None:
    with pytest.raises(BinaryGymError, match="no version 9"):
        get_family("transformation").generate(1, 9)
