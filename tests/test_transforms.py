from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from binarygym.errors import SpecError
from binarygym.rng import Rng
from binarygym.transforms import (
    TRANSFORM_TYPES,
    AddConst,
    Permutation,
    PositionXor,
    RotateLeft,
    Substitution,
    Transform,
    XorConst,
    apply_pipeline,
    invert_pipeline,
    transform_from_dict,
    transform_to_dict,
)

LENGTH = 12


def transforms_for(length: int) -> st.SearchStrategy[Transform]:
    """Any primitive, generated through its own seeded ``generate``."""
    return st.builds(
        lambda op, seed: TRANSFORM_TYPES[op].generate(Rng.from_seed(seed), length),
        st.sampled_from(sorted(TRANSFORM_TYPES)),
        st.integers(0, 2**64),
    )


inputs = st.binary(min_size=LENGTH, max_size=LENGTH)


@given(transforms_for(LENGTH), inputs)
def test_invert_undoes_apply(t: Transform, data: bytes) -> None:
    assert t.invert(t.apply(data)) == data


@given(st.lists(transforms_for(LENGTH), min_size=1, max_size=6), inputs)
def test_pipeline_is_bijective(pipeline: list[Transform], data: bytes) -> None:
    p = tuple(pipeline)
    assert invert_pipeline(p, apply_pipeline(p, data)) == data


@given(st.lists(transforms_for(LENGTH), min_size=1, max_size=6), inputs, inputs)
def test_distinct_inputs_never_collide(pipeline: list[Transform], a: bytes, b: bytes) -> None:
    # Bijectivity is what guarantees a challenge has exactly one accepted answer.
    if a != b:
        assert apply_pipeline(tuple(pipeline), a) != apply_pipeline(tuple(pipeline), b)


@given(transforms_for(LENGTH))
def test_serialization_roundtrip(t: Transform) -> None:
    assert transform_from_dict(transform_to_dict(t)) == t


def test_reference_values() -> None:
    assert XorConst(0x0F).apply(b"\xf0") == b"\xff"
    assert AddConst(0x02).apply(b"\xff") == b"\x01"
    assert RotateLeft(1).apply(b"\x81") == b"\x03"
    assert PositionXor(mul=1, offset=0).apply(b"\x00\x00\x00") == b"\x00\x01\x02"
    assert Permutation(order=(2, 0, 1)).apply(b"abc") == b"cab"
    table = bytes([(i + 1) % 256 for i in range(256)])
    assert Substitution(table).apply(b"\x00\xff") == b"\x01\x00"


def test_generated_sbox_has_no_fixed_points() -> None:
    for seed in range(20):
        table = Substitution.generate(Rng.from_seed(seed), LENGTH).table
        assert all(table[i] != i for i in range(256))


def test_generated_permutation_is_not_identity() -> None:
    for seed in range(50):
        order = Permutation.generate(Rng.from_seed(seed), 2).order
        assert order == (1, 0)


def test_permutation_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        Permutation(order=(1, 0)).apply(b"abc")


@pytest.mark.parametrize(
    "raw",
    [
        {"op": "xor", "key": 0},  # identity XOR is rejected
        {"op": "xor", "key": 256},
        {"op": "add", "addend": 0},
        {"op": "rol", "bits": 8},
        {"op": "rol", "bits": "3"},
        {"op": "rol"},
        {"op": "pxor", "mul": 0, "offset": 1},
        {"op": "sbox", "table": "00" * 256},  # not a permutation
        {"op": "sbox", "table": "zz"},
        {"op": "perm", "order": [0, 0]},
        {"op": "perm", "order": [0]},
        {"op": "perm", "order": "01"},
        {"op": "xor", "key": 1, "extra": 2},
        {"op": "aes", "key": 1},
        "xor",
    ],
)
def test_malformed_transforms_rejected(raw: object) -> None:
    with pytest.raises(SpecError):
        transform_from_dict(raw)
