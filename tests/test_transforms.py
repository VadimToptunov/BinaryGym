from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from binarygym.errors import SpecError
from binarygym.transforms import (
    RotateLeft,
    Transform,
    XorConst,
    apply_pipeline,
    invert_pipeline,
    transform_from_dict,
    transform_to_dict,
)

xors = st.integers(1, 255).map(lambda k: XorConst(key=k))
rols = st.integers(1, 7).map(lambda b: RotateLeft(bits=b))
transforms: st.SearchStrategy[Transform] = st.one_of(xors, rols)


@given(transforms, st.binary(max_size=64))
def test_invert_undoes_apply(t: Transform, data: bytes) -> None:
    assert t.invert(t.apply(data)) == data


@given(st.lists(transforms, min_size=1, max_size=6), st.binary(max_size=64))
def test_pipeline_is_bijective(pipeline: list[Transform], data: bytes) -> None:
    p = tuple(pipeline)
    assert invert_pipeline(p, apply_pipeline(p, data)) == data


@given(st.lists(transforms, min_size=1, max_size=6), st.binary(min_size=1, max_size=16),
       st.binary(min_size=1, max_size=16))  # fmt: skip
def test_distinct_inputs_never_collide(pipeline: list[Transform], a: bytes, b: bytes) -> None:
    # Bijectivity is what guarantees a challenge has exactly one accepted answer.
    if a != b and len(a) == len(b):
        assert apply_pipeline(tuple(pipeline), a) != apply_pipeline(tuple(pipeline), b)


@given(transforms)
def test_serialization_roundtrip(t: Transform) -> None:
    assert transform_from_dict(transform_to_dict(t)) == t


def test_reference_values() -> None:
    assert XorConst(0x0F).apply(b"\xf0") == b"\xff"
    assert RotateLeft(1).apply(b"\x81") == b"\x03"


@pytest.mark.parametrize(
    "raw",
    [
        {"op": "xor", "key": 0},  # identity XOR is rejected
        {"op": "xor", "key": 256},
        {"op": "rol", "bits": 8},
        {"op": "rol", "bits": "3"},
        {"op": "rol"},
        {"op": "xor", "key": 1, "extra": 2},
        {"op": "aes", "key": 1},
        "xor",
    ],
)
def test_malformed_transforms_rejected(raw: object) -> None:
    with pytest.raises(SpecError):
        transform_from_dict(raw)
