from __future__ import annotations

import json
from typing import Any

import pytest

from binarygym.errors import SpecError
from binarygym.families import get_family
from binarygym.spec import ChallengeSpec


def spec_dict() -> dict[str, Any]:
    return get_family("transformation").generate(12345).to_dict()


def test_json_roundtrip() -> None:
    spec = get_family("transformation").generate(12345)
    assert ChallengeSpec.from_json(spec.to_json()) == spec


def test_large_seed_roundtrip() -> None:
    spec = get_family("transformation").generate(2**128 - 1)
    assert ChallengeSpec.from_json(spec.to_json()).seed == 2**128 - 1


def test_spec_is_backend_independent() -> None:
    text = json.dumps(spec_dict()).lower()
    for backend_term in ("clang", "gcc", "strategy", "fused_loop", "staged_passes", "-o2"):
        assert backend_term not in text


def mutate(path: list[str], value: object) -> dict[str, Any]:
    d = spec_dict()
    node = d
    for key in path[:-1]:
        node = node[key]
    if value is DELETE:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return d


DELETE = object()


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (["schema_version"], 99),
        (["seed"], 12345),  # must be a string
        (["seed"], "-5"),
        (["goal"], "pwn"),
        (["safety_class"], "malware"),
        (["family"], DELETE),
        (["unexpected"], 1),
        (["secret", "value"], "has space!"),
        (["checker", "expected"], "zz"),
        (["checker", "expected"], "00"),  # wrong length
        (["checker", "kind"], "state_machine"),
        (["checker", "pipeline"], []),
        (["checker", "pipeline"], [{"op": "nope"}]),
        (["challenge_id"], "bg-0000000000000000"),  # does not match content
        (["challenge_id"], "../../etc/passwd"),
    ],
)
def test_malformed_specs_rejected(path: list[str], value: object) -> None:
    with pytest.raises(SpecError):
        ChallengeSpec.from_dict(mutate(path, value))


def test_inconsistent_expected_rejected() -> None:
    d = spec_dict()
    expected = bytearray.fromhex(d["checker"]["expected"])
    expected[0] ^= 1
    d["checker"]["expected"] = expected.hex()
    with pytest.raises(SpecError, match="does not accept the secret"):
        ChallengeSpec.from_dict(d)


def test_invalid_json_rejected() -> None:
    with pytest.raises(SpecError):
        ChallengeSpec.from_json("{not json")
