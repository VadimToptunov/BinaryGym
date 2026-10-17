from __future__ import annotations

import json
from typing import Any

import pytest

from binarygym.errors import SpecError
from binarygym.families import FAMILIES, get_family
from binarygym.spec import ChallengeSpec, StateMachineChecker

DELETE = object()


def spec_dict(family: str = "transformation") -> dict[str, Any]:
    return get_family(family).generate(12345).to_dict()


@pytest.mark.parametrize("family", sorted(FAMILIES))
def test_json_roundtrip(family: str) -> None:
    spec = get_family(family).generate(12345)
    assert ChallengeSpec.from_json(spec.to_json()) == spec


def test_large_seed_roundtrip() -> None:
    spec = get_family("transformation").generate(2**128 - 1)
    assert ChallengeSpec.from_json(spec.to_json()).seed == 2**128 - 1


@pytest.mark.parametrize("family", sorted(FAMILIES))
def test_spec_is_platform_and_backend_independent(family: str) -> None:
    text = json.dumps(spec_dict(family)).lower()
    for term in ("linux", "x86", "elf", "clang", "gcc", "strategy", "fused_loop", "target"):
        assert term not in text


def mutate(d: dict[str, Any], path: list[str], value: object) -> dict[str, Any]:
    node = d
    for key in path[:-1]:
        node = node[key]
    if value is DELETE:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return d


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (["schema_version"], 1),  # old schema: explicit, clear rejection
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
        (["checker", "kind"], "neural_net"),
        (["checker", "pipeline"], [{"op": "nope"}]),
        (["challenge_id"], "bg-0000000000000000"),  # does not match content
        (["challenge_id"], "../../etc/passwd"),
    ],
)
def test_malformed_specs_rejected(path: list[str], value: object) -> None:
    with pytest.raises(SpecError):
        ChallengeSpec.from_dict(mutate(spec_dict(), path, value))


def test_old_schema_error_explains_how_to_recover() -> None:
    with pytest.raises(SpecError, match="regenerate"):
        ChallengeSpec.from_dict(mutate(spec_dict(), ["schema_version"], 1))


def test_inconsistent_expected_rejected() -> None:
    d = spec_dict()
    expected = bytearray.fromhex(d["checker"]["expected"])
    expected[0] ^= 1
    d["checker"]["expected"] = expected.hex()
    with pytest.raises(SpecError, match="does not accept the secret"):
        ChallengeSpec.from_dict(d)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (["checker", "start"], 999),
        (["checker", "rows"], []),
        (["checker", "rows", 0], "00"),  # short row
        (["checker", "input_length"], 0),
    ],
)
def test_malformed_state_machines_rejected(path: list[Any], value: object) -> None:
    with pytest.raises(SpecError):
        ChallengeSpec.from_dict(mutate(spec_dict("state_machine"), path, value))


def test_state_machine_with_second_answer_rejected() -> None:
    d = spec_dict("state_machine")
    checker = StateMachineChecker.from_dict(d["checker"])
    secret = d["secret"]["value"].encode()
    # Add a second forward edge at the first step: another first character now also works.
    row = bytearray(checker.rows[checker.start])
    other = next(c for c in b"ABCDEFGHIJ" if c != secret[0])
    row[other] = row[secret[0]]
    d["checker"]["rows"][checker.start] = bytes(row).hex()
    with pytest.raises(SpecError, match="more than one answer"):
        ChallengeSpec.from_dict(d)


def test_invalid_json_rejected() -> None:
    with pytest.raises(SpecError):
        ChallengeSpec.from_json("{not json")
