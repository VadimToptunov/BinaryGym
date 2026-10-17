"""Byte-level transformation primitives.

Each primitive is a frozen dataclass with:

* ``generate(rng)``  - deterministic parameter generation,
* ``apply(data)``    - the reference implementation (source of truth for ``expected``),
* ``invert(data)``   - the inverse, used by property tests to prove the primitive is a
  bijection (so a challenge has exactly one answer). It is *not* used to derive solutions:
  the generated secret is the authoritative answer.
* ``concept``        - what the primitive exercises, for metadata and future hints.

Rendering into a target language lives in the backends, not here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Protocol

from binarygym.errors import SpecError
from binarygym.rng import Rng


class Transform(Protocol):
    op: ClassVar[str]
    concept: ClassVar[str]

    def apply(self, data: bytes) -> bytes: ...
    def invert(self, data: bytes) -> bytes: ...
    def params(self) -> dict[str, Any]: ...


def _rol8(b: int, n: int) -> int:
    return ((b << n) | (b >> (8 - n))) & 0xFF


def _int_param(params: dict[str, Any], name: str, lo: int, hi: int) -> int:
    value = params.get(name)
    if type(value) is not int or not lo <= value <= hi:
        raise SpecError(f"parameter {name!r} must be an int in [{lo}, {hi}], got {value!r}")
    return value


@dataclass(frozen=True)
class XorConst:
    """XOR every byte with one constant."""

    key: int
    op: ClassVar[str] = "xor"
    param_names: ClassVar[frozenset[str]] = frozenset({"key"})
    concept: ClassVar[str] = "bytewise XOR with a constant"

    def __post_init__(self) -> None:
        _int_param({"key": self.key}, "key", 1, 255)

    @classmethod
    def generate(cls, rng: Rng) -> XorConst:
        return cls(key=rng.randint(1, 255))

    def apply(self, data: bytes) -> bytes:
        return bytes(b ^ self.key for b in data)

    def invert(self, data: bytes) -> bytes:
        return self.apply(data)

    def params(self) -> dict[str, Any]:
        return {"key": self.key}

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> XorConst:
        return cls(key=_int_param(params, "key", 1, 255))


@dataclass(frozen=True)
class RotateLeft:
    """Rotate every byte left by a fixed number of bits."""

    bits: int
    op: ClassVar[str] = "rol"
    param_names: ClassVar[frozenset[str]] = frozenset({"bits"})
    concept: ClassVar[str] = "8-bit rotate left"

    def __post_init__(self) -> None:
        _int_param({"bits": self.bits}, "bits", 1, 7)

    @classmethod
    def generate(cls, rng: Rng) -> RotateLeft:
        return cls(bits=rng.randint(1, 7))

    def apply(self, data: bytes) -> bytes:
        return bytes(_rol8(b, self.bits) for b in data)

    def invert(self, data: bytes) -> bytes:
        return bytes(_rol8(b, 8 - self.bits) for b in data)

    def params(self) -> dict[str, Any]:
        return {"bits": self.bits}

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> RotateLeft:
        return cls(bits=_int_param(params, "bits", 1, 7))


TRANSFORM_TYPES: dict[str, type[XorConst] | type[RotateLeft]] = {
    XorConst.op: XorConst,
    RotateLeft.op: RotateLeft,
}


def apply_pipeline(pipeline: tuple[Transform, ...], data: bytes) -> bytes:
    for step in pipeline:
        data = step.apply(data)
    return data


def invert_pipeline(pipeline: tuple[Transform, ...], data: bytes) -> bytes:
    for step in reversed(pipeline):
        data = step.invert(data)
    return data


def transform_to_dict(t: Transform) -> dict[str, Any]:
    return {"op": t.op, **t.params()}


def transform_from_dict(raw: Any) -> Transform:
    if not isinstance(raw, dict):
        raise SpecError(f"transform must be an object, got {type(raw).__name__}")
    params = dict(raw)
    op = params.pop("op", None)
    cls = TRANSFORM_TYPES.get(op) if isinstance(op, str) else None
    if cls is None:
        raise SpecError(f"unknown transform op {op!r}")
    if set(params) != cls.param_names:
        raise SpecError(
            f"transform {op!r} expects parameters {sorted(cls.param_names)}, got {sorted(params)}"
        )
    return cls.from_params(params)
