"""Byte-level transformation primitives.

Each primitive is a frozen dataclass with:

* ``generate(rng, length)`` - deterministic parameter generation for an input of ``length``,
* ``apply(data)``    - the reference implementation (source of truth for ``expected``),
* ``invert(data)``   - the inverse, used by property tests to prove the primitive is a
  bijection (so a challenge has exactly one answer). It is *not* used to derive solutions:
  the generated secret is the authoritative answer.
* ``concept``        - what the primitive exercises, for metadata and future hints.
* ``position_dependent`` / ``reorders`` - structural properties backends rely on when
  deciding which rendering strategies can express a pipeline.

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
    position_dependent: ClassVar[bool]
    reorders: ClassVar[bool]

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


def _hex_param(params: dict[str, Any], name: str) -> bytes:
    value = params.get(name)
    if not isinstance(value, str):
        raise SpecError(f"parameter {name!r} must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise SpecError(f"parameter {name!r} must be a hex string") from exc


@dataclass(frozen=True)
class XorConst:
    """XOR every byte with one constant."""

    key: int
    op: ClassVar[str] = "xor"
    param_names: ClassVar[frozenset[str]] = frozenset({"key"})
    concept: ClassVar[str] = "bytewise XOR with a constant"
    position_dependent: ClassVar[bool] = False
    reorders: ClassVar[bool] = False

    def __post_init__(self) -> None:
        _int_param({"key": self.key}, "key", 1, 255)

    @classmethod
    def generate(cls, rng: Rng, length: int) -> XorConst:
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
class AddConst:
    """Add a constant to every byte, modulo 256 (subtraction is adding ``256 - k``)."""

    addend: int
    op: ClassVar[str] = "add"
    param_names: ClassVar[frozenset[str]] = frozenset({"addend"})
    concept: ClassVar[str] = "modular byte addition"
    position_dependent: ClassVar[bool] = False
    reorders: ClassVar[bool] = False

    def __post_init__(self) -> None:
        _int_param({"addend": self.addend}, "addend", 1, 255)

    @classmethod
    def generate(cls, rng: Rng, length: int) -> AddConst:
        return cls(addend=rng.randint(1, 255))

    def apply(self, data: bytes) -> bytes:
        return bytes((b + self.addend) & 0xFF for b in data)

    def invert(self, data: bytes) -> bytes:
        return bytes((b - self.addend) & 0xFF for b in data)

    def params(self) -> dict[str, Any]:
        return {"addend": self.addend}

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> AddConst:
        return cls(addend=_int_param(params, "addend", 1, 255))


@dataclass(frozen=True)
class RotateLeft:
    """Rotate every byte left by a fixed number of bits."""

    bits: int
    op: ClassVar[str] = "rol"
    param_names: ClassVar[frozenset[str]] = frozenset({"bits"})
    concept: ClassVar[str] = "8-bit rotate left"
    position_dependent: ClassVar[bool] = False
    reorders: ClassVar[bool] = False

    def __post_init__(self) -> None:
        _int_param({"bits": self.bits}, "bits", 1, 7)

    @classmethod
    def generate(cls, rng: Rng, length: int) -> RotateLeft:
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


@dataclass(frozen=True)
class PositionXor:
    """XOR byte ``i`` with ``(mul * i + offset) mod 256`` - a simple position-keyed stream."""

    mul: int
    offset: int
    op: ClassVar[str] = "pxor"
    param_names: ClassVar[frozenset[str]] = frozenset({"mul", "offset"})
    concept: ClassVar[str] = "position-dependent XOR key"
    position_dependent: ClassVar[bool] = True
    reorders: ClassVar[bool] = False

    def __post_init__(self) -> None:
        _int_param({"mul": self.mul}, "mul", 1, 255)
        _int_param({"offset": self.offset}, "offset", 0, 255)

    @classmethod
    def generate(cls, rng: Rng, length: int) -> PositionXor:
        return cls(mul=rng.randint(1, 255), offset=rng.randint(0, 255))

    def key_at(self, i: int) -> int:
        return (self.mul * i + self.offset) & 0xFF

    def apply(self, data: bytes) -> bytes:
        return bytes(b ^ self.key_at(i) for i, b in enumerate(data))

    def invert(self, data: bytes) -> bytes:
        return self.apply(data)

    def params(self) -> dict[str, Any]:
        return {"mul": self.mul, "offset": self.offset}

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> PositionXor:
        return cls(
            mul=_int_param(params, "mul", 1, 255), offset=_int_param(params, "offset", 0, 255)
        )


@dataclass(frozen=True)
class Substitution:
    """Map every byte through a 256-entry permutation table (an S-box)."""

    table: bytes
    op: ClassVar[str] = "sbox"
    param_names: ClassVar[frozenset[str]] = frozenset({"table"})
    concept: ClassVar[str] = "lookup-table substitution"
    position_dependent: ClassVar[bool] = False
    reorders: ClassVar[bool] = False

    def __post_init__(self) -> None:
        if sorted(self.table) != list(range(256)):
            raise SpecError("sbox table must be a permutation of 0..255")

    @classmethod
    def generate(cls, rng: Rng, length: int) -> Substitution:
        table = bytes(rng.shuffled(range(256)))
        # Fixed points would leave some input bytes visible unchanged; re-draw until none.
        while any(table[i] == i for i in range(256)):
            table = bytes(rng.shuffled(range(256)))
        return cls(table=table)

    def apply(self, data: bytes) -> bytes:
        return bytes(self.table[b] for b in data)

    def invert(self, data: bytes) -> bytes:
        inverse = bytearray(256)
        for i, v in enumerate(self.table):
            inverse[v] = i
        return bytes(inverse[b] for b in data)

    def params(self) -> dict[str, Any]:
        return {"table": self.table.hex()}

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> Substitution:
        return cls(table=_hex_param(params, "table"))


@dataclass(frozen=True)
class Permutation:
    """Reorder bytes: output position ``j`` takes input byte ``order[j]``.

    Only defined for inputs of exactly ``len(order)`` bytes.
    """

    order: tuple[int, ...]
    op: ClassVar[str] = "perm"
    param_names: ClassVar[frozenset[str]] = frozenset({"order"})
    concept: ClassVar[str] = "byte reordering"
    position_dependent: ClassVar[bool] = True
    reorders: ClassVar[bool] = True

    def __post_init__(self) -> None:
        if sorted(self.order) != list(range(len(self.order))) or len(self.order) < 2:
            raise SpecError("perm order must be a permutation of 0..n-1 with n >= 2")

    @classmethod
    def generate(cls, rng: Rng, length: int) -> Permutation:
        identity = list(range(length))
        order = rng.shuffled(identity)
        while order == identity:
            order = rng.shuffled(identity)
        return cls(order=tuple(order))

    def _check(self, data: bytes) -> None:
        if len(data) != len(self.order):
            raise ValueError(f"perm expects {len(self.order)} bytes, got {len(data)}")

    def apply(self, data: bytes) -> bytes:
        self._check(data)
        return bytes(data[src] for src in self.order)

    def invert(self, data: bytes) -> bytes:
        self._check(data)
        out = bytearray(len(data))
        for j, src in enumerate(self.order):
            out[src] = data[j]
        return bytes(out)

    def params(self) -> dict[str, Any]:
        return {"order": list(self.order)}

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> Permutation:
        order = params.get("order")
        if not isinstance(order, list) or not all(type(i) is int for i in order):
            raise SpecError("parameter 'order' must be a list of integers")
        return cls(order=tuple(order))


TransformType = (
    type[XorConst]
    | type[AddConst]
    | type[RotateLeft]
    | type[PositionXor]
    | type[Substitution]
    | type[Permutation]
)

TRANSFORM_TYPES: dict[str, TransformType] = {
    t.op: t for t in (XorConst, AddConst, RotateLeft, PositionXor, Substitution, Permutation)
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
