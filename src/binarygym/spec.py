"""ChallengeSpec: the platform-independent source of truth for a challenge.

Generated source code and binaries are artifacts derived from a spec. A spec
contains no backend-specific information (no C, no compiler flags, no render
strategy), so the same spec can later be lowered by other backends.

Serialization is explicit and strict: unknown or missing fields, invalid values
and internally inconsistent specs raise :class:`SpecError`.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from typing import Any

from binarygym import __version__
from binarygym.errors import SpecError
from binarygym.rng import MAX_SEED
from binarygym.transforms import (
    Transform,
    apply_pipeline,
    transform_from_dict,
    transform_to_dict,
)

SCHEMA_VERSION = 1
GOAL_RECOVER_SECRET = "recover_secret"
SAFETY_BENIGN_RE = "benign_re"
_ID_RE = re.compile(r"^bg-[0-9a-f]{16}$")
_PLACEHOLDER_ID = "bg-" + "0" * 16


def _obj(raw: Any, where: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SpecError(f"{where} must be an object")
    missing, extra = keys - raw.keys(), raw.keys() - keys
    if missing or extra:
        raise SpecError(f"{where}: missing {sorted(missing)}, unexpected {sorted(extra)}")
    return raw


def _str(raw: Any, where: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise SpecError(f"{where} must be a non-empty string")
    return raw


def _int(raw: Any, where: str) -> int:
    if type(raw) is not int:
        raise SpecError(f"{where} must be an integer")
    return raw


@dataclass(frozen=True)
class Target:
    platform: str
    arch: str
    language: str

    def to_dict(self) -> dict[str, Any]:
        return {"platform": self.platform, "arch": self.arch, "language": self.language}

    @classmethod
    def from_dict(cls, raw: Any) -> Target:
        d = _obj(raw, "target", {"platform", "arch", "language"})
        return cls(
            _str(d["platform"], "target.platform"),
            _str(d["arch"], "target.arch"),
            _str(d["language"], "target.language"),
        )


@dataclass(frozen=True)
class Secret:
    """The authoritative intended answer. Private."""

    alphabet: str
    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.isascii() or not self.alphabet.isascii():
            raise SpecError("secret and alphabet must be non-empty ASCII")
        if any(c not in self.alphabet for c in self.value):
            raise SpecError("secret contains characters outside its alphabet")

    def to_dict(self) -> dict[str, Any]:
        return {"alphabet": self.alphabet, "value": self.value}

    @classmethod
    def from_dict(cls, raw: Any) -> Secret:
        d = _obj(raw, "secret", {"alphabet", "value"})
        return cls(_str(d["alphabet"], "secret.alphabet"), _str(d["value"], "secret.value"))


@dataclass(frozen=True)
class ByteCompareChecker:
    """Accept an input of ``input_length`` bytes iff ``pipeline(input) == expected``."""

    input_length: int
    pipeline: tuple[Transform, ...]
    expected: bytes
    kind: str = field(default="byte_compare", init=False)

    def __post_init__(self) -> None:
        if not 1 <= self.input_length <= 64:
            raise SpecError("checker.input_length must be in [1, 64]")
        if len(self.expected) != self.input_length:
            raise SpecError("checker.expected length does not match input_length")
        if not self.pipeline:
            raise SpecError("checker.pipeline must not be empty")

    def accepts(self, candidate: bytes) -> bool:
        """Reference evaluator on the exact candidate bytes."""
        return (
            len(candidate) == self.input_length
            and apply_pipeline(self.pipeline, candidate) == self.expected
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "input_length": self.input_length,
            "pipeline": [transform_to_dict(t) for t in self.pipeline],
            "expected": self.expected.hex(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ByteCompareChecker:
        d = _obj(raw, "checker", {"kind", "input_length", "pipeline", "expected"})
        if d["kind"] != "byte_compare":
            raise SpecError(f"unsupported checker kind {d['kind']!r}")
        if not isinstance(d["pipeline"], list):
            raise SpecError("checker.pipeline must be a list")
        try:
            expected = bytes.fromhex(_str(d["expected"], "checker.expected"))
        except ValueError as exc:
            raise SpecError("checker.expected must be hex") from exc
        return cls(
            input_length=_int(d["input_length"], "checker.input_length"),
            pipeline=tuple(transform_from_dict(t) for t in d["pipeline"]),
            expected=expected,
        )


@dataclass(frozen=True)
class Difficulty:
    """Heuristic, multi-dimensional difficulty. Not an empirical measurement."""

    dimensions: dict[str, int]
    label: str
    method: str = "heuristic-v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimensions": dict(sorted(self.dimensions.items())),
            "label": self.label,
            "method": self.method,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> Difficulty:
        d = _obj(raw, "difficulty", {"dimensions", "label", "method"})
        dims = d["dimensions"]
        if not isinstance(dims, dict) or not all(
            isinstance(k, str) and type(v) is int for k, v in dims.items()
        ):
            raise SpecError("difficulty.dimensions must map names to integers")
        return cls(
            dict(dims), _str(d["label"], "difficulty.label"), _str(d["method"], "difficulty.method")
        )


@dataclass(frozen=True)
class ChallengeSpec:
    challenge_id: str
    family: str
    family_version: int
    seed: int
    goal: str
    target: Target
    secret: Secret
    checker: ByteCompareChecker
    difficulty: Difficulty
    safety_class: str = SAFETY_BENIGN_RE
    generator_version: str = __version__
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SpecError(f"unsupported schema_version {self.schema_version}")
        if not 0 <= self.seed <= MAX_SEED:
            raise SpecError("seed out of range")
        if self.goal != GOAL_RECOVER_SECRET:
            raise SpecError(f"unsupported goal {self.goal!r}")
        if self.safety_class != SAFETY_BENIGN_RE:
            raise SpecError(f"unsupported safety_class {self.safety_class!r}")
        if not self.checker.accepts(self.secret.value.encode("ascii")):
            raise SpecError("inconsistent spec: the checker does not accept the secret")
        if not _ID_RE.match(self.challenge_id):
            raise SpecError(f"malformed challenge_id {self.challenge_id!r}")

    @classmethod
    def create(cls, **fields: Any) -> ChallengeSpec:
        """Build a spec whose ``challenge_id`` is derived from its content."""
        provisional = cls(challenge_id=_PLACEHOLDER_ID, **fields)
        return replace(provisional, challenge_id=compute_challenge_id(provisional._content_dict()))

    def _content_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generator_version": self.generator_version,
            "family": self.family,
            "family_version": self.family_version,
            "seed": str(self.seed),  # string: 128-bit ints are not JSON-portable
            "goal": self.goal,
            "target": self.target.to_dict(),
            "secret": self.secret.to_dict(),
            "checker": self.checker.to_dict(),
            "difficulty": self.difficulty.to_dict(),
            "safety_class": self.safety_class,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"challenge_id": self.challenge_id, **self._content_dict()}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode()).hexdigest()

    @classmethod
    def from_dict(cls, raw: Any) -> ChallengeSpec:
        keys = {
            "challenge_id",
            "schema_version",
            "generator_version",
            "family",
            "family_version",
            "seed",
            "goal",
            "target",
            "secret",
            "checker",
            "difficulty",
            "safety_class",
        }
        d = _obj(raw, "spec", keys)
        seed_raw = _str(d["seed"], "seed")
        if not seed_raw.isdigit():
            raise SpecError("seed must be a decimal string")
        spec = cls(
            challenge_id=_str(d["challenge_id"], "challenge_id"),
            schema_version=_int(d["schema_version"], "schema_version"),
            generator_version=_str(d["generator_version"], "generator_version"),
            family=_str(d["family"], "family"),
            family_version=_int(d["family_version"], "family_version"),
            seed=int(seed_raw),
            goal=_str(d["goal"], "goal"),
            target=Target.from_dict(d["target"]),
            secret=Secret.from_dict(d["secret"]),
            checker=ByteCompareChecker.from_dict(d["checker"]),
            difficulty=Difficulty.from_dict(d["difficulty"]),
            safety_class=_str(d["safety_class"], "safety_class"),
        )
        if spec.challenge_id != compute_challenge_id(spec._content_dict()):
            raise SpecError("challenge_id does not match spec content")
        return spec

    @classmethod
    def from_json(cls, text: str) -> ChallengeSpec:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecError(f"spec is not valid JSON: {exc}") from exc
        return cls.from_dict(raw)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_challenge_id(content: dict[str, Any]) -> str:
    return "bg-" + hashlib.sha256(canonical_json(content).encode()).hexdigest()[:16]
