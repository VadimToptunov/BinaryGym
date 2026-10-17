"""ChallengeSpec: the platform-independent source of truth for a challenge.

Generated source code and binaries are artifacts derived from a spec. A spec
contains no build or platform information (no target, no compiler flags, no
render strategy - those live in :class:`binarygym.build.BuildSpec`), so the
same spec can be lowered by different backends and share one ``challenge_id``.

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

SCHEMA_VERSION = 2
GOAL_RECOVER_SECRET = "recover_secret"
SAFETY_BENIGN_RE = "benign_re"
CHALLENGE_ID_RE = re.compile(r"^bg-[0-9a-f]{16}$")
_PLACEHOLDER_ID = "bg-" + "0" * 16

# Bytes a candidate can never contain: the line contract cuts at CR, LF and NUL.
LINE_TERMINATORS = frozenset({0x00, 0x0A, 0x0D})
_CANDIDATE_BYTES = tuple(b for b in range(256) if b not in LINE_TERMINATORS)


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


def _hex(raw: Any, where: str) -> bytes:
    try:
        return bytes.fromhex(_str(raw, where))
    except ValueError as exc:
        raise SpecError(f"{where} must be hex") from exc


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
        if any(ord(c) in LINE_TERMINATORS for c in self.alphabet):
            raise SpecError("alphabet must not contain line terminators")

    def to_dict(self) -> dict[str, Any]:
        return {"alphabet": self.alphabet, "value": self.value}

    @classmethod
    def from_dict(cls, raw: Any) -> Secret:
        d = _obj(raw, "secret", {"alphabet", "value"})
        return cls(_str(d["alphabet"], "secret.alphabet"), _str(d["value"], "secret.value"))


@dataclass(frozen=True)
class ByteCompareChecker:
    """Accept an input of ``input_length`` bytes iff ``pipeline(input) == expected``.

    An empty pipeline means the expected bytes are the answer itself (plaintext comparison).
    """

    input_length: int
    pipeline: tuple[Transform, ...]
    expected: bytes
    kind: str = field(default="byte_compare", init=False)

    def __post_init__(self) -> None:
        if not 1 <= self.input_length <= 64:
            raise SpecError("checker.input_length must be in [1, 64]")
        if len(self.expected) != self.input_length:
            raise SpecError("checker.expected length does not match input_length")
        for t in self.pipeline:
            if t.reorders and len(t.params()["order"]) != self.input_length:
                raise SpecError("checker: permutation length does not match input_length")

    def accepts(self, candidate: bytes) -> bool:
        """Reference evaluator on the exact candidate bytes."""
        return (
            len(candidate) == self.input_length
            and apply_pipeline(self.pipeline, candidate) == self.expected
        )

    def embeds_plaintext(self) -> bool:
        """True when the answer is, by design, stored verbatim in the artifact."""
        return not self.pipeline

    def accepted_count(self) -> int:
        # Every primitive is a bijection, so exactly one input maps to ``expected``.
        return 1

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
        if not isinstance(d["pipeline"], list):
            raise SpecError("checker.pipeline must be a list")
        return cls(
            input_length=_int(d["input_length"], "checker.input_length"),
            pipeline=tuple(transform_from_dict(t) for t in d["pipeline"]),
            expected=_hex(d["expected"], "checker.expected"),
        )


@dataclass(frozen=True)
class StateMachineChecker:
    """A DFA over input bytes: accept iff the input has ``input_length`` bytes and the
    final state is ``accept``.

    The length check makes the answer unique even when back edges allow longer walks
    to reach ``accept``. ``rows[s][c]`` is the next state from state ``s`` on ASCII byte
    ``c``; bytes >= 128 go to ``dead``. ``dead`` is absorbing and not accepting.
    """

    input_length: int
    state_count: int
    start: int
    accept: int
    dead: int
    rows: tuple[bytes, ...]
    kind: str = field(default="state_machine", init=False)

    ROW_WIDTH = 128

    def __post_init__(self) -> None:
        if not 1 <= self.input_length <= 64:
            raise SpecError("checker.input_length must be in [1, 64]")
        if not 3 <= self.state_count <= 255:
            raise SpecError("checker.state_count must be in [3, 255]")
        if len(self.rows) != self.state_count:
            raise SpecError("checker.rows must have one row per state")
        for name in ("start", "accept", "dead"):
            if not 0 <= getattr(self, name) < self.state_count:
                raise SpecError(f"checker.{name} is not a valid state")
        if len({self.start, self.accept, self.dead}) != 3:
            raise SpecError("checker: start, accept and dead must be distinct")
        for row in self.rows:
            if len(row) != self.ROW_WIDTH or any(s >= self.state_count for s in row):
                raise SpecError("checker: malformed transition row")
        if set(self.rows[self.dead]) != {self.dead}:
            raise SpecError("checker: dead state must be absorbing")

    def step(self, state: int, byte: int) -> int:
        return self.rows[state][byte] if byte < self.ROW_WIDTH else self.dead

    def accepts(self, candidate: bytes) -> bool:
        if len(candidate) != self.input_length:
            return False
        state = self.start
        for b in candidate:
            state = self.step(state, b)
        return state == self.accept

    def embeds_plaintext(self) -> bool:
        return False

    def accepted_count(self) -> int:
        """Number of accepted candidates, by dynamic programming over the automaton."""
        counts = {self.start: 1}
        for _ in range(self.input_length):
            nxt: dict[int, int] = {}
            for state, n in counts.items():
                if state == self.dead:
                    continue
                for b in _CANDIDATE_BYTES:
                    target = self.step(state, b)
                    if target != self.dead:
                        nxt[target] = nxt.get(target, 0) + n
            counts = nxt
        return counts.get(self.accept, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "input_length": self.input_length,
            "state_count": self.state_count,
            "start": self.start,
            "accept": self.accept,
            "dead": self.dead,
            "rows": [row.hex() for row in self.rows],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> StateMachineChecker:
        keys = {"kind", "input_length", "state_count", "start", "accept", "dead", "rows"}
        d = _obj(raw, "checker", keys)
        if not isinstance(d["rows"], list):
            raise SpecError("checker.rows must be a list")
        return cls(
            input_length=_int(d["input_length"], "checker.input_length"),
            state_count=_int(d["state_count"], "checker.state_count"),
            start=_int(d["start"], "checker.start"),
            accept=_int(d["accept"], "checker.accept"),
            dead=_int(d["dead"], "checker.dead"),
            rows=tuple(_hex(r, "checker.rows[]") for r in d["rows"]),
        )


Checker = ByteCompareChecker | StateMachineChecker

_CHECKER_TYPES: dict[str, type[ByteCompareChecker] | type[StateMachineChecker]] = {
    "byte_compare": ByteCompareChecker,
    "state_machine": StateMachineChecker,
}


def checker_from_dict(raw: Any) -> Checker:
    kind = raw.get("kind") if isinstance(raw, dict) else None
    cls = _CHECKER_TYPES.get(kind) if isinstance(kind, str) else None
    if cls is None:
        raise SpecError(f"unsupported checker kind {kind!r}")
    return cls.from_dict(raw)


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
    secret: Secret
    checker: Checker
    difficulty: Difficulty
    safety_class: str = SAFETY_BENIGN_RE
    generator_version: str = __version__
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SpecError(
                f"unsupported schema_version {self.schema_version} (this BinaryGym reads "
                f"{SCHEMA_VERSION}); regenerate the challenge with the current version"
            )
        if not 0 <= self.seed <= MAX_SEED:
            raise SpecError("seed out of range")
        if self.goal != GOAL_RECOVER_SECRET:
            raise SpecError(f"unsupported goal {self.goal!r}")
        if self.safety_class != SAFETY_BENIGN_RE:
            raise SpecError(f"unsupported safety_class {self.safety_class!r}")
        secret = self.secret.value.encode("ascii")
        if not self.checker.accepts(secret):
            raise SpecError("inconsistent spec: the checker does not accept the secret")
        if self.checker.accepted_count() != 1:
            raise SpecError("inconsistent spec: the checker accepts more than one answer")
        if not CHALLENGE_ID_RE.match(self.challenge_id):
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
        if isinstance(raw, dict) and raw.get("schema_version") not in (None, SCHEMA_VERSION):
            raise SpecError(
                f"unsupported schema_version {raw.get('schema_version')!r} (this BinaryGym "
                f"reads {SCHEMA_VERSION}); regenerate the challenge with the current version"
            )
        keys = {
            "challenge_id", "schema_version", "generator_version", "family", "family_version",
            "seed", "goal", "secret", "checker", "difficulty", "safety_class",
        }  # fmt: skip
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
            secret=Secret.from_dict(d["secret"]),
            checker=checker_from_dict(d["checker"]),
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
