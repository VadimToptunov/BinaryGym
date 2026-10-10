"""Explicit, version-stable deterministic randomness.

Everything that must be reproducible from a seed draws from :class:`Rng`.
``random``, time and OS entropy are never used inside generation.

SplitMix64 is used instead of :mod:`random` because its output is defined
by this file alone and cannot change between Python releases.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import TypeVar

T = TypeVar("T")

_MASK64 = (1 << 64) - 1
MAX_SEED = (1 << 128) - 1


class Rng:
    """SplitMix64 generator keyed by a 32-byte derivation key.

    Independent sub-streams are derived with :meth:`fork`, so adding a draw
    in one part of a generator never shifts the values drawn elsewhere.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("Rng key must be 32 bytes")
        self._key = key
        self._state = int.from_bytes(key[:8], "little")

    @classmethod
    def from_seed(cls, seed: int) -> Rng:
        if not 0 <= seed <= MAX_SEED:
            raise ValueError(f"seed must be in [0, 2**128 - 1], got {seed}")
        return cls(hashlib.sha256(b"binarygym/seed/" + str(seed).encode()).digest())

    def fork(self, label: str) -> Rng:
        """Derive an independent stream; depends only on this stream's key and ``label``."""
        return Rng(hashlib.sha256(self._key + b"/" + label.encode()).digest())

    def next_u64(self) -> int:
        self._state = (self._state + 0x9E3779B97F4A7C15) & _MASK64
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
        return z ^ (z >> 31)

    def below(self, n: int) -> int:
        """Uniform integer in ``[0, n)`` (rejection sampling, no modulo bias)."""
        if not 0 < n <= 1 << 64:
            raise ValueError(f"n must be in (0, 2**64], got {n}")
        limit = (1 << 64) - ((1 << 64) % n)
        while True:
            x = self.next_u64()
            if x < limit:
                return x % n

    def randint(self, lo: int, hi: int) -> int:
        """Uniform integer in ``[lo, hi]``."""
        if lo > hi:
            raise ValueError(f"empty range [{lo}, {hi}]")
        return lo + self.below(hi - lo + 1)

    def choice(self, items: Sequence[T]) -> T:
        if not items:
            raise ValueError("cannot choose from an empty sequence")
        return items[self.below(len(items))]

    def shuffled(self, items: Sequence[T]) -> list[T]:
        """Fisher-Yates shuffle of a copy."""
        out = list(items)
        for i in range(len(out) - 1, 0, -1):
            j = self.below(i + 1)
            out[i], out[j] = out[j], out[i]
        return out
