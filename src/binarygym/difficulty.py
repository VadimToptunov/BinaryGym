"""Heuristic difficulty. Labels are estimates, not measurements of human effort."""

from __future__ import annotations

from binarygym.spec import Difficulty

_OPT_COMPLEXITY = {"O0": 0, "O1": 1, "O2": 2}


def label_for(dimensions: dict[str, int]) -> str:
    total = sum(dimensions.values())
    if total <= 4:
        return "beginner"
    if total <= 7:
        return "intermediate"
    return "advanced"


def semantic(dimensions: dict[str, int]) -> Difficulty:
    """Difficulty of the logical challenge, independent of how it is built."""
    return Difficulty(dimensions=dict(dimensions), label=label_for(dimensions))


def with_build(base: Difficulty, optimization: str, strip: bool) -> Difficulty:
    """Add compiler-related dimensions for a concrete build."""
    dims = dict(base.dimensions)
    dims["compiler_complexity"] = _OPT_COMPLEXITY[optimization] + int(strip)
    return Difficulty(dimensions=dims, label=label_for(dims), method=base.method)
