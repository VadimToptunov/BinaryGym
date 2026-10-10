"""Reference evaluator: decides acceptance exactly as every backend must.

The I/O contract of a ``recover_secret`` challenge: the program reads one line
from stdin; the candidate is that line cut at the first CR, LF or NUL byte.
Backends must implement this contract; validation checks they agree with
this module on every probe.
"""

from __future__ import annotations

from binarygym.spec import ChallengeSpec

MAX_LINE = 255  # backends must read at least this many bytes per line

_TERMINATORS = (b"\r", b"\n", b"\0")


def candidate_from_line(raw: bytes) -> bytes:
    """Apply the line contract to raw stdin bytes."""
    raw = raw[:MAX_LINE]
    cut = min((i for i in (raw.find(t) for t in _TERMINATORS) if i >= 0), default=len(raw))
    return raw[:cut]


def accepts(spec: ChallengeSpec, raw: bytes) -> bool:
    return spec.checker.accepts(candidate_from_line(raw))
