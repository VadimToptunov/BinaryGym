"""Answer verification against trusted private data (never by analyzing the binary)."""

from __future__ import annotations

from pathlib import Path

from binarygym import reference
from binarygym.errors import ChallengeNotFound
from binarygym.package import load_private_spec, read_public_metadata
from binarygym.spec import CHALLENGE_ID_RE


def resolve_challenge_id(ref: str) -> str:
    """Accept a public challenge directory or a bare challenge id (``bg-...``)."""
    path = Path(ref)
    if path.is_dir():
        return str(read_public_metadata(path)["challenge_id"])
    if CHALLENGE_ID_RE.match(ref):
        return ref
    raise ChallengeNotFound(f"{ref!r} is neither a challenge directory nor a challenge id")


def verify_answer(ref: str, answer: str, private_root: Path) -> bool:
    spec = load_private_spec(resolve_challenge_id(ref), private_root)
    return reference.accepts(spec, answer.encode("utf-8"))
