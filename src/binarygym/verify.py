"""Answer verification against trusted private data (never by analyzing the binary)."""

from __future__ import annotations

import re
from pathlib import Path

from binarygym import reference
from binarygym.errors import ChallengeNotFound
from binarygym.package import load_private_spec, read_public_metadata

_ID_RE = re.compile(r"^bg-[0-9a-f]{16}$")


def resolve_challenge_id(ref: str) -> str:
    """Accept a public challenge directory or a bare challenge id."""
    path = Path(ref)
    if path.is_dir():
        challenge_id = str(read_public_metadata(path)["challenge_id"])
    elif _ID_RE.match(ref):
        challenge_id = ref
    else:
        raise ChallengeNotFound(f"{ref!r} is neither a challenge directory nor a challenge id")
    if not _ID_RE.match(challenge_id):
        raise ChallengeNotFound(f"malformed challenge id {challenge_id!r}")
    return challenge_id


def verify_answer(ref: str, answer: str, private_root: Path) -> bool:
    spec = load_private_spec(resolve_challenge_id(ref), private_root)
    return reference.accepts(spec, answer.encode("utf-8"))
