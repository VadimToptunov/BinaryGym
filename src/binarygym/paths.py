"""Default locations for local data."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_OUT = Path("generated")


def default_private_dir() -> Path:
    """Private store outside the working directory.

    Keeping answers away from the folder handed to a participant (or to an AI agent
    with file access) avoids reading the answer instead of reversing the binary.
    Override with ``BINARYGYM_PRIVATE_DIR`` or ``--private-dir``.
    """
    explicit = os.environ.get("BINARYGYM_PRIVATE_DIR")
    if explicit:
        return Path(explicit)
    data_home = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data_home) / "binarygym" / "private"
