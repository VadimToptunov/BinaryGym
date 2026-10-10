from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from binarygym.compiler import BuildOptions
from binarygym.generate import GenerationResult, generate_challenge

HAS_TOOLCHAIN = bool((shutil.which("clang") or shutil.which("gcc")) and shutil.which("nm"))
needs_toolchain = pytest.mark.skipif(not HAS_TOOLCHAIN, reason="needs a C compiler and nm")


@pytest.fixture
def generated(tmp_path: Path) -> GenerationResult:
    return generate_challenge(
        "transformation", 12345, BuildOptions(), tmp_path / "generated", tmp_path / "private"
    )
