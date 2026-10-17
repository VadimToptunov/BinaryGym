from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from binarygym.compiler import BuildOptions
from binarygym.generate import GenerationResult, generate_challenge

HAS_TOOLCHAIN = bool((shutil.which("clang") or shutil.which("gcc")) and shutil.which("nm"))
needs_toolchain = pytest.mark.skipif(not HAS_TOOLCHAIN, reason="needs a C compiler and nm")


@pytest.fixture(autouse=True)
def isolated_private_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Never let tests touch the real ~/.local/share/binarygym."""
    store = tmp_path / "default-private"
    monkeypatch.setenv("BINARYGYM_PRIVATE_DIR", str(store))
    return store


@pytest.fixture
def generated(tmp_path: Path) -> GenerationResult:
    return generate_challenge(
        "transformation", 12345, BuildOptions(), tmp_path / "generated", tmp_path / "private"
    )
