from __future__ import annotations

from pathlib import Path

import pytest

from binarygym.paths import default_private_dir


def test_explicit_env_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BINARYGYM_PRIVATE_DIR", str(tmp_path / "x"))
    assert default_private_dir() == tmp_path / "x"


def test_xdg_data_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("BINARYGYM_PRIVATE_DIR")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert default_private_dir() == tmp_path / "binarygym" / "private"


def test_default_is_outside_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("BINARYGYM_PRIVATE_DIR")
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    path = default_private_dir()
    assert path == Path.home() / ".local" / "share" / "binarygym" / "private"
    assert not path.is_relative_to(tmp_path)
