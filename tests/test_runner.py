from __future__ import annotations

import os

import pytest

from binarygym.runner import SubprocessRunner


def test_timeout_is_enforced() -> None:
    result = SubprocessRunner().run(["/bin/sleep", "5"], b"", timeout=0.3)
    assert result.timed_out and result.exit_code is None
    assert result.duration < 3


def test_environment_is_not_inherited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BINARYGYM_TEST_LEAK", "secret-token")
    result = SubprocessRunner().run(["/usr/bin/env"], b"")
    assert b"BINARYGYM_TEST_LEAK" not in result.stdout
    assert b"LC_ALL=C" in result.stdout


def test_runs_in_throwaway_directory() -> None:
    result = SubprocessRunner().run(["/bin/pwd"], b"")
    cwd = result.stdout.decode().strip()
    assert "binarygym-run-" in cwd and cwd != os.getcwd()
    assert not os.path.exists(cwd)


def test_stdin_is_delivered() -> None:
    assert SubprocessRunner().run(["/bin/cat"], b"hello").stdout == b"hello"
