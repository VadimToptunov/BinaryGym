"""Execution of generated programs.

Security assumptions: programs come only from BinaryGym's own templates built
from allowlisted primitives, and they pass the backend's safety policy before
packaging. This runner is defense in depth, not a sandbox: it enforces a
timeout, runs in a throwaway working directory and passes a minimal
environment. A stronger isolating Runner (bubblewrap, nsjail, containers) can
implement the same protocol later.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

DEFAULT_TIMEOUT = 5.0
_MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


@dataclass(frozen=True)
class RunResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    duration: float


class Runner(Protocol):
    def run(self, argv: list[str], stdin: bytes, timeout: float = DEFAULT_TIMEOUT) -> RunResult: ...


class SubprocessRunner:
    def run(self, argv: list[str], stdin: bytes, timeout: float = DEFAULT_TIMEOUT) -> RunResult:
        start = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="binarygym-run-") as cwd:
            try:
                proc = subprocess.run(
                    argv, input=stdin, capture_output=True, cwd=Path(cwd),
                    env=dict(_MINIMAL_ENV), timeout=timeout, check=False,
                )  # fmt: skip
            except subprocess.TimeoutExpired as exc:
                return RunResult(None, exc.stdout or b"", exc.stderr or b"", True,
                                 time.monotonic() - start)  # fmt: skip
        return RunResult(proc.returncode, proc.stdout, proc.stderr, False, time.monotonic() - start)
