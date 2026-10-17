"""Native compiler abstraction."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from binarygym.backends.base import RenderedSource
from binarygym.errors import CompileError

OPTIMIZATION_LEVELS = ("O0", "O1", "O2")
BINARY_NAME = "challenge"


@dataclass(frozen=True)
class BuildOptions:
    optimization: str = "O0"
    strip: bool = False

    def __post_init__(self) -> None:
        if self.optimization not in OPTIMIZATION_LEVELS:
            raise ValueError(f"optimization must be one of {OPTIMIZATION_LEVELS}")


@dataclass(frozen=True)
class CompilerInfo:
    name: str
    path: str
    version: str


@dataclass(frozen=True)
class BuildArtifact:
    binary: Path
    sha256: str
    compiler: CompilerInfo
    flags: tuple[str, ...]
    stderr: str


class Compiler(Protocol):
    info: CompilerInfo

    def compile(
        self, source: RenderedSource, build_dir: Path, options: BuildOptions
    ) -> BuildArtifact: ...


def _build_env() -> dict[str, str]:
    # Minimal, fixed environment: reproducible builds, no locale-dependent output.
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "SOURCE_DATE_EPOCH": "0",
    }


class NativeCompiler:
    """Host C compiler (clang preferred, gcc fallback) producing a native executable."""

    PREFERENCE = ("clang", "gcc")

    def __init__(self, info: CompilerInfo) -> None:
        self.info = info

    @classmethod
    def detect(cls, name: str | None = None) -> NativeCompiler:
        for candidate in (name,) if name else cls.PREFERENCE:
            path = shutil.which(candidate)
            if path is None:
                continue
            proc = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=30,
                env=_build_env(), check=False,
            )  # fmt: skip
            version = proc.stdout.splitlines()[0].strip() if proc.stdout else "unknown"
            return cls(CompilerInfo(name=candidate, path=path, version=version))
        wanted = name or " or ".join(cls.PREFERENCE)
        raise CompileError(f"no C compiler found (looked for {wanted})")

    def flags(self, options: BuildOptions) -> tuple[str, ...]:
        flags = [
            "-std=c11",
            f"-{options.optimization}",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-ident",
        ]
        if options.strip:
            flags.append("-s")
        return tuple(flags)

    def compile(
        self, source: RenderedSource, build_dir: Path, options: BuildOptions
    ) -> BuildArtifact:
        build_dir.mkdir(parents=True, exist_ok=True)
        (build_dir / source.filename).write_text(source.text)
        flags = self.flags(options)
        # Relative paths and a fixed source name keep build paths out of the binary.
        cmd = [self.info.path, *flags, source.filename, "-o", BINARY_NAME]
        try:
            proc = subprocess.run(
                cmd, cwd=build_dir, capture_output=True, text=True, timeout=120,
                env=_build_env(), check=False,
            )  # fmt: skip
        except subprocess.TimeoutExpired as exc:
            raise CompileError("compiler timed out") from exc
        if proc.returncode != 0:
            raise CompileError(
                f"{self.info.name} failed (exit {proc.returncode}):\n{proc.stderr.strip()}"
            )
        binary = build_dir / BINARY_NAME
        return BuildArtifact(
            binary=binary,
            sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            compiler=self.info,
            flags=flags,
            stderr=proc.stderr,
        )
