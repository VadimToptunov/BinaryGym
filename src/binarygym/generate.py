"""End-to-end generation: spec -> source -> binary -> validation -> package."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from binarygym.backends.base import Backend
from binarygym.backends.c_linux import LinuxCBackend
from binarygym.compiler import BuildOptions, Compiler, NativeCompiler
from binarygym.errors import ValidationFailed
from binarygym.families import get_family
from binarygym.package import BuildRecord, write_package
from binarygym.runner import Runner, SubprocessRunner
from binarygym.spec import ChallengeSpec
from binarygym.validation import ValidationReport, validate


@dataclass(frozen=True)
class GenerationResult:
    spec: ChallengeSpec
    build: BuildRecord
    report: ValidationReport
    public_dir: Path
    private_path: Path


def generate_challenge(
    family_name: str,
    seed: int,
    options: BuildOptions,
    out_root: Path,
    private_root: Path,
    *,
    compiler: Compiler | None = None,
    backend: Backend | None = None,
    runner: Runner | None = None,
    force: bool = False,
) -> GenerationResult:
    family = get_family(family_name)
    spec = family.generate(seed)
    backend_: Backend = backend or LinuxCBackend()
    compiler_: Compiler = compiler or NativeCompiler.detect()
    strategy = backend_.choose_strategy(spec)
    source = backend_.render(spec, strategy)

    with tempfile.TemporaryDirectory(prefix="binarygym-build-") as tmp:
        artifact = compiler_.compile(source, Path(tmp), options)
        report = validate(
            spec, artifact.binary, backend_.safety_policy, runner or SubprocessRunner()
        )
        if not report.passed:
            details = "; ".join(f"{c.name}: {c.detail}" for c in report.failures())
            raise ValidationFailed(f"challenge {spec.challenge_id} failed validation: {details}")
        build = BuildRecord(backend_.name, strategy, options, artifact)
        public_dir, private_path = write_package(
            spec, build, report, family.solution(spec), family.concepts,
            out_root, private_root, force=force,
        )  # fmt: skip
    return GenerationResult(spec, build, report, public_dir, private_path)
