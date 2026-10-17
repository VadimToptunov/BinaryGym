"""End-to-end generation: spec -> source -> binary -> validation -> package."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from binarygym.backends.base import Backend
from binarygym.backends.c_linux import LinuxCBackend
from binarygym.build import BuildSpec
from binarygym.compiler import BuildArtifact, BuildOptions, Compiler, NativeCompiler
from binarygym.errors import BinaryGymError, ValidationFailed
from binarygym.families import get_family
from binarygym.package import write_package
from binarygym.runner import Runner, SubprocessRunner
from binarygym.spec import ChallengeSpec
from binarygym.validation import ValidationReport, validate


@dataclass(frozen=True)
class GenerationResult:
    spec: ChallengeSpec
    build: BuildSpec
    artifact: BuildArtifact
    report: ValidationReport
    public_dir: Path
    build_record: Path


def generate_challenge(
    family_name: str,
    seed: int,
    options: BuildOptions,
    out_root: Path,
    private_root: Path,
    *,
    family_version: int | None = None,
    compiler: Compiler | None = None,
    backend: Backend | None = None,
    runner: Runner | None = None,
    force: bool = False,
) -> GenerationResult:
    family = get_family(family_name)
    spec = family.generate(seed, family_version)
    backend_: Backend = backend or LinuxCBackend()
    problems = backend_.host_problems()
    if problems:
        raise BinaryGymError("this host cannot build the challenge: " + "; ".join(problems))
    compiler_: Compiler = compiler or NativeCompiler.detect()
    strategy = backend_.choose_strategy(spec)
    source = backend_.render(spec, strategy)
    build = BuildSpec(
        challenge_id=spec.challenge_id,
        backend=backend_.name,
        target=backend_.target,
        strategy=strategy,
        optimization=options.optimization,
        strip=options.strip,
        compiler=compiler_.info.name,
        compiler_version=compiler_.info.version,
    )

    with tempfile.TemporaryDirectory(prefix="binarygym-build-") as tmp:
        artifact = compiler_.compile(source, Path(tmp), options)
        report = validate(
            spec, artifact.binary, backend_.safety_policy, runner or SubprocessRunner()
        )
        if not report.passed:
            details = "; ".join(f"{c.name}: {c.detail}" for c in report.failures())
            raise ValidationFailed(f"challenge {spec.challenge_id} failed validation: {details}")
        public_dir, build_record = write_package(
            spec, build, artifact, report, family.solution(spec), family.concepts,
            out_root, private_root, force=force,
        )  # fmt: skip
    return GenerationResult(spec, build, artifact, report, public_dir, build_record)
