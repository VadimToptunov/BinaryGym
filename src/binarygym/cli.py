"""BinaryGym: generate and verify reverse-engineering practice challenges."""

from __future__ import annotations

import json
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Annotated

import typer

from binarygym import __version__
from binarygym.backends.c_linux import LinuxCBackend
from binarygym.compiler import OPTIMIZATION_LEVELS, BuildOptions, NativeCompiler
from binarygym.errors import BinaryGymError
from binarygym.families import FAMILIES
from binarygym.generate import generate_challenge
from binarygym.package import load_build_record, load_private_record, read_public_metadata
from binarygym.paths import DEFAULT_OUT, default_private_dir
from binarygym.rng import MAX_SEED
from binarygym.verify import verify_answer

app = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)

PrivateDir = Annotated[
    Path | None,
    typer.Option(
        "--private-dir",
        help="Private store (spec, secret, solution). Default: $BINARYGYM_PRIVATE_DIR or "
        "~/.local/share/binarygym/private.",
    ),
]


def _fail(exc: BinaryGymError) -> typer.Exit:
    typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
    return typer.Exit(2)


@app.command()
def generate(
    family: Annotated[str, typer.Option(help="Challenge family (see list-families).")] = (
        "transformation"
    ),
    family_version: Annotated[
        int | None, typer.Option(help="Family version (default: latest).")
    ] = None,
    seed: Annotated[
        int | None,
        typer.Option(min=0, max=MAX_SEED, help="Seed for reproducible generation (guessable!)."),
    ] = None,
    optimization: Annotated[str, typer.Option(help="O0, O1 or O2.")] = "O0",
    strip: Annotated[bool, typer.Option("--strip/--no-strip", help="Strip symbols.")] = False,
    out: Annotated[Path, typer.Option(help="Public output root.")] = DEFAULT_OUT,
    private_dir: PrivateDir = None,
    compiler: Annotated[str | None, typer.Option(help="Force 'clang' or 'gcc'.")] = None,
    force: Annotated[bool, typer.Option(help="Replace an existing challenge directory.")] = False,
) -> None:
    """Generate, compile, validate and package one challenge."""
    if optimization not in OPTIMIZATION_LEVELS:
        raise typer.BadParameter(
            f"must be one of {', '.join(OPTIMIZATION_LEVELS)}", param_hint="--optimization"
        )
    explicit_seed = seed is not None
    # OS entropy is only used here, outside the deterministic core.
    actual_seed = seed if seed is not None else secrets.randbits(128)
    try:
        result = generate_challenge(
            family, actual_seed, BuildOptions(optimization, strip), out,
            private_dir or default_private_dir(), family_version=family_version,
            compiler=NativeCompiler.detect(compiler), force=force,
        )  # fmt: skip
    except BinaryGymError as exc:
        raise _fail(exc) from exc

    checks = result.report.checks
    typer.echo(f"Challenge:   {result.spec.challenge_id}")
    typer.echo(f"Build:       {result.build.build_id}")
    typer.echo(f"Family:      {result.spec.family} v{result.spec.family_version}")
    typer.echo(f"Seed:        {actual_seed if explicit_seed else '(random, stored privately)'}")
    typer.echo(
        f"Compiler:    {result.build.compiler_version}  "
        f"-{optimization}{' stripped' if strip else ''}"
    )
    typer.echo(f"Validation:  {sum(c.passed for c in checks)}/{len(checks)} checks passed")
    typer.echo(f"Public:      {result.public_dir}")
    typer.echo(f"Private:     {result.build_record.parent.parent}  (do not distribute)")


@app.command()
def verify(
    challenge: Annotated[str, typer.Argument(help="Challenge directory or challenge id.")],
    answer: Annotated[str, typer.Argument(help="Your answer.")],
    private_dir: PrivateDir = None,
) -> None:
    """Check an answer using the local private record."""
    try:
        correct = verify_answer(challenge, answer, private_dir or default_private_dir())
    except BinaryGymError as exc:
        raise _fail(exc) from exc
    if correct:
        typer.secho("✓ Correct", fg=typer.colors.GREEN)
    else:
        typer.secho("✗ Incorrect", fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command()
def inspect(
    challenge: Annotated[Path, typer.Argument(help="Public challenge directory.")],
    private: Annotated[
        bool, typer.Option("--private", help="Developer mode: also show private data.")
    ] = False,
    private_dir: PrivateDir = None,
) -> None:
    """Show a challenge's public metadata (and, with --private, its answer and solution)."""
    try:
        meta = read_public_metadata(challenge)
        target, diff, binary = meta["target"], meta["difficulty"], meta["binary"]
        dims = ", ".join(f"{k}={v}" for k, v in diff["dimensions"].items())
        typer.echo(f"Challenge:   {meta['challenge_id']}")
        typer.echo(f"Build:       {meta['build_id']}")
        typer.echo(f"Family:      {meta['family']} v{meta['family_version']}")
        typer.echo(f"Goal:        {meta['goal']}")
        typer.echo(f"Target:      {target['platform']}/{target['arch']} ({target['artifact']})")
        typer.echo(f"Difficulty:  {diff['label']} (heuristic; {dims})")
        typer.echo(f"Concepts:    {'; '.join(meta['concepts'])}")
        typer.echo(
            f"Binary:      sha256 {binary['sha256']}  -{binary['optimization']}"
            f"{' stripped' if binary['stripped'] else ''}  ({binary['compiler']})"
        )
        if not private:
            return
        root = private_dir or default_private_dir()
        record = load_private_record(meta["challenge_id"], root)
        build = load_build_record(meta["challenge_id"], meta["build_id"], root)
    except BinaryGymError as exc:
        raise _fail(exc) from exc
    typer.secho("\n--- PRIVATE (developer mode, do not share) ---", fg=typer.colors.YELLOW)
    typer.echo(f"Answer:      {record['spec']['secret']['value']}")
    typer.echo(f"Seed:        {record['spec']['seed']}")
    typer.echo(f"Strategy:    {build['build']['strategy']}")
    typer.echo(f"Validation:  {'passed' if build['validation']['passed'] else 'FAILED'}")
    typer.echo("Solution:")
    typer.echo(json.dumps(record["solution"], indent=2))


@app.command("list-families")
def list_families() -> None:
    """List available challenge families."""
    for family in FAMILIES.values():
        versions = ", ".join(f"v{v}" for v in family.versions)
        typer.echo(f"{family.name}  ({versions}; latest v{family.latest_version})")
        typer.echo(f"    {family.summary}")
        typer.echo(f"    Concepts: {'; '.join(family.concepts)}")


@app.command()
def doctor(private_dir: PrivateDir = None) -> None:
    """Check that this machine can generate, build and validate challenges."""
    ok = True

    def report(passed: bool, text: str) -> None:
        nonlocal ok
        ok &= passed
        mark = (
            typer.style("✓", fg=typer.colors.GREEN)
            if passed
            else typer.style("✗", fg=typer.colors.RED)
        )
        typer.echo(f"{mark} {text}")

    typer.echo(f"BinaryGym {__version__}")
    py = sys.version_info
    report(py >= (3, 12), f"Python {py.major}.{py.minor}.{py.micro} (need 3.12+)")

    backend = LinuxCBackend()
    problems = backend.host_problems()
    report(not problems, f"Host can build {backend.target.platform}/{backend.target.arch} "
                         f"{backend.target.artifact} binaries")  # fmt: skip
    for problem in problems:
        typer.echo(f"    {problem}")

    compiler: NativeCompiler | None = None
    try:
        compiler = NativeCompiler.detect()
        report(True, f"C compiler: {compiler.info.version}")
    except BinaryGymError as exc:
        report(False, f"C compiler: {exc}")

    root = (private_dir or default_private_dir()).expanduser().absolute()
    inside_cwd = root.is_relative_to(Path.cwd().absolute())
    if inside_cwd:
        # A warning, not a failure: e.g. running from $HOME is legitimate.
        typer.echo(f"{typer.style('!', fg=typer.colors.YELLOW)} Private store: {root}")
        typer.echo("    it is inside the current directory; answers could be shipped along "
                   "with challenges or read by tools working in this folder")  # fmt: skip
    else:
        report(True, f"Private store: {root}")

    if ok and compiler is not None:
        with tempfile.TemporaryDirectory(prefix="binarygym-doctor-") as tmp:
            try:
                result = generate_challenge(
                    "transformation", 0, BuildOptions(), Path(tmp) / "out",
                    Path(tmp) / "private", compiler=compiler,
                )  # fmt: skip
                good = verify_answer(
                    str(result.public_dir), result.spec.secret.value, Path(tmp) / "private"
                )
                report(good, "Self-test: generated, compiled, validated and verified a challenge")
            except BinaryGymError as exc:
                report(False, f"Self-test failed: {exc}")

    if ok:
        typer.secho("Environment is ready.", fg=typer.colors.GREEN)
    else:
        typer.secho("Environment is NOT ready.", fg=typer.colors.RED)
        raise typer.Exit(1)
