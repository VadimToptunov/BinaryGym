"""BinaryGym: generate and verify reverse-engineering practice challenges."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Annotated

import typer

from binarygym.compiler import OPTIMIZATION_LEVELS, BuildOptions, NativeCompiler
from binarygym.errors import BinaryGymError
from binarygym.generate import generate_challenge
from binarygym.rng import MAX_SEED
from binarygym.verify import verify_answer

DEFAULT_OUT = Path("generated")
DEFAULT_PRIVATE = Path(".binarygym/private")

app = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)

PrivateDir = Annotated[
    Path, typer.Option("--private-dir", help="Local private store (spec, secret, solution).")
]


@app.command()
def generate(
    family: Annotated[str, typer.Option(help="Challenge family.")] = "transformation",
    seed: Annotated[
        int | None,
        typer.Option(min=0, max=MAX_SEED, help="Seed for reproducible generation (guessable!)."),
    ] = None,
    optimization: Annotated[str, typer.Option(help="O0, O1 or O2.")] = "O0",
    strip: Annotated[bool, typer.Option("--strip/--no-strip", help="Strip symbols.")] = False,
    out: Annotated[Path, typer.Option(help="Public output root.")] = DEFAULT_OUT,
    private_dir: PrivateDir = DEFAULT_PRIVATE,
    compiler: Annotated[str | None, typer.Option(help="Force 'clang' or 'gcc'.")] = None,
    force: Annotated[bool, typer.Option(help="Replace an existing challenge directory.")] = False,
) -> None:
    """Generate, compile, validate and package one challenge."""
    if optimization not in OPTIMIZATION_LEVELS:
        raise typer.BadParameter(f"must be one of {', '.join(OPTIMIZATION_LEVELS)}",
                                 param_hint="--optimization")  # fmt: skip
    explicit_seed = seed is not None
    # OS entropy is only used here, outside the deterministic core.
    actual_seed = seed if seed is not None else secrets.randbits(128)
    try:
        result = generate_challenge(
            family, actual_seed, BuildOptions(optimization, strip), out, private_dir,
            compiler=NativeCompiler.detect(compiler), force=force,
        )  # fmt: skip
    except BinaryGymError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    checks = result.report.checks
    typer.echo(f"Challenge:   {result.spec.challenge_id}")
    typer.echo(f"Family:      {result.spec.family} v{result.spec.family_version}")
    typer.echo(f"Seed:        {actual_seed if explicit_seed else '(random, stored privately)'}")
    typer.echo(f"Compiler:    {result.build.artifact.compiler.version}  "
               f"-{optimization}{' stripped' if strip else ''}")  # fmt: skip
    typer.echo(f"Validation:  {sum(c.passed for c in checks)}/{len(checks)} checks passed")
    typer.echo(f"Public:      {result.public_dir}")
    typer.echo(f"Private:     {result.private_path}  (do not distribute)")


@app.command()
def verify(
    challenge: Annotated[str, typer.Argument(help="Challenge directory or id.")],
    answer: Annotated[str, typer.Argument(help="Your answer.")],
    private_dir: PrivateDir = DEFAULT_PRIVATE,
) -> None:
    """Check an answer using the local private record."""
    try:
        correct = verify_answer(challenge, answer, private_dir)
    except BinaryGymError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    if correct:
        typer.secho("✓ Correct", fg=typer.colors.GREEN)
    else:
        typer.secho("✗ Incorrect", fg=typer.colors.RED)
        raise typer.Exit(1)
