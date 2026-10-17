from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from binarygym.cli import app
from tests.conftest import needs_toolchain

runner = CliRunner()


def gen(tmp_path: Path, *extra: str) -> str:
    result = runner.invoke(app, ["generate", "--out", str(tmp_path / "out"),
                                 "--private-dir", str(tmp_path / "priv"), *extra])  # fmt: skip
    assert result.exit_code == 0, result.output
    return result.output


@needs_toolchain
def test_generate_then_verify(tmp_path: Path) -> None:
    output = gen(tmp_path, "--seed", "12345", "--optimization", "O1", "--strip")
    assert "7/7 checks passed" in output
    (challenge,) = (tmp_path / "out").iterdir()
    record = json.loads((tmp_path / "priv" / f"{challenge.name}.json").read_text())
    answer = record["spec"]["secret"]["value"]
    priv = ["--private-dir", str(tmp_path / "priv")]

    ok = runner.invoke(app, ["verify", str(challenge), answer, *priv])
    assert ok.exit_code == 0 and "✓ Correct" in ok.output

    bad = runner.invoke(app, ["verify", str(challenge), "WRONG_ANSWER", *priv])
    assert bad.exit_code == 1 and "✗ Incorrect" in bad.output
    assert answer not in bad.output


@needs_toolchain
def test_random_seed_is_not_printed(tmp_path: Path) -> None:
    output = gen(tmp_path)
    assert "(random, stored privately)" in output


def test_unknown_family_is_a_clean_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["generate", "--family", "nope", "--out", str(tmp_path)])
    assert result.exit_code == 2
    assert "unknown family" in result.output


def test_bad_optimization_rejected(tmp_path: Path) -> None:
    result = runner.invoke(app, ["generate", "--optimization", "O9", "--out", str(tmp_path)])
    assert result.exit_code != 0


def test_verify_missing_challenge(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify", str(tmp_path / "missing"), "x"])
    assert result.exit_code == 2
