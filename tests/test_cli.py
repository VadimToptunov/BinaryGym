from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from binarygym.cli import app
from tests.conftest import needs_toolchain

runner = CliRunner()


def gen(tmp_path: Path, *extra: str) -> tuple[str, Path]:
    result = runner.invoke(app, ["generate", "--out", str(tmp_path / "out"),
                                 "--private-dir", str(tmp_path / "priv"), *extra])  # fmt: skip
    assert result.exit_code == 0, result.output
    (challenge,) = (tmp_path / "out").iterdir()
    return result.output, challenge


def answer_for(tmp_path: Path, challenge: Path) -> str:
    meta = json.loads((challenge / "metadata.json").read_text())
    record = tmp_path / "priv" / meta["challenge_id"] / "challenge.json"
    return str(json.loads(record.read_text())["spec"]["secret"]["value"])


@needs_toolchain
@pytest.mark.parametrize("family", ["direct", "transformation", "state_machine"])
def test_generate_then_verify(tmp_path: Path, family: str) -> None:
    output, challenge = gen(tmp_path, "--family", family, "--seed", "12345", "--optimization",
                            "O1", "--strip")  # fmt: skip
    assert "7/7 checks passed" in output
    answer = answer_for(tmp_path, challenge)
    priv = ["--private-dir", str(tmp_path / "priv")]

    ok = runner.invoke(app, ["verify", str(challenge), answer, *priv])
    assert ok.exit_code == 0 and "✓ Correct" in ok.output

    bad = runner.invoke(app, ["verify", str(challenge), "WRONG_ANSWER", *priv])
    assert bad.exit_code == 1 and "✗ Incorrect" in bad.output
    assert answer not in bad.output


@needs_toolchain
def test_family_version_option(tmp_path: Path) -> None:
    output, _ = gen(tmp_path, "--seed", "1", "--family-version", "1")
    assert "transformation v1" in output


@needs_toolchain
def test_default_private_store_is_used(tmp_path: Path, isolated_private_store: Path) -> None:
    result = runner.invoke(app, ["generate", "--seed", "5", "--out", str(tmp_path / "out")])
    assert result.exit_code == 0, result.output
    assert any(isolated_private_store.iterdir())


@needs_toolchain
def test_random_seed_is_not_printed(tmp_path: Path) -> None:
    output, _ = gen(tmp_path)
    assert "(random, stored privately)" in output


@needs_toolchain
def test_inspect_public_shows_no_secret(tmp_path: Path) -> None:
    _, challenge = gen(tmp_path, "--family", "state_machine", "--seed", "9")
    answer = answer_for(tmp_path, challenge)
    result = runner.invoke(app, ["inspect", str(challenge)])
    assert result.exit_code == 0
    assert "state_machine v1" in result.output and "heuristic" in result.output
    assert answer not in result.output and "Seed" not in result.output


@needs_toolchain
def test_inspect_private_shows_answer(tmp_path: Path) -> None:
    _, challenge = gen(tmp_path, "--seed", "9")
    answer = answer_for(tmp_path, challenge)
    result = runner.invoke(app, ["inspect", str(challenge), "--private",
                                 "--private-dir", str(tmp_path / "priv")])  # fmt: skip
    assert result.exit_code == 0
    assert "PRIVATE" in result.output and answer in result.output and "Strategy" in result.output


def test_list_families() -> None:
    result = runner.invoke(app, ["list-families"])
    assert result.exit_code == 0
    for name in ("direct", "transformation", "state_machine"):
        assert name in result.output


@needs_toolchain
def test_doctor_reports_ready(tmp_path: Path) -> None:
    result = runner.invoke(app, ["doctor", "--private-dir", str(tmp_path / "outside")])
    assert result.exit_code == 0, result.output
    assert "Environment is ready." in result.output and "Self-test" in result.output


@needs_toolchain
def test_doctor_warns_about_private_store_inside_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["doctor", "--private-dir", "inside"])
    assert result.exit_code == 0  # a warning, not a failure
    assert "inside the current directory" in result.output


def test_doctor_fails_on_unsupported_host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    result = runner.invoke(app, ["doctor", "--private-dir", str(tmp_path / "p")])
    assert result.exit_code == 1
    assert "docker run" in result.output and "NOT ready" in result.output


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
