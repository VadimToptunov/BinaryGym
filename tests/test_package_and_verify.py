from __future__ import annotations

import json
from pathlib import Path

import pytest

from binarygym.compiler import BuildOptions, NativeCompiler
from binarygym.errors import ChallengeNotFound, SpecError, ValidationFailed
from binarygym.generate import GenerationResult, generate_challenge
from binarygym.validation import Check, ValidationReport
from binarygym.verify import verify_answer
from tests.conftest import needs_toolchain

pytestmark = needs_toolchain


def test_public_package_layout(generated: GenerationResult) -> None:
    assert generated.public_dir.name == generated.build.build_id
    names = sorted(p.name for p in generated.public_dir.iterdir())
    assert names == ["README.md", "challenge", "metadata.json"]
    meta = json.loads((generated.public_dir / "metadata.json").read_text())
    assert meta["challenge_id"] == generated.spec.challenge_id
    assert meta["build_id"] == generated.build.build_id
    assert meta["target"] == {"platform": "linux", "arch": "x86_64", "language": "c",
                              "artifact": "elf"}  # fmt: skip
    assert meta["binary"]["sha256"] == generated.artifact.sha256
    assert "heuristic" in meta["difficulty"]["note"]


@pytest.mark.parametrize("family", ["transformation", "state_machine"])
def test_public_package_leaks_no_private_data(tmp_path: Path, family: str) -> None:
    result = generate_challenge(family, 12345, BuildOptions(), tmp_path / "out", tmp_path / "p")
    spec = result.spec
    secret = spec.secret.value.encode()
    forbidden = [spec.secret.value, str(spec.seed), result.build.strategy]
    for path in result.public_dir.iterdir():
        data = path.read_bytes()
        assert secret not in data, path
        if path.name != "challenge":
            for item in forbidden:
                assert item not in data.decode(), (path.name, item)
    keys = (result.public_dir / "metadata.json").read_text()
    for private_key in ('"seed"', '"secret"', '"solution"', '"checker"', '"pipeline"',
                        '"expected"', '"strategy"', '"rows"'):  # fmt: skip
        assert private_key not in keys


def test_private_records_keep_what_verification_needs(
    generated: GenerationResult, tmp_path: Path
) -> None:
    challenge_dir = tmp_path / "private" / generated.spec.challenge_id
    record = json.loads((challenge_dir / "challenge.json").read_text())
    assert record["spec"]["secret"]["value"] == generated.spec.secret.value
    assert record["spec"]["seed"] == "12345"
    assert record["solution"]["answer"] == generated.spec.secret.value
    build = json.loads(generated.build_record.read_text())
    assert build["validation"]["passed"] is True
    assert build["build"]["strategy"] == generated.build.strategy
    for path in (challenge_dir / "challenge.json", generated.build_record):
        assert path.stat().st_mode & 0o077 == 0
    assert challenge_dir.stat().st_mode & 0o077 == 0


def test_verify_by_path_and_by_id(generated: GenerationResult, tmp_path: Path) -> None:
    private = tmp_path / "private"
    answer = generated.spec.secret.value
    assert verify_answer(str(generated.public_dir), answer, private)
    assert verify_answer(generated.spec.challenge_id, answer, private)
    assert not verify_answer(str(generated.public_dir), answer[:-1], private)
    assert not verify_answer(str(generated.public_dir), answer.swapcase(), private)
    assert not verify_answer(str(generated.public_dir), "", private)


def test_verify_without_private_data_fails_clearly(
    generated: GenerationResult, tmp_path: Path
) -> None:
    with pytest.raises(ChallengeNotFound, match="private"):
        verify_answer(str(generated.public_dir), "x", tmp_path / "elsewhere")


def test_verify_rejects_tampered_private_record(
    generated: GenerationResult, tmp_path: Path
) -> None:
    path = tmp_path / "private" / generated.spec.challenge_id / "challenge.json"
    record = json.loads(path.read_text())
    record["spec"]["secret"]["value"] = "Tampered123"
    path.write_text(json.dumps(record))
    with pytest.raises(SpecError):
        verify_answer(str(generated.public_dir), "Tampered123", tmp_path / "private")


def test_verify_unknown_reference() -> None:
    with pytest.raises(ChallengeNotFound):
        verify_answer("no-such-thing", "x", Path("/nonexistent"))


def test_same_seed_regenerates_same_build(generated: GenerationResult, tmp_path: Path) -> None:
    again = generate_challenge(
        "transformation", 12345, BuildOptions(), tmp_path / "second", tmp_path / "private2"
    )
    assert again.spec.to_json() == generated.spec.to_json()
    assert again.build == generated.build
    assert again.artifact.sha256 == generated.artifact.sha256


def test_builds_with_other_options_get_their_own_build_id(
    generated: GenerationResult, tmp_path: Path
) -> None:
    out, private = generated.public_dir.parent, tmp_path / "private"
    other = generate_challenge("transformation", 12345, BuildOptions("O2", True), out, private)
    assert other.spec.challenge_id == generated.spec.challenge_id
    assert other.build.build_id != generated.build.build_id
    builds = sorted(p.stem for p in other.build_record.parent.iterdir())
    assert builds == sorted([generated.build.build_id, other.build.build_id])


def test_gcc_and_clang_builds_do_not_collide(tmp_path: Path) -> None:
    ids = set()
    for name in ("clang", "gcc"):
        try:
            compiler = NativeCompiler.detect(name)
        except Exception:
            pytest.skip(f"{name} not installed")
        r = generate_challenge("direct", 7, BuildOptions(), tmp_path / "out", tmp_path / "p",
                               compiler=compiler)  # fmt: skip
        ids.add(r.build.build_id)
    assert len(ids) == 2


def test_existing_directory_requires_force(generated: GenerationResult, tmp_path: Path) -> None:
    out, private = generated.public_dir.parent, tmp_path / "private"
    with pytest.raises(Exception, match="already exists"):
        generate_challenge("transformation", 12345, BuildOptions(), out, private)
    generate_challenge("transformation", 12345, BuildOptions(), out, private, force=True)


def test_failed_validation_publishes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_validate(*_a: object, **_k: object) -> ValidationReport:
        return ValidationReport((Check("binary_matches_intent", False, "forced"),))

    monkeypatch.setattr("binarygym.generate.validate", failing_validate)
    with pytest.raises(ValidationFailed):
        generate_challenge("transformation", 1, BuildOptions(), tmp_path / "out", tmp_path / "priv")
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "priv").exists()


def test_unsupported_host_fails_before_building(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    with pytest.raises(Exception, match="docker run"):
        generate_challenge("direct", 1, BuildOptions(), tmp_path / "out", tmp_path / "priv")
    assert not (tmp_path / "out").exists()
