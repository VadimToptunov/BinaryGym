from __future__ import annotations

import json
from pathlib import Path

import pytest

from binarygym.compiler import BuildOptions
from binarygym.errors import ChallengeNotFound, SpecError, ValidationFailed
from binarygym.generate import GenerationResult, generate_challenge
from binarygym.validation import Check, ValidationReport
from binarygym.verify import verify_answer
from tests.conftest import needs_toolchain

pytestmark = needs_toolchain


def test_public_package_layout(generated: GenerationResult) -> None:
    names = sorted(p.name for p in generated.public_dir.iterdir())
    assert names == ["README.md", "challenge", "metadata.json"]
    meta = json.loads((generated.public_dir / "metadata.json").read_text())
    assert meta["challenge_id"] == generated.spec.challenge_id
    assert meta["binary"]["sha256"] == generated.build.artifact.sha256
    assert "heuristic" in meta["difficulty"]["note"]


def test_public_package_leaks_no_private_data(generated: GenerationResult) -> None:
    spec = generated.spec
    secret = spec.secret.value.encode()
    forbidden_values = [spec.secret.value, spec.checker.expected.hex(), str(spec.seed),
                        generated.build.strategy]  # fmt: skip
    for path in generated.public_dir.iterdir():
        data = path.read_bytes()
        assert secret not in data, path
        if path.name != "challenge":
            text = data.decode()
            for item in forbidden_values:
                assert item not in text, (path.name, item)
    meta = json.loads((generated.public_dir / "metadata.json").read_text())
    keys = json.dumps(meta)
    for private_key in ('"seed"', '"secret"', '"solution"', '"checker"', '"pipeline"',
                        '"expected"', '"strategy"'):  # fmt: skip
        assert private_key not in keys


def test_private_record_keeps_what_verification_needs(generated: GenerationResult) -> None:
    record = json.loads(generated.private_path.read_text())
    assert record["spec"]["secret"]["value"] == generated.spec.secret.value
    assert record["spec"]["seed"] == "12345"
    assert record["solution"]["answer"] == generated.spec.secret.value
    assert record["validation"]["passed"] is True
    assert generated.private_path.stat().st_mode & 0o077 == 0


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
    with pytest.raises(ChallengeNotFound, match="private record"):
        verify_answer(str(generated.public_dir), "x", tmp_path / "elsewhere")


def test_verify_rejects_tampered_private_record(
    generated: GenerationResult, tmp_path: Path
) -> None:
    record = json.loads(generated.private_path.read_text())
    record["spec"]["secret"]["value"] = "Tampered123"
    generated.private_path.write_text(json.dumps(record))
    with pytest.raises(SpecError):
        verify_answer(str(generated.public_dir), "Tampered123", tmp_path / "private")


def test_verify_unknown_reference() -> None:
    with pytest.raises(ChallengeNotFound):
        verify_answer("no-such-thing", "x", Path("/nonexistent"))


def test_same_seed_regenerates_same_logical_challenge(
    generated: GenerationResult, tmp_path: Path
) -> None:
    again = generate_challenge("transformation", 12345, BuildOptions(), tmp_path / "second",
                               tmp_path / "private2")  # fmt: skip
    assert again.spec.to_json() == generated.spec.to_json()
    assert again.build.strategy == generated.build.strategy


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
