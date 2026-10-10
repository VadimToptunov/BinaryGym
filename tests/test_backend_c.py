"""Generated C must implement the spec exactly, for every strategy and optimization level."""

from __future__ import annotations

from pathlib import Path

import pytest

from binarygym import reference
from binarygym.backends.c_linux import LinuxCBackend
from binarygym.compiler import BuildOptions, NativeCompiler
from binarygym.families import get_family
from binarygym.runner import SubprocessRunner
from binarygym.validation import validate
from tests.conftest import needs_toolchain

backend = LinuxCBackend()
family = get_family("transformation")


def test_source_does_not_contain_plaintext_secret() -> None:
    spec = family.generate(12345)
    for strategy in backend.strategies(spec):
        assert spec.secret.value not in backend.render(spec, strategy).text


def test_strategy_choice_is_deterministic_and_varied() -> None:
    assert backend.choose_strategy(family.generate(5)) == backend.choose_strategy(
        family.generate(5)
    )
    chosen = {backend.choose_strategy(family.generate(s)) for s in range(50)}
    assert chosen == set(backend.strategies(family.generate(0)))


def test_unknown_strategy_rejected() -> None:
    with pytest.raises(Exception, match="unknown strategy"):
        backend.render(family.generate(1), "nonexistent")


@needs_toolchain
@pytest.mark.parametrize("strategy", ["fused_loop", "staged_passes"])
@pytest.mark.parametrize("optimization", ["O0", "O2"])
@pytest.mark.parametrize("seed", [1, 2, 12345])
def test_every_strategy_matches_reference(
    tmp_path: Path, strategy: str, optimization: str, seed: int
) -> None:
    spec = family.generate(seed)
    artifact = NativeCompiler.detect().compile(
        backend.render(spec, strategy), tmp_path, BuildOptions(optimization, strip=True)
    )
    report = validate(spec, artifact.binary, backend.safety_policy, SubprocessRunner())
    assert report.passed, report.failures()


@needs_toolchain
@pytest.mark.parametrize("strategy", ["fused_loop", "staged_passes"])
def test_optimizer_does_not_reconstruct_plaintext(tmp_path: Path, strategy: str) -> None:
    # Regression: clang -O2 once folded the inverse pipeline into a plaintext constant.
    compiler = NativeCompiler.detect()
    for seed in range(20):
        spec = family.generate(seed)
        artifact = compiler.compile(
            backend.render(spec, strategy), tmp_path / str(seed), BuildOptions("O2")
        )
        assert spec.secret.value.encode() not in artifact.binary.read_bytes(), seed


@needs_toolchain
def test_binary_agrees_with_reference_on_arbitrary_inputs(tmp_path: Path) -> None:
    spec = family.generate(424242)
    artifact = NativeCompiler.detect().compile(
        backend.render(spec, "fused_loop"), tmp_path, BuildOptions()
    )
    runner = SubprocessRunner()
    secret = spec.secret.value.encode()
    inputs = [
        secret[:i] + bytes([b]) + secret[i + 1 :] for i in range(len(secret)) for b in (0x41, 0x7A)
    ]
    for raw in [*inputs, secret, b"\x00" + secret, secret + b"\n\n"]:
        result = runner.run([str(artifact.binary)], raw)
        assert (result.exit_code == 0) == reference.accepts(spec, raw), raw


@needs_toolchain
def test_rebuild_is_bit_identical_with_same_toolchain(tmp_path: Path) -> None:
    spec = family.generate(12345)
    source = backend.render(spec, backend.choose_strategy(spec))
    compiler = NativeCompiler.detect()
    a = compiler.compile(source, tmp_path / "a", BuildOptions("O1", strip=True))
    b = compiler.compile(source, tmp_path / "b", BuildOptions("O1", strip=True))
    assert a.sha256 == b.sha256
