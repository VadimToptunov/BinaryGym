"""Generated C must implement the spec exactly, for every strategy and optimization level."""

from __future__ import annotations

from pathlib import Path

import pytest

from binarygym import reference
from binarygym.backends.c_linux import LinuxCBackend
from binarygym.compiler import BuildOptions, NativeCompiler
from binarygym.families import FAMILIES, get_family
from binarygym.runner import SubprocessRunner
from binarygym.spec import ByteCompareChecker
from binarygym.validation import validate
from tests.conftest import needs_toolchain

backend = LinuxCBackend()

CASES = [
    (name, version, strategy)
    for name, family in sorted(FAMILIES.items())
    for version in family.versions
    for strategy in sorted(
        {s for seed in range(40) for s in backend.strategies(family.generate(seed, version))}
    )
]


def test_every_family_has_several_strategies() -> None:
    for name, family in FAMILIES.items():
        chosen = {backend.choose_strategy(family.generate(s)) for s in range(60)}
        assert len(chosen) >= 2, name


def test_strategy_choice_is_deterministic() -> None:
    spec = get_family("state_machine").generate(5)
    assert backend.choose_strategy(spec) == backend.choose_strategy(spec)


def test_fused_loop_is_not_offered_for_permutations() -> None:
    family = get_family("transformation")
    for seed in range(100):
        spec = family.generate(seed)
        assert isinstance(spec.checker, ByteCompareChecker)
        has_perm = any(t.reorders for t in spec.checker.pipeline)
        assert ("fused_loop" in backend.strategies(spec)) != has_perm


def test_string_compare_only_for_plaintext_checkers() -> None:
    assert "string_compare" in backend.strategies(get_family("direct").generate(1))
    assert "string_compare" not in backend.strategies(get_family("transformation").generate(1))


def test_source_has_no_plaintext_secret_unless_intended() -> None:
    for name, family in FAMILIES.items():
        for seed in range(10):
            spec = family.generate(seed)
            for strategy in backend.strategies(spec):
                text = backend.render(spec, strategy).text
                assert (spec.secret.value in text) == (strategy == "string_compare"), name


def test_unknown_strategy_rejected() -> None:
    with pytest.raises(Exception, match="unknown strategy"):
        backend.render(get_family("transformation").generate(1), "nonexistent")
    with pytest.raises(Exception, match="unknown strategy"):
        backend.render(get_family("transformation").generate(1), "string_compare")


@needs_toolchain
@pytest.mark.parametrize(("name", "version", "strategy"), CASES)
@pytest.mark.parametrize("optimization", ["O0", "O2"])
def test_every_strategy_matches_reference(
    tmp_path: Path, name: str, version: int, strategy: str, optimization: str
) -> None:
    family = get_family(name)
    seeds = [s for s in range(40) if strategy in backend.strategies(family.generate(s, version))]
    compiler = NativeCompiler.detect()
    for seed in seeds[:3]:
        spec = family.generate(seed, version)
        artifact = compiler.compile(
            backend.render(spec, strategy), tmp_path / str(seed), BuildOptions(optimization, True)
        )
        report = validate(spec, artifact.binary, backend.safety_policy, SubprocessRunner())
        assert report.passed, (seed, report.failures())


@needs_toolchain
@pytest.mark.parametrize("strategy", ["fused_loop", "staged_passes"])
def test_optimizer_does_not_reconstruct_plaintext(tmp_path: Path, strategy: str) -> None:
    # Regression: clang -O2 once folded the inverse pipeline into a plaintext constant.
    compiler = NativeCompiler.detect()
    family = get_family("transformation")
    for seed in range(20):
        spec = family.generate(seed)
        if strategy not in backend.strategies(spec):
            continue
        artifact = compiler.compile(
            backend.render(spec, strategy), tmp_path / str(seed), BuildOptions("O2")
        )
        assert spec.secret.value.encode() not in artifact.binary.read_bytes(), seed


@needs_toolchain
@pytest.mark.parametrize("name", ["transformation", "state_machine"])
def test_binary_agrees_with_reference_on_near_misses(tmp_path: Path, name: str) -> None:
    spec = get_family(name).generate(424242)
    artifact = NativeCompiler.detect().compile(
        backend.render(spec, backend.choose_strategy(spec)), tmp_path, BuildOptions()
    )
    runner = SubprocessRunner()
    secret = spec.secret.value.encode()
    near = [
        secret[:i] + bytes([b]) + secret[i + 1 :] for i in range(len(secret)) for b in (65, 122)
    ]
    for raw in [*near, secret, b"\x00" + secret, secret + b"\n\n", b"\xff" * len(secret)]:
        result = runner.run([str(artifact.binary)], raw)
        assert (result.exit_code == 0) == reference.accepts(spec, raw), raw


@needs_toolchain
def test_rebuild_is_bit_identical_with_same_toolchain(tmp_path: Path) -> None:
    spec = get_family("transformation").generate(12345)
    source = backend.render(spec, backend.choose_strategy(spec))
    compiler = NativeCompiler.detect()
    a = compiler.compile(source, tmp_path / "a", BuildOptions("O1", strip=True))
    b = compiler.compile(source, tmp_path / "b", BuildOptions("O1", strip=True))
    assert a.sha256 == b.sha256


def test_host_problems_explain_docker_on_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    monkeypatch.setattr("platform.machine", lambda: "arm64")
    problems = backend.host_problems()
    assert any("docker run" in p for p in problems)
    assert any("arm64" in p for p in problems)
