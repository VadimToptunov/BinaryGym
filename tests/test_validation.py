from __future__ import annotations

from pathlib import Path

from binarygym.backends.base import RenderedSource
from binarygym.backends.c_linux import LinuxCBackend, LinuxCSafetyPolicy
from binarygym.compiler import BuildOptions, NativeCompiler
from binarygym.families import get_family
from binarygym.runner import SubprocessRunner
from binarygym.validation import validate
from tests.conftest import needs_toolchain

family = get_family("transformation")
backend = LinuxCBackend()


def build(tmp_path: Path, text: str) -> Path:
    src = RenderedSource("challenge.c", text, "handwritten")
    return NativeCompiler.detect().compile(src, tmp_path, BuildOptions()).binary


def failed(report: object) -> set[str]:
    return {c.name for c in report.failures()}  # type: ignore[attr-defined]


@needs_toolchain
def test_binary_from_another_spec_is_rejected(tmp_path: Path) -> None:
    spec, other = family.generate(1), family.generate(2)
    binary = build(tmp_path, backend.render(other, "fused_loop").text)
    report = validate(spec, binary, backend.safety_policy, SubprocessRunner())
    assert not report.passed
    assert "binary_matches_intent" in failed(report)
    assert "binary_agrees_with_reference" in failed(report)


@needs_toolchain
def test_plaintext_leak_regression_detector(tmp_path: Path) -> None:
    spec = family.generate(3)
    leaky = (
        backend.render(spec, "fused_loop")
        .text.replace(
            "int main(void) {",
            f'const char *debug_note = "{spec.secret.value}";\nint main(void) {{',
        )
        .replace("    char line[256];", "    char line[256];\n    (void)debug_note;")
    )
    report = validate(spec, build(tmp_path, leaky), backend.safety_policy, SubprocessRunner())
    assert "plaintext_leak_regression" in failed(report)


@needs_toolchain
def test_hanging_binary_fails_timeout_check(tmp_path: Path) -> None:
    spec = family.generate(4)
    hanging = "int main(void) { volatile int x = 1; while (x) {} return 0; }\n"
    report = validate(spec, build(tmp_path, hanging), backend.safety_policy, SubprocessRunner(),
                      timeout=0.2)  # fmt: skip
    assert "within_timeout" in failed(report)


@needs_toolchain
def test_backend_policy_flags_disallowed_imports(tmp_path: Path) -> None:
    # Compiled only to inspect its import table; never executed.
    source = (
        '#include <unistd.h>\n#include <stdio.h>\nint main(void) { printf("%d", (int)getpid()); }\n'
    )
    violations = LinuxCSafetyPolicy().check(build(tmp_path, source))
    assert violations == ["disallowed import: getpid"]
