"""Validation: a challenge is published only if its binary provably matches its spec.

Checks (all must pass):

* the reference evaluator accepts the generated secret and rejects every wrong probe;
* the binary accepts the secret and rejects every wrong probe;
* the binary agrees with the reference evaluator on every probe (including edge cases
  such as CRLF, embedded NUL and over-long lines);
* every run finishes within the timeout and prints a well-formed verdict;
* ``plaintext_leak_regression``: the secret does not appear verbatim in the binary
  (skipped for checkers that embed the answer by design, e.g. the ``direct`` family).
  This is a regression/leak detector for generator or optimizer mistakes only. It says
  nothing about how hard the challenge is or how resistant it is to analysis;
* the backend's own safety policy (target-specific; the validator knows no rules itself).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from binarygym import reference
from binarygym.backends.base import SafetyPolicy
from binarygym.rng import Rng
from binarygym.runner import DEFAULT_TIMEOUT, Runner
from binarygym.spec import ChallengeSpec

SUCCESS_SUFFIX = b"SUCCESS\n"
DENIED_SUFFIX = b"ACCESS DENIED\n"


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class ValidationReport:
    checks: tuple[Check, ...]

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.checks
            ],
        }


@dataclass(frozen=True)
class Probe:
    label: str
    raw: bytes
    must_accept: bool | None  # None: edge case where only agreement is required


def build_probes(spec: ChallengeSpec, wrong_count: int = 12) -> list[Probe]:
    """Deterministic probe set: the answer, wrong answers and line-contract edge cases."""
    rng = Rng.from_seed(spec.seed).fork("validation/probes")
    secret = spec.secret.value.encode("ascii")
    alphabet = spec.secret.alphabet
    probes = [
        Probe("secret", secret + b"\n", True),
        Probe("secret-no-newline", secret, True),
        Probe("secret-crlf", secret + b"\r\n", True),
        Probe("secret-nul-suffix", secret + b"\0trailing\n", None),
        Probe("empty", b"", False),
        Probe("blank-line", b"\n", False),
        Probe("truncated", secret[:-1] + b"\n", False),
        Probe("extended", secret + b"A\n", False),
        Probe("doubled", secret + secret + b"\n", False),
        Probe("overlong", b"A" * 300 + b"\n", False),
        Probe("swapcase", secret.swapcase() + b"\n", None),
    ]
    for i in range(wrong_count):
        pos = rng.below(len(secret))
        replacement = rng.choice([c for c in alphabet if ord(c) != secret[pos]])
        mutated = secret[:pos] + replacement.encode() + secret[pos + 1 :]
        probes.append(Probe(f"substitution-{i}", mutated + b"\n", False))
    for i in range(3):
        rand = "".join(rng.choice(alphabet) for _ in secret).encode()
        probes.append(Probe(f"random-{i}", rand + b"\n", None if rand == secret else False))
    return probes


def _verdict(stdout: bytes, exit_code: int | None) -> bool | None:
    if exit_code == 0 and stdout.endswith(SUCCESS_SUFFIX):
        return True
    if exit_code == 1 and stdout.endswith(DENIED_SUFFIX):
        return False
    return None  # malformed: crash, wrong exit code or unexpected output


def validate(
    spec: ChallengeSpec,
    binary: Path,
    policy: SafetyPolicy,
    runner: Runner,
    timeout: float = DEFAULT_TIMEOUT,
) -> ValidationReport:
    probes = build_probes(spec)
    ref_errors, bin_errors, disagreements, malformed, timeouts = [], [], [], [], []
    for probe in probes:
        ref = reference.accepts(spec, probe.raw)
        if probe.must_accept is not None and ref != probe.must_accept:
            ref_errors.append(probe.label)
        result = runner.run([str(binary.resolve())], probe.raw, timeout)
        if result.timed_out:
            timeouts.append(probe.label)
            continue
        got = _verdict(result.stdout, result.exit_code)
        if got is None:
            malformed.append(f"{probe.label} (exit {result.exit_code})")
            continue
        if probe.must_accept is not None and got != probe.must_accept:
            bin_errors.append(probe.label)
        if got != ref:
            disagreements.append(probe.label)

    plaintext_intended = spec.checker.embeds_plaintext()
    secret_leaked = spec.secret.value.encode("ascii") in binary.read_bytes()
    violations = policy.check(binary)
    n = len(probes)
    checks = (
        Check("reference_matches_intent", not ref_errors, _detail(ref_errors, n)),
        Check("binary_matches_intent", not bin_errors, _detail(bin_errors, n)),
        Check("binary_agrees_with_reference", not disagreements, _detail(disagreements, n)),
        Check("well_formed_verdicts", not malformed, _detail(malformed, n)),
        Check("within_timeout", not timeouts, f"timeout={timeout}s; " + _detail(timeouts, n)),
        Check(
            "plaintext_leak_regression",
            plaintext_intended or not secret_leaked,
            "skipped: this family stores the answer in plaintext by design"
            if plaintext_intended
            else "secret bytes found verbatim in binary"
            if secret_leaked
            else "no verbatim secret",
        ),
        Check(f"safety_policy:{policy.name}", not violations, "; ".join(violations) or "ok"),
    )
    return ValidationReport(checks)


def _detail(failed: list[str], total: int) -> str:
    return f"{total} probes ok" if not failed else f"failed: {', '.join(failed)}"
