"""Linux C backend.

Rendering strategies
--------------------
A checker is never tied to one fixed template. Each checker kind maps to several
strategies; a strategy may declare that it cannot express a given checker (e.g. a
fused per-byte loop cannot express a byte permutation). Every strategy must
implement the same ChallengeSpec semantics - validation proves it against the
reference evaluator. The choice is drawn from a dedicated RNG sub-stream so it is
reproducible, and it is recorded in the BuildSpec, not in the ChallengeSpec.

Generated programs only read one line from stdin and print a verdict.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from binarygym.backends.base import RenderedSource, SafetyPolicy
from binarygym.build import Target
from binarygym.errors import BinaryGymError
from binarygym.rng import Rng
from binarygym.spec import ByteCompareChecker, ChallengeSpec, Checker, StateMachineChecker
from binarygym.transforms import (
    AddConst,
    Permutation,
    PositionXor,
    RotateLeft,
    Substitution,
    Transform,
    XorConst,
)

SOURCE_FILENAME = "challenge.c"
SUCCESS_LINE = "SUCCESS"
DENIED_LINE = "ACCESS DENIED"


class LinuxCSafetyPolicy:
    """Every dynamically imported symbol must be on an explicit allowlist.

    This is the Linux/C policy only; other backends define their own.
    """

    name = "linux-c-imports-v1"
    ALLOWED_IMPORTS = frozenset({
        # stdio / string functions the templates use (and their compiler-lowered forms)
        "fgets", "fputs", "puts", "printf", "putchar", "fwrite", "fflush",
        "strlen", "strcspn", "strcmp", "memcmp", "bcmp", "memcpy", "stdin", "stdout",
        # C runtime / toolchain plumbing
        "__libc_start_main", "__stack_chk_fail", "__cxa_finalize", "__gmon_start__",
        "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable",
    })  # fmt: skip

    def check(self, artifact: Path) -> list[str]:
        nm = shutil.which("nm")
        if nm is None:
            return ["cannot inspect imports: 'nm' (binutils) not found"]
        proc = subprocess.run(
            [nm, "-D", "--undefined-only", str(artifact)],
            capture_output=True, text=True, timeout=30, check=False,
        )  # fmt: skip
        if proc.returncode != 0:
            return [f"nm failed: {proc.stderr.strip()}"]
        imported = {line.split()[-1].split("@")[0] for line in proc.stdout.splitlines() if line}
        return [f"disallowed import: {s}" for s in sorted(imported - self.ALLOWED_IMPORTS)]


@dataclass(frozen=True)
class _Strategy:
    render: Callable[[Checker], str]
    applies: Callable[[Checker], bool]


class LinuxCBackend:
    name = "linux-c"
    target = Target(platform="linux", arch="x86_64", language="c", artifact="elf")
    safety_policy: SafetyPolicy = LinuxCSafetyPolicy()

    def host_problems(self) -> list[str]:
        """Reasons this host cannot build and run this backend's artifacts natively."""
        problems = []
        system, machine = platform.system(), platform.machine().lower()
        if system != "Linux":
            problems.append(
                f"host OS is {system}, but linux-c builds Linux ELF binaries; "
                "use a Linux container, e.g. "
                '`docker run --rm -it --platform linux/amd64 -v "$PWD":/work -w /work '
                "python:3.12 bash`"
            )
        if machine not in ("x86_64", "amd64"):
            problems.append(f"host architecture is {machine}, but linux-c targets x86_64")
        if shutil.which("nm") is None:
            problems.append("'nm' (binutils) not found; it is needed for the import safety check")
        return problems

    def strategies(self, spec: ChallengeSpec) -> tuple[str, ...]:
        return tuple(name for name, s in _STRATEGIES[spec.checker.kind].items()
                     if s.applies(spec.checker))  # fmt: skip

    def choose_strategy(self, spec: ChallengeSpec) -> str:
        rng = Rng.from_seed(spec.seed).fork(f"backend/{self.name}/strategy")
        return rng.choice(self.strategies(spec))

    def render(self, spec: ChallengeSpec, strategy: str) -> RenderedSource:
        s = _STRATEGIES[spec.checker.kind].get(strategy)
        if s is None or not s.applies(spec.checker):
            raise BinaryGymError(f"unknown strategy {strategy!r} for {spec.checker.kind}")
        return RenderedSource(SOURCE_FILENAME, s.render(spec.checker), strategy)


# --- C emission helpers -------------------------------------------------------


def _c_bytes(data: bytes, indent: str = "    ") -> str:
    rows = [", ".join(f"0x{b:02x}" for b in data[i : i + 12]) for i in range(0, len(data), 12)]
    return f",\n{indent}".join(rows)


def _c_array(name: str, size: str, data: bytes) -> str:
    return f"static const unsigned char {name}[{size}] = {{\n    {_c_bytes(data)}\n}};\n"


def _c_step(t: Transform, index: int, var: str = "v", pos: str = "i") -> str:
    """One per-byte stage as a C statement (``pos`` is the byte's index)."""
    if isinstance(t, XorConst):
        return f"{var} ^= 0x{t.key:02x};"
    if isinstance(t, AddConst):
        return f"{var} = (unsigned char)({var} + 0x{t.addend:02x}u);"
    if isinstance(t, RotateLeft):
        return f"{var} = (unsigned char)(({var} << {t.bits}) | ({var} >> {8 - t.bits}));"
    if isinstance(t, PositionXor):
        return f"{var} ^= (unsigned char)(0x{t.mul:02x}u * {pos} + 0x{t.offset:02x}u);"
    if isinstance(t, Substitution):
        return f"{var} = sub_{index}[{var}];"
    raise BinaryGymError(f"linux-c backend cannot render transform {t.op!r} per byte")


def _stage_tables(checker: ByteCompareChecker) -> str:
    out = []
    for i, t in enumerate(checker.pipeline):
        if isinstance(t, Substitution):
            out.append(_c_array(f"sub_{i}", "256", t.table))
        elif isinstance(t, Permutation):
            out.append(_c_array(f"order_{i}", "EXPECTED_LEN", bytes(t.order)))
    return "\n".join(out)


def _program(length: int, decls: str, body: str) -> str:
    return f"""\
/* Generated by BinaryGym: benign practice challenge. Reads one line, prints a verdict. */
#include <stdio.h>
#include <string.h>

#define EXPECTED_LEN {length}u

{decls}
static int deny(void) {{
    puts("{DENIED_LINE}");
    return 1;
}}

int main(void) {{
    char line[256];
    fputs("Enter key: ", stdout);
    fflush(stdout);
    if (fgets(line, sizeof line, stdin) == NULL) {{
        return deny();
    }}
    line[strcspn(line, "\\r\\n")] = '\\0';
    if (strlen(line) != EXPECTED_LEN) {{
        return deny();
    }}
{body}    puts("{SUCCESS_LINE}");
    return 0;
}}
"""


def _ref_decls(checker: ByteCompareChecker) -> str:
    return _c_array("ref", "EXPECTED_LEN", checker.expected)


# Read through a volatile slot so the optimizer cannot fold the comparison data
# (at -O2 it could otherwise precompute the inverse, i.e. the plaintext answer).
_REF_SLOT = """\
    const unsigned char *const volatile ref_slot = ref;
    const unsigned char *table = ref_slot;
"""


def _as_byte_compare(checker: Checker) -> ByteCompareChecker:
    assert isinstance(checker, ByteCompareChecker)
    return checker


def _render_fused_loop(checker: Checker) -> str:
    """One loop applies the whole pipeline per byte and accumulates differences."""
    c = _as_byte_compare(checker)
    steps = "\n".join(f"        {_c_step(t, i)}" for i, t in enumerate(c.pipeline))
    body = (
        _REF_SLOT
        + f"""\
    unsigned char diff = 0;
    for (size_t i = 0; i < EXPECTED_LEN; i++) {{
        unsigned char v = (unsigned char)line[i];
{steps}
        diff |= (unsigned char)(v ^ table[i]);
    }}
    if (diff != 0) {{
        return deny();
    }}
"""
    )
    return _program(c.input_length, _ref_decls(c) + _stage_tables(c), body)


def _render_staged_passes(checker: Checker) -> str:
    """One helper function per stage over a working buffer, then memcmp."""
    c = _as_byte_compare(checker)
    helpers = []
    for i, t in enumerate(c.pipeline):
        if isinstance(t, Permutation):
            loop = f"""\
    unsigned char tmp[EXPECTED_LEN];
    for (size_t i = 0; i < n; i++) {{
        tmp[i] = buf[order_{i}[i]];
    }}
    memcpy(buf, tmp, n);"""
        else:
            loop = f"""\
    for (size_t i = 0; i < n; i++) {{
        unsigned char v = buf[i];
        {_c_step(t, i)}
        buf[i] = v;
    }}"""
        helpers.append(f"static void stage_{i}(unsigned char *buf, size_t n) {{\n{loop}\n}}\n")
    calls = "".join(f"    stage_{i}(work, EXPECTED_LEN);\n" for i in range(len(c.pipeline)))
    body = (
        _REF_SLOT
        + f"""\
    unsigned char work[EXPECTED_LEN];
    memcpy(work, line, EXPECTED_LEN);
{calls}    if (memcmp(work, table, EXPECTED_LEN) != 0) {{
        return deny();
    }}
"""
    )
    decls = _ref_decls(c) + _stage_tables(c) + "\n" + "\n".join(helpers)
    return _program(c.input_length, decls, body)


def _render_string_compare(checker: Checker) -> str:
    """The classic beginner check: strcmp against a string literal (plaintext by design)."""
    c = _as_byte_compare(checker)
    literal = c.expected.decode("ascii")
    body = f"""\
    if (strcmp(line, "{literal}") != 0) {{
        return deny();
    }}
"""
    return _program(c.input_length, "", body)


def _as_state_machine(checker: Checker) -> StateMachineChecker:
    assert isinstance(checker, StateMachineChecker)
    return checker


def _sm_defines(m: StateMachineChecker) -> str:
    return (
        f"#define STATE_START {m.start}u\n#define STATE_ACCEPT {m.accept}u\n"
        f"#define STATE_DEAD {m.dead}u\n"
    )


def _render_transition_table(checker: Checker) -> str:
    """A 2-D transition table indexed by [state][character]."""
    m = _as_state_machine(checker)
    rows = ",\n".join(f"    {{\n        {_c_bytes(row, '        ')}\n    }}" for row in m.rows)
    decls = (
        _sm_defines(m)
        + f"\nstatic const unsigned char transitions[{m.state_count}][128] = {{\n{rows}\n}};\n"
    )
    body = """\
    unsigned int state = STATE_START;
    for (size_t i = 0; i < EXPECTED_LEN; i++) {
        unsigned char c = (unsigned char)line[i];
        state = c < 128u ? transitions[state][c] : STATE_DEAD;
    }
    if (state != STATE_ACCEPT) {
        return deny();
    }
"""
    return _program(m.input_length, decls, body)


def _render_switch_dispatch(checker: Checker) -> str:
    """Nested switch statements: one case per state, one case group per target state."""
    m = _as_state_machine(checker)
    cases = []
    for state, row in enumerate(m.rows):
        targets: dict[int, list[int]] = {}
        for c, nxt in enumerate(row):
            if nxt != m.dead:
                targets.setdefault(nxt, []).append(c)
        if not targets:
            continue
        groups = "".join(
            "        " + " ".join(f"case 0x{c:02x}:" for c in chars) + f" return {nxt}u;\n"
            for nxt, chars in targets.items()
        )
        cases.append(
            f"    case {state}u:\n        switch (c) {{\n{groups}"
            "        default: return STATE_DEAD;\n        }\n"
        )
    decls = (
        _sm_defines(m)
        + "\nstatic unsigned int next_state(unsigned int state, unsigned char c) {\n"
        + "    switch (state) {\n"
        + "".join(cases)
        + "    default:\n        return STATE_DEAD;\n    }\n}\n"
    )
    body = """\
    unsigned int state = STATE_START;
    for (size_t i = 0; i < EXPECTED_LEN; i++) {
        state = next_state(state, (unsigned char)line[i]);
    }
    if (state != STATE_ACCEPT) {
        return deny();
    }
"""
    return _program(m.input_length, decls, body)


def _always(_: Checker) -> bool:
    return True


def _per_byte_only(checker: Checker) -> bool:
    return not any(t.reorders for t in _as_byte_compare(checker).pipeline)


def _plaintext_only(checker: Checker) -> bool:
    return _as_byte_compare(checker).embeds_plaintext()


_STRATEGIES: dict[str, dict[str, _Strategy]] = {
    "byte_compare": {
        "fused_loop": _Strategy(_render_fused_loop, _per_byte_only),
        "staged_passes": _Strategy(_render_staged_passes, _always),
        "string_compare": _Strategy(_render_string_compare, _plaintext_only),
    },
    "state_machine": {
        "transition_table": _Strategy(_render_transition_table, _always),
        "switch_dispatch": _Strategy(_render_switch_dispatch, _always),
    },
}
