# BinaryGym

Procedural engine for **safe, reproducible, automatically verified reverse-engineering practice challenges**.

BinaryGym is not a course and does not claim to teach reverse engineering. It generates
challenges; you analyze them with your own tools (Ghidra, IDA Free, Binary Ninja, radare2,
objdump, gdb, ...). It never generates malicious functionality — see `docs/PLAN.md` §6.

> Status: **Slice 2**. Three families, Linux x86_64 ELF, C backend.

## Prerequisites

- Linux x86_64, Python 3.12+
- `clang` (preferred) or `gcc`, and `nm` (binutils)

On macOS (or any non-Linux host) work inside a Linux container:

```bash
docker run --rm -it --platform linux/amd64 -v "$PWD":/work -w /work python:3.12 bash
```

## Quick start

```bash
pip install -e '.[dev]'
binarygym doctor                                   # is this machine ready?
binarygym list-families
binarygym generate --family transformation --seed 12345
./generated/<build-id>/challenge
binarygym verify ./generated/<build-id> YOUR_ANSWER
binarygym inspect ./generated/<build-id>           # public info only
```

## Families

| Family | What you recover | Notes |
|---|---|---|
| `direct` | a key stored as-is | beginner; the answer is visible to `strings` by design |
| `transformation` | a key passed through 3–5 reversible byte operations (XOR, ADD, rotate, position-keyed XOR, S-box, byte permutation) | v1 (XOR/rotate only) is kept for reproducibility |
| `state_machine` | the key that walks a hidden path through a finite state machine | shuffled state numbering, back edges and decoy states |

Each family is rendered by several **strategies** (e.g. one fused loop vs. one function per
stage; a transition table vs. nested `switch`), picked deterministically from the seed. Every
strategy is validated against the same reference evaluator.

## Public vs. private data

`generate` writes:

- `generated/<build-id>/` — the **public** package (`challenge`, `README.md`, `metadata.json`).
  Safe to hand to a participant: no answer, seed, spec or strategy.
- the **private** records, outside the working directory by default
  (`$BINARYGYM_PRIVATE_DIR`, else `~/.local/share/binarygym/private`):
  - `<challenge-id>/challenge.json` — spec, seed and reference solution;
  - `<challenge-id>/builds/<build-id>.json` — build spec and validation report.

Hand participants — and AI agents with file access — **only the public directory**.
`binarygym inspect --private` shows the answer and solution (developer mode).

A challenge (`bg-…`) is logical and platform-independent; each build of it (`bgb-…`) records
backend, target, strategy, compiler and options. A clang and a gcc build of the same challenge
are separate builds of one challenge.

A challenge is only packaged after validation: the binary must accept the intended answer,
reject a set of wrong answers, agree with the Python reference evaluator on every probe,
finish within a timeout and satisfy the backend's safety policy.

## Seeds and reproducibility

The same BinaryGym version, family/version, seed and options produce the same logical
`ChallengeSpec` and, with the same compiler, normally the same binary.

Without `--seed`, a random 128-bit seed is used. **An explicit, small seed is reproducible
but guessable**: since the generator is open source, anyone can regenerate the challenge
from it. Do not use small seeds for challenges whose answer should stay unknown.

## Development

```bash
pytest && ruff check . && ruff format --check . && mypy
```

Design and roadmap: [`docs/PLAN.md`](docs/PLAN.md).
