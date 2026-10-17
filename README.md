# BinaryGym

Procedural engine for **safe, reproducible, automatically verified reverse-engineering practice challenges**.

BinaryGym is not a course and does not claim to teach reverse engineering. It generates
challenges; you analyze them with your own tools (Ghidra, IDA Free, Binary Ninja, radare2,
objdump, gdb, ...). It never generates malicious functionality — see `docs/PLAN.md` §6.

> Status: **Slice 1** (proof of concept). One family (`transformation`), Linux x86_64, C.

## Prerequisites

- Linux x86_64, Python 3.12+
- `clang` (preferred) or `gcc`, and `nm` (binutils)

## Quick start

```bash
pip install -e '.[dev]'
binarygym generate --family transformation --seed 12345
./generated/<challenge-id>/challenge
binarygym verify ./generated/<challenge-id> YOUR_ANSWER
```

`generate` writes two things:

- `generated/<id>/` — the **public** package (`challenge`, `README.md`, `metadata.json`).
  Safe to hand to a participant: it contains no answer, seed or spec.
- `.binarygym/private/<id>.json` — the **private** record (spec, seed, solution, build
  info, validation report). `verify` uses it. Never distribute it.

A challenge is only packaged after validation: the binary must accept the intended answer,
reject a set of wrong answers, agree with the Python reference evaluator on every probe,
finish within a timeout and satisfy the backend's safety policy.

## Seeds and reproducibility

The same BinaryGym version, family/version, seed and options produce the same logical
`ChallengeSpec` (and, with the same compiler, normally the same binary).

Without `--seed`, a random 128-bit seed is used. **An explicit, small seed is reproducible
but guessable**: since the generator is open source, anyone can regenerate the challenge
from it. Do not use small seeds for challenges whose answer should stay unknown.

## Development

```bash
pytest && ruff check . && ruff format --check . && mypy
```

Design and roadmap: [`docs/PLAN.md`](docs/PLAN.md).
