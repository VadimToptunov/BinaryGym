"""Challenge packaging with strict public/private separation.

Public package (safe to distribute)::

    <out_root>/<challenge_id>/challenge
    <out_root>/<challenge_id>/README.md
    <out_root>/<challenge_id>/metadata.json

Private record (never distributed)::

    <private_root>/<challenge_id>.json

Public metadata is built from an explicit allowlist of fields, never by
removing secret fields from the spec.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from binarygym import difficulty
from binarygym.compiler import BuildArtifact, BuildOptions
from binarygym.errors import BinaryGymError, ChallengeNotFound, SpecError
from binarygym.spec import ChallengeSpec
from binarygym.validation import ValidationReport

PUBLIC_METADATA_VERSION = 1
PRIVATE_RECORD_VERSION = 1
METADATA_FILE = "metadata.json"
BINARY_FILE = "challenge"
README_FILE = "README.md"


@dataclass(frozen=True)
class BuildRecord:
    backend: str
    strategy: str
    options: BuildOptions
    artifact: BuildArtifact

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "strategy": self.strategy,
            "optimization": self.options.optimization,
            "strip": self.options.strip,
            "compiler": self.artifact.compiler.name,
            "compiler_version": self.artifact.compiler.version,
            "flags": list(self.artifact.flags),
            "binary_sha256": self.artifact.sha256,
        }


def public_metadata(
    spec: ChallengeSpec, build: BuildRecord, concepts: tuple[str, ...]
) -> dict[str, Any]:
    diff = difficulty.with_build(spec.difficulty, build.options.optimization, build.options.strip)
    return {
        "public_metadata_version": PUBLIC_METADATA_VERSION,
        "challenge_id": spec.challenge_id,
        "family": spec.family,
        "family_version": spec.family_version,
        "generator_version": spec.generator_version,
        "goal": spec.goal,
        "target": spec.target.to_dict(),
        "difficulty": {**diff.to_dict(), "note": "heuristic estimate, not measured"},
        "concepts": list(concepts),
        "binary": {
            "file": BINARY_FILE,
            "sha256": build.artifact.sha256,
            "optimization": build.options.optimization,
            "stripped": build.options.strip,
            "compiler": build.artifact.compiler.version,
        },
    }


def public_readme(meta: dict[str, Any]) -> str:
    concepts = "\n".join(f"- {c}" for c in meta["concepts"])
    return f"""# BinaryGym challenge `{meta["challenge_id"]}`

Goal: **recover the secret key.**

```
$ ./challenge
Enter key: <your guess>
```

The program prints `SUCCESS` for the correct key and `ACCESS DENIED` otherwise.
Analyze `challenge` with any tools you like (Ghidra, IDA Free, Binary Ninja, radare2,
objdump, gdb, ...), then check your answer:

```
binarygym verify <path-to-this-directory> <your-answer>
```

- Platform: {meta["target"]["platform"]} / {meta["target"]["arch"]}
- Estimated difficulty: **{meta["difficulty"]["label"].capitalize()}** (heuristic estimate)
- Skills exercised:
{concepts}

This is a benign practice program: it only reads one line from stdin and prints a verdict.
"""


def write_package(
    spec: ChallengeSpec,
    build: BuildRecord,
    report: ValidationReport,
    solution: dict[str, Any],
    concepts: tuple[str, ...],
    out_root: Path,
    private_root: Path,
    force: bool = False,
) -> tuple[Path, Path]:
    if not report.passed:
        raise BinaryGymError("refusing to package a challenge that failed validation")
    public_dir = out_root / spec.challenge_id
    if public_dir.exists() and not force:
        raise BinaryGymError(f"{public_dir} already exists (use --force to replace it)")

    meta = public_metadata(spec, build, concepts)
    out_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=out_root))
    try:
        os.chmod(staging, 0o755)
        shutil.copyfile(build.artifact.binary, staging / BINARY_FILE)
        os.chmod(staging / BINARY_FILE, 0o755)
        (staging / README_FILE).write_text(public_readme(meta))
        (staging / METADATA_FILE).write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

        private_path = _write_private(spec, build, report, solution, private_root)
        if public_dir.exists():
            shutil.rmtree(public_dir)
        staging.rename(public_dir)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return public_dir, private_path


def _write_private(
    spec: ChallengeSpec,
    build: BuildRecord,
    report: ValidationReport,
    solution: dict[str, Any],
    private_root: Path,
) -> Path:
    private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = {
        "private_record_version": PRIVATE_RECORD_VERSION,
        "spec": spec.to_dict(),
        "solution": solution,
        "build": build.to_dict(),
        "validation": report.to_dict(),
    }
    path = private_root / f"{spec.challenge_id}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return path


def read_public_metadata(public_dir: Path) -> dict[str, Any]:
    path = public_dir / METADATA_FILE
    try:
        meta = json.loads(path.read_text())
    except FileNotFoundError:
        raise ChallengeNotFound(
            f"{public_dir} is not a challenge directory (no {METADATA_FILE})"
        ) from None
    except json.JSONDecodeError as exc:
        raise SpecError(f"{path} is not valid JSON") from exc
    if not isinstance(meta, dict) or not isinstance(meta.get("challenge_id"), str):
        raise SpecError(f"{path} has no challenge_id")
    return meta


def load_private_spec(challenge_id: str, private_root: Path) -> ChallengeSpec:
    path = private_root / f"{challenge_id}.json"
    try:
        record = json.loads(path.read_text())
    except FileNotFoundError:
        raise ChallengeNotFound(
            f"no private record for {challenge_id} in {private_root}; "
            "verification needs the private data created at generation time"
        ) from None
    except json.JSONDecodeError as exc:
        raise SpecError(f"private record {path} is not valid JSON") from exc
    if (
        not isinstance(record, dict)
        or record.get("private_record_version") != PRIVATE_RECORD_VERSION
    ):
        raise SpecError(f"private record {path} has an unsupported format")
    spec = ChallengeSpec.from_dict(record.get("spec"))
    if spec.challenge_id != challenge_id:
        raise SpecError(f"private record {path} belongs to {spec.challenge_id}")
    return spec
