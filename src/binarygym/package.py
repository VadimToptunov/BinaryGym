"""Challenge packaging with strict public/private separation.

Public package (safe to distribute), one per build::

    <out_root>/<build_id>/challenge
    <out_root>/<build_id>/README.md
    <out_root>/<build_id>/metadata.json

Private records (never distributed), outside the working directory by default::

    <private_root>/<challenge_id>/challenge.json            spec + reference solution
    <private_root>/<challenge_id>/builds/<build_id>.json    build spec + validation report

Public metadata is built from an explicit allowlist of fields, never by removing
secret fields from the spec.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from binarygym import difficulty
from binarygym.build import BUILD_ID_RE, BuildSpec
from binarygym.compiler import BuildArtifact
from binarygym.errors import BinaryGymError, ChallengeNotFound, SpecError
from binarygym.spec import CHALLENGE_ID_RE, ChallengeSpec
from binarygym.validation import ValidationReport

PUBLIC_METADATA_VERSION = 2
PRIVATE_RECORD_VERSION = 2
METADATA_FILE = "metadata.json"
BINARY_FILE = "challenge"
README_FILE = "README.md"
CHALLENGE_RECORD = "challenge.json"


def public_metadata(
    spec: ChallengeSpec, build: BuildSpec, artifact: BuildArtifact, concepts: tuple[str, ...]
) -> dict[str, Any]:
    diff = difficulty.with_build(spec.difficulty, build.optimization, build.strip)
    return {
        "public_metadata_version": PUBLIC_METADATA_VERSION,
        "challenge_id": spec.challenge_id,
        "build_id": build.build_id,
        "family": spec.family,
        "family_version": spec.family_version,
        "generator_version": spec.generator_version,
        "goal": spec.goal,
        "target": build.target.to_dict(),
        "difficulty": {**diff.to_dict(), "note": "heuristic estimate, not measured"},
        "concepts": list(concepts),
        "binary": {
            "file": BINARY_FILE,
            "sha256": artifact.sha256,
            "optimization": build.optimization,
            "stripped": build.strip,
            "compiler": build.compiler_version,
        },
    }


def public_readme(meta: dict[str, Any]) -> str:
    concepts = "\n".join(f"  - {c}" for c in meta["concepts"])
    return f"""# BinaryGym challenge `{meta["build_id"]}`

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
    build: BuildSpec,
    artifact: BuildArtifact,
    report: ValidationReport,
    solution: dict[str, Any],
    concepts: tuple[str, ...],
    out_root: Path,
    private_root: Path,
    force: bool = False,
) -> tuple[Path, Path]:
    if not report.passed:
        raise BinaryGymError("refusing to package a challenge that failed validation")
    public_dir = out_root / build.build_id
    if public_dir.exists() and not force:
        raise BinaryGymError(f"{public_dir} already exists (use --force to replace it)")

    meta = public_metadata(spec, build, artifact, concepts)
    out_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=out_root))
    try:
        os.chmod(staging, 0o755)
        shutil.copyfile(artifact.binary, staging / BINARY_FILE)
        os.chmod(staging / BINARY_FILE, 0o755)
        (staging / README_FILE).write_text(public_readme(meta))
        (staging / METADATA_FILE).write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

        challenge_dir = private_root / spec.challenge_id
        _write_private(
            challenge_dir / CHALLENGE_RECORD,
            {"private_record_version": PRIVATE_RECORD_VERSION, "spec": spec.to_dict(),
             "solution": solution},
        )  # fmt: skip
        build_path = challenge_dir / "builds" / f"{build.build_id}.json"
        _write_private(
            build_path,
            {
                "private_record_version": PRIVATE_RECORD_VERSION,
                "build_id": build.build_id,
                "build": build.to_dict(),
                "artifact": {"sha256": artifact.sha256, "flags": list(artifact.flags)},
                "validation": report.to_dict(),
            },
        )
        if public_dir.exists():
            shutil.rmtree(public_dir)
        staging.rename(public_dir)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return public_dir, build_path


def _write_private(path: Path, record: dict[str, Any]) -> None:
    for parent in reversed(path.parents):
        if not parent.exists():
            parent.mkdir(mode=0o700)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


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
    if not isinstance(meta, dict):
        raise SpecError(f"{path} is not a metadata object")
    if meta.get("public_metadata_version") != PUBLIC_METADATA_VERSION:
        raise SpecError(
            f"{path} uses an unsupported metadata format; regenerate the challenge with the "
            "current BinaryGym version"
        )
    if not CHALLENGE_ID_RE.match(str(meta.get("challenge_id"))) or not BUILD_ID_RE.match(
        str(meta.get("build_id"))
    ):
        raise SpecError(f"{path} has a malformed challenge_id or build_id")
    return meta


def _read_private(path: Path, what: str) -> dict[str, Any]:
    try:
        record = json.loads(path.read_text())
    except FileNotFoundError:
        raise ChallengeNotFound(
            f"no private {what} at {path}; verification needs the private data created at "
            "generation time (see --private-dir / BINARYGYM_PRIVATE_DIR)"
        ) from None
    except json.JSONDecodeError as exc:
        raise SpecError(f"private record {path} is not valid JSON") from exc
    if (
        not isinstance(record, dict)
        or record.get("private_record_version") != PRIVATE_RECORD_VERSION
    ):
        raise SpecError(f"private record {path} has an unsupported format")
    return record


def load_private_record(challenge_id: str, private_root: Path) -> dict[str, Any]:
    if not CHALLENGE_ID_RE.match(challenge_id):
        raise ChallengeNotFound(f"malformed challenge id {challenge_id!r}")
    path = private_root / challenge_id / CHALLENGE_RECORD
    record = _read_private(path, "record for " + challenge_id)
    spec = ChallengeSpec.from_dict(record.get("spec"))
    if spec.challenge_id != challenge_id:
        raise SpecError(f"private record {path} belongs to {spec.challenge_id}")
    return record


def load_private_spec(challenge_id: str, private_root: Path) -> ChallengeSpec:
    return ChallengeSpec.from_dict(load_private_record(challenge_id, private_root)["spec"])


def load_build_record(challenge_id: str, build_id: str, private_root: Path) -> dict[str, Any]:
    if not BUILD_ID_RE.match(build_id):
        raise ChallengeNotFound(f"malformed build id {build_id!r}")
    path = private_root / challenge_id / "builds" / f"{build_id}.json"
    return _read_private(path, "build record for " + build_id)
