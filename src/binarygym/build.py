"""BuildSpec: how one ChallengeSpec is turned into one concrete artifact.

A challenge (``challenge_id``) is logical and platform-independent. Each build of
it - a backend, target, rendering strategy, toolchain and options - gets its own
deterministic ``build_id``, so a clang and a gcc build of the same challenge are
distinct artifacts with distinct records.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from binarygym.spec import canonical_json

BUILD_ID_RE = re.compile(r"^bgb-[0-9a-f]{16}$")


@dataclass(frozen=True)
class Target:
    platform: str
    arch: str
    language: str
    artifact: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "arch": self.arch,
            "language": self.language,
            "artifact": self.artifact,
        }


@dataclass(frozen=True)
class BuildSpec:
    challenge_id: str
    backend: str
    target: Target
    strategy: str
    optimization: str
    strip: bool
    compiler: str
    compiler_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "backend": self.backend,
            "target": self.target.to_dict(),
            "strategy": self.strategy,
            "optimization": self.optimization,
            "strip": self.strip,
            "compiler": self.compiler,
            "compiler_version": self.compiler_version,
        }

    @property
    def build_id(self) -> str:
        return "bgb-" + hashlib.sha256(canonical_json(self.to_dict()).encode()).hexdigest()[:16]
