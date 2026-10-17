"""Backend and safety-policy interfaces.

A backend owns everything target-specific: which rendering strategies exist
for each checker kind, how source is emitted, and which artifact-level safety
policy applies (runtime dependencies differ wildly between C, Rust, JVM, ...).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from binarygym.build import Target
from binarygym.spec import ChallengeSpec


@dataclass(frozen=True)
class RenderedSource:
    filename: str
    text: str
    strategy: str


class SafetyPolicy(Protocol):
    name: str

    def check(self, artifact: Path) -> list[str]:
        """Return human-readable violations; empty means the artifact complies."""
        ...


class Backend(Protocol):
    name: str
    target: Target
    safety_policy: SafetyPolicy

    def host_problems(self) -> list[str]:
        """Reasons this host cannot build and run the backend's artifacts (empty: fine)."""
        ...

    def strategies(self, spec: ChallengeSpec) -> tuple[str, ...]:
        """Rendering strategies available for this spec's checker."""
        ...

    def choose_strategy(self, spec: ChallengeSpec) -> str:
        """Deterministic choice derived from the spec's seed."""
        ...

    def render(self, spec: ChallengeSpec, strategy: str) -> RenderedSource: ...
