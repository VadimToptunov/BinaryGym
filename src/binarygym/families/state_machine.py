"""StateMachineFamily: input characters drive a finite state machine.

The program accepts the key iff, after consuming exactly ``input_length``
characters, the machine is in the accepting state. Exactly one key works:
the only transitions that move "forward" along the hidden path are the key's
characters; every other transition stays at the same depth or goes back
(including into decoy states, which only lead back to the start or die).
The state numbering is shuffled so the path is not visible as 0, 1, 2, ...
"""

from __future__ import annotations

from typing import Any

from binarygym import difficulty
from binarygym.families.base import DEFAULT_ALPHABET, generate_secret, resolve_version
from binarygym.rng import Rng
from binarygym.spec import GOAL_RECOVER_SECRET, ChallengeSpec, Secret, StateMachineChecker

DECOY_STATES = (2, 4)


class StateMachineFamily:
    name = "state_machine"
    versions: tuple[int, ...] = (1,)
    summary = "Recover the key that walks a hidden path through a finite state machine."
    concepts: tuple[str, ...] = (
        "locating input validation",
        "reconstructing state machines",
        "control-flow and table-driven logic",
    )

    @property
    def latest_version(self) -> int:
        return self.versions[-1]

    def generate(self, seed: int, version: int | None = None) -> ChallengeSpec:
        version = resolve_version(self, version)
        rng = Rng.from_seed(seed).fork(f"family/{self.name}/v{version}")
        secret = generate_secret(rng.fork("secret"))
        checker = _build_machine(rng.fork("machine"), secret.encode("ascii"))
        size = 1 if checker.state_count <= 16 else 2
        return ChallengeSpec.create(
            family=self.name,
            family_version=version,
            seed=seed,
            goal=GOAL_RECOVER_SECRET,
            secret=Secret(alphabet=DEFAULT_ALPHABET, value=secret),
            checker=checker,
            difficulty=difficulty.semantic(
                {
                    "transformation_complexity": 0,
                    "structural_complexity": 2,
                    "state_machine_size": size,
                }
            ),
        )

    def solution(self, spec: ChallengeSpec) -> dict[str, Any]:
        checker = spec.checker
        assert isinstance(checker, StateMachineChecker)
        path, state = [], checker.start
        for b in spec.secret.value.encode("ascii"):
            nxt = checker.step(state, b)
            path.append({"state": state, "char": chr(b), "next": nxt})
            state = nxt
        return {
            "answer": spec.secret.value,
            "input_length": checker.input_length,
            "start": checker.start,
            "accept": checker.accept,
            "dead": checker.dead,
            "state_count": checker.state_count,
            "path": path,
            "approach": "From the start state, follow the unique transition chain that reaches "
            "the accepting state after exactly input_length characters.",
        }


def _build_machine(rng: Rng, secret: bytes) -> StateMachineChecker:
    length = len(secret)
    decoys = rng.randint(*DECOY_STATES)
    total = length + 1 + decoys + 1  # chain c0..cL, decoys, dead
    ids = rng.shuffled(range(total))
    chain = ids[: length + 1]
    decoy_ids = ids[length + 1 : length + 1 + decoys]
    dead = ids[-1]
    alphabet = [ord(c) for c in DEFAULT_ALPHABET]

    rows = [bytearray([dead] * StateMachineChecker.ROW_WIDTH) for _ in range(total)]
    for depth in range(length):
        row = rows[chain[depth]]
        for c in alphabet:
            if c == secret[depth]:
                row[c] = chain[depth + 1]  # the only forward move
                continue
            roll = rng.below(6)
            if roll < 2:  # back edge: same or smaller depth
                row[c] = chain[rng.randint(0, depth)]
            elif roll == 2:
                row[c] = rng.choice(decoy_ids)
    for decoy in decoy_ids:  # decoys count as depth 0: they lead to decoys or the start
        row = rows[decoy]
        for c in alphabet:
            roll = rng.below(8)
            if roll < 2:
                row[c] = rng.choice(decoy_ids)
            elif roll == 2:
                row[c] = chain[0]
    # The accepting state and the dead state only lead to dead.
    return StateMachineChecker(
        input_length=length,
        state_count=total,
        start=chain[0],
        accept=chain[length],
        dead=dead,
        rows=tuple(bytes(r) for r in rows),
    )
