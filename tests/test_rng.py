from __future__ import annotations

import pytest

from binarygym.rng import MAX_SEED, Rng


def draws(rng: Rng, n: int = 20) -> list[int]:
    return [rng.next_u64() for _ in range(n)]


def test_same_seed_same_stream() -> None:
    assert draws(Rng.from_seed(42)) == draws(Rng.from_seed(42))


def test_different_seeds_differ() -> None:
    assert draws(Rng.from_seed(1)) != draws(Rng.from_seed(2))


def test_known_values_are_stable() -> None:
    # Frozen output: changing it silently changes every generated challenge.
    assert draws(Rng.from_seed(12345), 3) == [
        13337657837910739137,
        2416479722038485486,
        3674337242975617779,
    ]


def test_forks_are_independent_of_draws_elsewhere() -> None:
    a = Rng.from_seed(7)
    untouched = draws(a.fork("secret"))
    b = Rng.from_seed(7)
    draws(b.fork("pipeline"), 100)  # consuming another sub-stream...
    b.next_u64()  # ...or the parent...
    assert draws(b.fork("secret")) == untouched  # ...does not shift this one


def test_below_bounds_and_coverage() -> None:
    rng = Rng.from_seed(3)
    values = {rng.below(10) for _ in range(1000)}
    assert values == set(range(10))


def test_shuffled_is_permutation() -> None:
    items = list(range(50))
    out = Rng.from_seed(9).shuffled(items)
    assert sorted(out) == items and out != items


@pytest.mark.parametrize("seed", [-1, MAX_SEED + 1])
def test_seed_range_enforced(seed: int) -> None:
    with pytest.raises(ValueError):
        Rng.from_seed(seed)


def test_splitmix64_reference_vector() -> None:
    # Published SplitMix64 outputs for state 1234567 (Vigna's reference implementation).
    rng = Rng(bytes(32))
    rng._state = 1234567
    assert draws(rng, 3) == [6457827717110365317, 3203168211198807973, 9817491932198370423]
