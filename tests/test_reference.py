from __future__ import annotations

import pytest

from binarygym.reference import MAX_LINE, candidate_from_line


@pytest.mark.parametrize(
    ("raw", "candidate"),
    [
        (b"abc\n", b"abc"),
        (b"abc", b"abc"),
        (b"abc\r\n", b"abc"),
        (b"ab\0c\n", b"ab"),
        (b"", b""),
        (b"x" * 300, b"x" * MAX_LINE),
    ],
)
def test_line_contract(raw: bytes, candidate: bytes) -> None:
    assert candidate_from_line(raw) == candidate
