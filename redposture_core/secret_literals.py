"""Completed assignment literals shared by materialized discovery scanners.

Without a declared input dialect, retain literal contents exactly. Backslashes
affect quote termination, not decoding; JSON decoding belongs to its parser.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable, Iterator
from dataclasses import dataclass

_HEAD = re.compile(r"""(?i)(?<![\w.])(?:--)?([A-Za-z][A-Za-z0-9._-]{0,127})["']?\s*(?:=>|[:=])\s*(["'])""")
_BOUNDARY = re.compile(r"""\\.|["']""", re.S)


@dataclass(frozen=True)
class AssignmentLiteral:
    name: str
    start: int
    end: int
    value: str | None


def quoted_assignments(text: str, sensitive: Callable[[str], bool]) -> Iterator[AssignmentLiteral]:
    """Yield completed values or a blocked span for an unfinished candidate."""
    consumed = 0
    for head in _HEAD.finditer(text):
        if head.start() < consumed or not sensitive(head[1]):
            continue
        closing = next((m for m in _BOUNDARY.finditer(text, head.end()) if m.group() == head[2]), None)
        if closing is None:
            yield AssignmentLiteral(head[1], head.start(), len(text), None)
            return
        consumed = closing.end()
        yield AssignmentLiteral(head[1], head.start(), consumed, text[head.end() : closing.start()])


class AssignmentLiterals:
    """Sorted disjoint spans; overlap checks never rescan the whole catalog."""

    def __init__(self, text: str, sensitive: Callable[[str], bool]) -> None:
        self.items = tuple(quoted_assignments(text, sensitive)) if '"' in text or "'" in text else ()
        self.ends = tuple(item.end for item in self.items)

    def overlap(self, start: int, end: int) -> AssignmentLiteral | None:
        index = bisect_right(self.ends, start)
        if index < len(self.items) and self.items[index].start < end:
            return self.items[index]
        return None
