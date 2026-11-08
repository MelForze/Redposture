"""Completed assignment literals shared by materialized discovery scanners.

Without a declared input dialect, retain literal contents exactly. Backslashes
affect quote termination, not decoding; JSON decoding belongs to its parser.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .discovery_values import DiskBackedText

_HEAD = re.compile(r"""(?i)(?<![\w.])(?:--)?([A-Za-z][A-Za-z0-9._-]{0,127})["']?\s*(?:=>|[:=])\s*(["'])""")
_BOUNDARY = re.compile(r"""\\.|["']""", re.S)


def has_toml_assignment(text: str, sensitive: Callable[[str], bool]) -> bool:
    return any(sensitive(head[1]) and text.startswith(head[2] * 3, head.end() - 1) for head in _HEAD.finditer(text))


@dataclass(frozen=True)
class AssignmentLiteral:
    name: str
    start: int
    end: int
    value: str | DiskBackedText | None


def quoted_assignments(text: str, sensitive: Callable[[str], bool]) -> Iterator[AssignmentLiteral]:
    """Yield completed values or a blocked span for an unfinished candidate."""
    consumed = 0
    for head in _HEAD.finditer(text):
        if head.start() < consumed or not sensitive(head[1]):
            continue
        if text.startswith(head[2] * 3, head.end() - 1):
            from .discovery_toml import TOMLMultiline

            reader = TOMLMultiline(head[2], lambda _reason: None)
            try:
                start = head.end() + 2
                read = reader.feed(text[start:], final=True)
                consumed = start + read
                yield AssignmentLiteral(head[1], head.start(), consumed, reader.take())
            finally:
                reader.close()
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
