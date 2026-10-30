"""Bounded validation used by Elastic's own long-value detector policy."""

from __future__ import annotations

import base64
import math
import re
import time
from array import array
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from functools import cmp_to_key
from itertools import zip_longest
from typing import Any, SupportsIndex, TypeVar, overload

from ...discovery_encoded import decode_disk_base64_utf8
from ...discovery_spool import SpoolingRecords, _slice_values
from ...discovery_text import _Value
from ...discovery_values import DiskBackedText, iter_json_chunks
from ...json_stream import JSONPath, JSONScalarStream

_URLSAFE = re.compile(r"[A-Za-z0-9_-]*")


def _check(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("max_seconds")


class _JSONPart:
    def __init__(self) -> None:
        self.length = 0
        self.pending = ""
        self.failed = False
        self.string_fields: set[str] = set()
        self.parser = JSONScalarStream(self._string, on_primitive=self._primitive, on_container=self._container)

    def _string(self, path: JSONPath, _text: str, final: bool) -> None:
        if final and path in {("alg",), ("enc",)}:
            self.string_fields.add(str(path[0]))

    def _primitive(self, item: tuple[JSONPath, Any]) -> None:
        path, _value = item
        if path in {("alg",), ("enc",)}:
            self.string_fields.discard(str(path[0]))

    def _container(self, path: JSONPath, _kind: str) -> None:
        if path in {("alg",), ("enc",)}:
            self.string_fields.discard(str(path[0]))

    def feed(self, part: str) -> None:
        self.length += len(part)
        if self.failed:
            return
        try:
            self.pending += part
            end = len(self.pending) // 4 * 4
            if end:
                self.parser.feed(base64.b64decode(self.pending[:end], altchars=b"-_", validate=True))
                self.pending = self.pending[end:]
        except (ValueError, UnicodeError):
            self.failed = True
            self.pending = ""

    def finish(self) -> bool:
        if self.failed:
            return False
        try:
            if self.pending:
                self.parser.feed(
                    base64.b64decode(self.pending + "=" * (-len(self.pending) % 4), altchars=b"-_", validate=True)
                )
            self.parser.finish()
            return self.parser.root_kind == "object"
        except (ValueError, UnicodeError):
            return False


def validated_disk_jose(value: DiskBackedText, *, deadline: float | None = None) -> str | None:
    """Apply Elastic's JWT/JWE structure checks without decoding a whole payload."""
    lengths = [0]
    header, payload = _JSONPart(), _JSONPart()
    for chunk in value.iter_text_chunks():
        _check(deadline)
        pieces = chunk.split(".")
        for offset, part in enumerate(pieces):
            if offset:
                lengths.append(0)
                if len(lengths) > 5:
                    return None
            if _URLSAFE.fullmatch(part) is None:
                return None
            index = len(lengths) - 1
            lengths[index] += len(part)
            if index == 0:
                header.feed(part)
            elif index == 1:
                payload.feed(part)
    if not header.finish() or "alg" not in header.string_fields:
        return None
    if len(lengths) == 3 and min(lengths) >= 8 and payload.finish():
        return "jwt"
    if len(lengths) == 5 and "enc" in header.string_fields and min(lengths[i] for i in (0, 2, 3, 4)) >= 8:
        return "jwe"
    return None


def disk_entropy(value: DiskBackedText, *, deadline: float | None = None) -> tuple[float, int]:
    """Exact Unicode histogram with a fixed <9 MB footprint, independent of size."""
    counts = array("Q", [0]) * 0x110000
    length = 0
    classes = [False] * 4
    for chunk in value.iter_text_chunks():
        _check(deadline)
        length += len(chunk)
        for character, count in Counter(chunk).items():
            counts[ord(character)] += count
        for index, pattern in enumerate((r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")):
            classes[index] |= re.search(pattern, chunk) is not None
    entropy = -sum((count / length) * math.log2(count / length) for count in counts if count) if length else 0.0
    return entropy, sum(classes)


def disk_basic_password(value: DiskBackedText, *, deadline: float | None = None) -> str | DiskBackedText | None:
    decoded = decode_disk_base64_utf8(value, deadline=deadline)
    if decoded is None:
        return None
    username = ""
    seen_colon = False
    password = _Value(65_536)
    try:
        for part in decoded.iter_text_chunks():
            _check(deadline)
            if "\r" in part or "\n" in part:
                return None
            if not seen_colon:
                before, separator, after = part.partition(":")
                username += before
                if len(username) > 256:
                    return None
                if not separator:
                    continue
                if re.fullmatch(r"[A-Za-z0-9_.@\\/+-]{1,256}", username) is None:
                    return None
                seen_colon = True
                part = after
            password.append(part)
        return password.finish() if seen_colon and password.length else None
    finally:
        decoded.close()
        password.close()


def stable_json_chunks(value: Any) -> Iterator[str]:
    """Match sort_keys/default=str JSON hashing without large string copies."""
    if isinstance(value, Mapping):
        yield "{"

        def compare(left: Any, right: Any) -> int:
            def characters(item: Any) -> Iterator[str]:
                if isinstance(item, DiskBackedText):
                    for chunk in item.iter_text_chunks():
                        yield from chunk
                else:
                    yield from str(item)

            for a, b in zip_longest(characters(left), characters(right)):
                if a != b:
                    return -1 if a is None or (b is not None and a < b) else 1
            return 0

        keys = (
            sorted(value, key=cmp_to_key(compare))
            if any(isinstance(key, DiskBackedText) for key in value)
            else sorted(value)
        )
        for offset, key in enumerate(keys):
            if offset:
                yield ", "
            if isinstance(key, (str, DiskBackedText)):
                encoded_key = key
            elif key is None:
                encoded_key = "null"
            elif isinstance(key, bool):
                encoded_key = "true" if key else "false"
            elif isinstance(key, (int, float)):
                encoded_key = str(key)
            else:
                raise TypeError("invalid JSON mapping key")
            yield from iter_json_chunks(encoded_key)
            yield ": "
            yield from stable_json_chunks(value[key])
        yield "}"
    elif isinstance(value, (list, tuple)):
        yield "["
        for offset, child in enumerate(value):
            if offset:
                yield ", "
            yield from stable_json_chunks(child)
        yield "]"
    else:
        scalar = value if value is None or isinstance(value, (str, int, float, bool, DiskBackedText)) else str(value)
        yield from iter_json_chunks(scalar)


_Item = TypeVar("_Item")


class SpoolingSequence(list[_Item]):
    """Mutable ordered dataclass values, spilling before count or payload grows."""

    def __init__(
        self,
        *,
        encode: Callable[[_Item], dict[str, Any]],
        decode: Callable[[Mapping[str, Any]], _Item],
        estimate: Callable[[_Item], int],
    ) -> None:
        super().__init__()
        self._encode = encode
        self._decode = decode
        self._estimate = estimate
        self._memory: list[_Item] = []
        self._records: SpoolingRecords | None = None
        self._count = 0
        self._bytes = 0
        self.incomplete_reason: str | None = None

    def append(self, value: _Item) -> None:
        size = self._estimate(value)
        if self._records is None and (self._count >= 1024 or self._bytes + size > 1024 * 1024):
            records = SpoolingRecords()
            for previous in self._memory:
                records.append(self._encode(previous))
            self._records = records
            self._memory.clear()
            self._bytes = 0
        if self._records is not None:
            self._records.append(self._encode(value))
        else:
            self._memory.append(value)
            self._bytes += size
        self._count += 1

    def extend(self, values: Iterable[_Item]) -> None:
        for value in values:
            self.append(value)

    def __iter__(self) -> Iterator[_Item]:
        if self._records is None:
            yield from self._memory
        else:
            # Discovery may inspect current values and append more afterwards.
            for record in self._records.iter_appended(0):
                yield self._decode(record)

    def __len__(self) -> int:
        return self._count

    def __contains__(self, value: object) -> bool:
        return any(item == value for item in self)

    def copy(self) -> list[_Item]:
        return list(self)

    def __reversed__(self) -> Iterator[_Item]:
        if self._records is None:
            yield from reversed(self._memory)
        else:
            for record in self._records.iter_appended(0, reverse=True):
                yield self._decode(record)

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> _Item: ...

    @overload
    def __getitem__(self, index: slice, /) -> list[_Item]: ...

    def __getitem__(self, index: SupportsIndex | slice, /) -> _Item | list[_Item]:
        if self._records is None:
            return self._memory[index]
        if isinstance(index, slice):
            return _slice_values(self, index)
        return self._decode(self._records[index])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(a == b for a, b in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __repr__(self) -> str:
        return f"SpoolingSequence(count={self._count})"
