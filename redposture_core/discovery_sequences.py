"""Bounded sequences and stable JSON for product-neutral discovery results."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from functools import cmp_to_key
from itertools import zip_longest
from typing import Any, SupportsIndex, TypeVar, overload

from .discovery_spool import SpoolingRecords, _slice_values
from .discovery_values import DiskBackedText, iter_json_chunks


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
