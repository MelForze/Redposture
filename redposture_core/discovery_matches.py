"""Bounded intermediate matches before discovery collectors deduplicate/output."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from itertools import zip_longest
from typing import Any, SupportsIndex, overload

from .discovery_frontier import DiscoveryFrontier
from .discovery_spool import SpoolingRecords
from .secret_detection import SecretMatch, fingerprint


class SpoolingSecretMatches(list[SecretMatch]):
    """Append while scanning, then iterate exact ordered matches from disk."""

    def __init__(self, values: Iterable[SecretMatch] = (), *, inline_limit: int = 2048) -> None:
        super().__init__()
        self._inline_limit = max(0, inline_limit)
        self._memory: list[SecretMatch] = []
        self._records: SpoolingRecords | None = None
        self._count = 0
        self._memory_bytes = 0
        self.incomplete_reason: str | None = None
        self.extend(values)

    @staticmethod
    def _record(match: SecretMatch) -> dict[str, Any]:
        return {
            "detector": match.detector,
            "confidence": match.confidence,
            "object_path": match.object_path,
            "value": match.value,
        }

    def append(self, match: SecretMatch) -> None:
        size = match.value.__sizeof__() + match.object_path.__sizeof__() + 128
        if self._records is None and (self._count >= self._inline_limit or self._memory_bytes + size > 4 * 1024 * 1024):
            records = SpoolingRecords()
            for previous in self._memory:
                records.append(self._record(previous))
            self._memory.clear()
            self._memory_bytes = 0
            self._records = records
        if self._records is not None:
            self._records.append(self._record(match))
        else:
            self._memory.append(match)
            self._memory_bytes += size
        self._count += 1

    def extend(self, values: Iterable[SecretMatch]) -> None:
        if reason := getattr(values, "incomplete_reason", None):
            self.incomplete_reason = reason
        for value in values:
            self.append(value)

    def __iter__(self) -> Iterator[SecretMatch]:
        if self._records is None:
            yield from self._memory
        else:
            for record in self._records:
                yield SecretMatch(**record)

    def __len__(self) -> int:
        return self._count

    def __contains__(self, value: object) -> bool:
        return any(match == value for match in self)

    def copy(self) -> list[SecretMatch]:
        return list(self)

    def __reversed__(self) -> Iterator[SecretMatch]:
        if self._records is None:
            yield from reversed(self._memory)
        else:
            for record in self._records.iter_reversed():
                yield SecretMatch(**record)

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> SecretMatch: ...

    @overload
    def __getitem__(self, index: slice, /) -> list[SecretMatch]: ...

    def __getitem__(self, index: SupportsIndex | slice, /) -> SecretMatch | list[SecretMatch]:
        if self._records is None:
            return self._memory[index]
        if isinstance(index, slice):
            return [SecretMatch(**record) for record in self._records[index]]
        return SecretMatch(**self._records[index])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(left == right for left, right in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __repr__(self) -> str:
        return f"SpoolingSecretMatches(count={self._count})"


def prefer_specific_matches(matches: list[SecretMatch], *, inline_limit: int = 2048) -> list[SecretMatch]:
    """Suppress heuristic duplicates when a specific detector found the same value."""
    fallback_detectors = {"generic_secret", "high_entropy"}
    if not any(match.detector in fallback_detectors for match in matches):
        return matches
    in_memory = not isinstance(matches, SpoolingSecretMatches) or matches._records is None
    if len(matches) <= inline_limit and in_memory:
        specific = {fingerprint(match.value) for match in matches if match.detector not in fallback_detectors}
        return [
            match
            for match in matches
            if match.detector not in fallback_detectors or fingerprint(match.value) not in specific
        ]
    with DiscoveryFrontier() as specific_values:
        for match in matches:
            if match.detector not in fallback_detectors:
                specific_values.claim(fingerprint(match.value))
        return SpoolingSecretMatches(
            (
                match
                for match in matches
                if match.detector not in fallback_detectors or not specific_values.contains(fingerprint(match.value))
            ),
            inline_limit=inline_limit,
        )
