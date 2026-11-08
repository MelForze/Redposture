"""Full discovery paths composed from disk-backed names without copying them."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from urllib.parse import quote

from .discovery_values import DiskBackedText

Text = str | DiskBackedText
_AMBIGUOUS_KEY = re.compile(r"[.\[\]\"'\\*\x00-\x20]")


def literal_field_component(key: str) -> str:
    """Unambiguous component for an already materialized small-tree path."""
    return "[" + json.dumps(key, ensure_ascii=False) + "]" if _AMBIGUOUS_KEY.search(key) else "." + key


def _bytes(value: Text) -> int:
    if isinstance(value, DiskBackedText):
        return value.byte_length
    return sum(len(value[i : i + 65536].encode("utf-8")) for i in range(0, len(value), 65536))


@dataclass(frozen=True)
class _Span:
    value: Text
    skip_chars: int = 0
    skip_bytes: int = 0


class DiskBackedPath(DiskBackedText):
    """Immutable path view. Components retain their independent text leases."""

    def __init__(self, parts: tuple[_Span, ...]) -> None:
        self._parts = parts
        self.byte_length = sum(_bytes(part.value) - part.skip_bytes for part in parts)
        self._finished, self._closed = True, False
        self._materialized: DiskBackedText | None = None
        self._digest: str | None = None
        self._all_x = self._all_star = self._all_dash = self._uniform = False
        self._has_nonspace, self._uniform_char = True, None

    def spool_components(self) -> Iterator[tuple[Text, int, int]]:
        """Expose immutable composition without materializing its full text."""
        self._readable()
        for part in self._parts:
            yield part.value, part.skip_chars, part.skip_bytes

    @classmethod
    def from_spool_components(cls, parts: Iterator[tuple[Text, int, int]]) -> DiskBackedPath:
        return cls(tuple(_Span(value, skip_chars, skip_bytes) for value, skip_chars, skip_bytes in parts))

    def iter_text_chunks(self, *, max_chars: int = 65536) -> Iterator[str]:
        self._readable()
        if max_chars <= 0:
            raise ValueError("max_chars must be positive")
        for part in self._parts:
            value = part.value
            chunks = (
                value.iter_text_chunks(max_chars=max_chars)
                if isinstance(value, DiskBackedText)
                else (value[i : i + max_chars] for i in range(0, len(value), max_chars))
            )
            skip = part.skip_chars
            for chunk in chunks:
                if skip:
                    amount = min(skip, len(chunk))
                    chunk, skip = chunk[amount:], skip - amount
                if chunk:
                    yield chunk

    @property
    def digest(self) -> str:
        self._readable()
        if self._digest is None:
            digest = sha256()
            for part in self.iter_text_chunks():
                digest.update(part.encode("utf-8"))
            self._digest = digest.hexdigest()
        return self._digest

    @property
    def path(self) -> Any:  # type: ignore[override]  # Immutable view; materialize only on demand.
        self._readable()
        if self._materialized is None:
            value = DiskBackedText()
            try:
                for part in self.iter_text_chunks():
                    value.append_text(part)
                value.finish()
                self._materialized = value
            except BaseException:
                value.close()
                raise
        return self._materialized.path

    def close(self) -> None:
        self._closed = True
        if self._materialized is not None:
            self._materialized.close()
        self._parts = ()

    def __eq__(self, other: object) -> bool:
        # Paths are immutable views, not str subclasses. Content comparison
        # between paths keeps repeated locations stable; JSON resume converts
        # its disk-backed path scalars back to these views before aggregation.
        if not isinstance(other, DiskBackedPath):
            return NotImplemented
        return self.byte_length == other.byte_length and self.digest == other.digest

    def __hash__(self) -> int:
        return hash((self.byte_length, self.digest))


def concat_discovery_text(*parts: Text) -> Text:
    strings = [part for part in parts if isinstance(part, str)]
    if len(strings) == len(parts) and sum(len(part) for part in strings) <= 65536:
        return "".join(strings)
    return DiskBackedPath(tuple(_Span(part) for part in parts))


def path_suffix(path: Text, prefix: str) -> Text:
    if isinstance(path, str):
        if not path.startswith(prefix):
            raise ValueError("discovery path lost its relative prefix")
        return path[len(prefix) :]
    seen = ""
    for chunk in path.iter_text_chunks(max_chars=max(1, len(prefix))):
        seen += chunk[: len(prefix) - len(seen)]
        if len(seen) >= len(prefix):
            break
    if seen != prefix:
        raise ValueError("discovery path lost its relative prefix")
    return DiskBackedPath((_Span(path, len(prefix), len(prefix.encode("utf-8"))),))


def escape_discovery_text(value: Text, style: str) -> Text:
    """Escape one complete component in bounded portions, retaining its spelling."""

    def escape(text: str) -> str:
        if style == "pointer":
            return text.replace("~", "~0").replace("/", "~1")
        if style == "url":
            return quote(text, safe="")
        return text

    if isinstance(value, str) or style == "dot":
        return escape(value) if isinstance(value, str) else value
    result = DiskBackedText()
    try:
        for chunk in value.iter_text_chunks():
            result.append_text(escape(chunk))
        result.finish()
        return result
    except BaseException:
        result.close()
        raise


def json_discovery_path(parts: tuple[Any, ...], source: Text = "$", *, style: str = "dot") -> Text:
    """Build an exact JSON location without stringifying disk-backed keys."""
    output: list[Text] = [source]
    for part in parts:
        if style == "dot":
            if isinstance(part, int):
                output.append(f"[{part}]")
            elif isinstance(part, str):
                output.append(literal_field_component(part))
            elif any(_AMBIGUOUS_KEY.search(chunk) for chunk in part.iter_text_chunks()):
                quoted = DiskBackedText()
                try:
                    for chunk in part.iter_json_chunks():
                        quoted.append_text(chunk)
                    quoted.finish()
                except BaseException:
                    quoted.close()
                    raise
                output.extend(("[", quoted, "]"))
            else:
                output.extend((".", part))
        else:
            output.extend(("/", escape_discovery_text(str(part) if isinstance(part, int) else part, style)))
    return concat_discovery_text(*output)
