"""Bounded Python-style display of native composite Map keys."""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from typing import Any

from ....discovery_containers import DiskMapping, DiskSequence
from ....discovery_values import DiskBackedText


class _RenderedKey(DiskBackedText):
    def __init__(self, identity: str) -> None:
        super().__init__()
        self._native_key_identity = identity


def _repr_parts(value: Any, deadline: float | None) -> Iterator[str]:
    def check() -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("discover_time")

    check()
    if isinstance(value, DiskBackedText):
        single = double = False
        for part in value.iter_text_chunks():
            check()
            single |= "'" in part
            double |= '"' in part
        quote = '"' if single and not double else "'"
        yield quote
        for part in value.iter_text_chunks():
            check()
            shown = repr(part)
            body = shown[1:-1]
            if quote == "'" and shown[0] == '"':
                body = body.replace("'", "\\'")
            yield body
        yield quote
    elif isinstance(value, DiskMapping):
        yield "{"
        owner = value.reference_owner
        rows = owner.execute(
            "SELECT key_node,child FROM edges WHERE parent=? ORDER BY ordinal", (value.reference_locator[0],)
        )
        for index, (key, child) in enumerate(rows):
            if index:
                yield ", "
            yield from _repr_parts(owner.view(key), deadline)
            yield ": "
            yield from _repr_parts(owner.view(child), deadline)
        yield "}"
    elif isinstance(value, (DiskSequence, list, tuple)):
        tuple_value = getattr(value, "tuple_value", isinstance(value, tuple))
        yield "(" if tuple_value else "["
        for index, item in enumerate(value):
            if index:
                yield ", "
            yield from _repr_parts(item, deadline)
        if tuple_value and len(value) == 1:
            yield ","
        yield ")" if tuple_value else "]"
    elif isinstance(value, Mapping):
        yield "{"
        for index, (key, item) in enumerate(value.items()):
            if index:
                yield ", "
            yield from _repr_parts(key, deadline)
            yield ": "
            yield from _repr_parts(item, deadline)
        yield "}"
    else:
        yield repr(value)


def rendered_native_key(value: Any, identity: str, deadline: float | None = None) -> DiskBackedText:
    result = _RenderedKey(identity)
    try:
        for part in _repr_parts(value, deadline):
            result.append_text(part)
        result.finish()
        # Public mapping lookup can use the returned display key without
        # confusing a rendered tuple/map with a literal String key.
        return result
    except BaseException:
        result.close()
        raise
