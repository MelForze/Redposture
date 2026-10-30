"""Scope bounded native String and row decoding to one SDK connection.

The native driver's String column delegates to its input buffer. Wrapping
that buffer keeps SDK type/null/tuple/array decoding and binary framing intact,
but moves a completed long scalar to disk before the SDK can allocate it whole.
"""

from __future__ import annotations

import codecs
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from ....discovery_text import _Value
from ....discovery_values import DiskBackedText
from .native_columns import NativeBlock, NativeReadState, read_block
from .native_values import NativeValues

_PORTION = 65_536


class _StringBuffer:
    def __init__(self, source: Any, deadline: float | None) -> None:
        self.source = source
        self.deadline = deadline

    def __getattr__(self, name: str) -> Any:
        return getattr(self.source, name)

    def _check(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError("discover_time")

    def _value(self, size: int, encoding: str | None, *, fixed: bool = False) -> str | bytes | DiskBackedText:
        value = _Value(_PORTION)
        decoder = codecs.getincrementaldecoder(encoding or "utf-8")("replace")
        pending_nuls = 0
        try:
            while size:
                self._check()
                part = self.source.read(min(_PORTION, size))
                if not part:
                    raise EOFError("truncated native String")
                size -= len(part)
                if fixed:
                    stripped = part.rstrip(b"\0")
                    if stripped:
                        while pending_nuls:
                            amount = min(pending_nuls, _PORTION)
                            value.append(decoder.decode(b"\0" * amount))
                            pending_nuls -= amount
                        value.append(decoder.decode(stripped))
                        pending_nuls = len(part) - len(stripped)
                    else:
                        pending_nuls += len(part)
                else:
                    value.append(decoder.decode(part))
            value.append(decoder.decode(b"", final=True))
            self._check()
            result = value.finish()
            # Preserve SDK bytes mode for small values. The discovery reader
            # normalizes bytes to UTF-8; long values are already disk-backed.
            if encoding is None and isinstance(result, str):
                return result.encode("utf-8")
            return result
        finally:
            value.close()


@contextmanager
def native_streaming_strings(client: Any, deadline: float | None) -> Iterator[NativeReadState | None]:
    """Wrap existing/reconnected SDK streams for this discovery query only."""
    try:
        from clickhouse_driver.connection import Connection
    except ImportError:
        yield None
        return
    connection = getattr(client, "connection", None)
    if not isinstance(connection, Connection):
        yield None
        return
    previous = connection.get_block_in_stream
    owned_attribute = "get_block_in_stream" in vars(connection)
    wrapped: list[tuple[Any, Any, Any, bool]] = []
    owner: NativeValues | None = None
    state = NativeReadState()

    def wrap(stream: Any) -> Any:
        if stream is not None and not isinstance(stream.fin, _StringBuffer):
            source = stream.fin
            stream.fin = _StringBuffer(source, deadline)
            original_read = stream.read
            owned_read = "read" in vars(stream)

            def read(*args: Any, **kwargs: Any) -> NativeBlock:
                nonlocal owner
                if owner is None:
                    owner = NativeValues(deadline)
                block = read_block(stream, owner)
                block.read_state = state
                state.remaining = block.num_rows
                state.buffered = block.row_view()
                return block

            stream.read = read
            wrapped.append((stream, source, original_read, owned_read))
        return stream

    def factory() -> Any:
        return wrap(previous())

    connection.get_block_in_stream = factory
    wrap(connection.block_in)
    try:
        yield state
    finally:
        for stream, source, original_read, owned_read in wrapped:
            stream.fin = source
            if owned_read:
                stream.read = original_read
            else:
                del stream.read
        if owned_attribute:
            connection.get_block_in_stream = previous
        else:
            del connection.get_block_in_stream
