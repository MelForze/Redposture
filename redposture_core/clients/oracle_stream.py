"""Bounded native LONG fields before python-oracledb's TTC coalescing.

The Oracle Thin namespace alone gets socket/SSL delegates. Authentication and
ordinary operations retain their original transport; only an explicitly armed
single-LONG fetch replaces its known TTC field with an owned disk-value marker.
Wire structures follow python-oracledb 3.4.2 impl/thin/{packet,messages/base}.pyx.
"""

from __future__ import annotations

import codecs
import hashlib
import importlib
import tempfile
import threading
import time
import uuid
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, BinaryIO

from ..discovery_text import _Value
from ..discovery_values import DiskBackedText

_BYTES_REPR_ESCAPES = tuple(
    "\\\\"
    if byte == 92
    else "\\t"
    if byte == 9
    else "\\n"
    if byte == 10
    else "\\r"
    if byte == 13
    else chr(byte)
    if 32 <= byte <= 126
    else f"\\x{byte:02x}"
    for byte in range(256)
)


class LongStreamError(OSError):
    """A native response cannot be verified without eager materialization."""


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("discover_time")


class StreamedLongValue:
    """An independently owned, complete native field; raw bytes stay exact."""

    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-oracle-long-")
        self.path = Path(self._temporary.name) / "value.bin"
        self._writer = self.path.open("wb")
        self._hash = hashlib.sha256()
        self.byte_length = 0
        self._finished = self._closed = False
        self._single_quote = self._double_quote = False
        self._text: str | DiskBackedText | None = None

    @property
    def digest(self) -> str:
        return self._hash.hexdigest()

    def write(self, piece: bytes) -> None:
        if self._finished or self._closed:
            raise LongStreamError("native LONG value is finished")
        self._writer.write(piece)
        self._hash.update(piece)
        self.byte_length += len(piece)
        self._single_quote |= b"'" in piece
        self._double_quote |= b'"' in piece

    def finish(self) -> None:
        self._writer.close()
        self._finished = True

    def iter_bytes(self, *, max_bytes: int = 65536) -> Iterator[bytes]:
        if not self._finished or self._closed:
            raise LongStreamError("native LONG value is incomplete or closed")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        with self.path.open("rb") as reader:
            while piece := reader.read(min(max_bytes, 65536)):
                yield piece

    def text(self, *, binary: bool, deadline: float | None) -> str | DiskBackedText:
        if self._text is not None:
            return self._text
        scalar = _Value(65536)
        try:
            if binary:
                # Match str(bytes), the existing RAW json_safe contract. CPython
                # selects double quotes only when that avoids single-quote
                # escapes. Record this while writing, then render bounded chunks.
                quote = '"' if self._single_quote and not self._double_quote else "'"
                escapes = list(_BYTES_REPR_ESCAPES)
                escapes[ord(quote)] = "\\" + quote
                scalar.append("b" + quote)
                for piece in self.iter_bytes():
                    _check_deadline(deadline)
                    scalar.append("".join(escapes[byte] for byte in piece))
                scalar.append(quote)
            else:
                decoder = codecs.getincrementaldecoder("utf-8")("strict")
                for piece in self.iter_bytes():
                    _check_deadline(deadline)
                    scalar.append(decoder.decode(piece))
                scalar.append(decoder.decode(b"", final=True))
            self._text = scalar.finish()
            return self._text
        finally:
            scalar.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._writer.close()
        finally:
            self._temporary.cleanup()

    def __del__(self) -> None:
        if not getattr(self, "_closed", True):
            self.close()


class _PayloadReader:
    def __init__(self, raw: Any, deadline: float | None, sdu: int) -> None:
        self.raw = raw
        self.deadline = deadline
        self.sdu = sdu
        self.remaining = 0
        self.header = b""
        self.flags = 0
        self.capture = True
        self.saved = tempfile.SpooledTemporaryFile(max_size=65536)

    def exact(self, amount: int) -> bytes:
        parts = []
        while amount:
            _check_deadline(self.deadline)
            request = min(amount, 65536)
            previous = self.raw.gettimeout() if hasattr(self.raw, "gettimeout") else None
            if self.deadline is not None:
                remaining = max(0.001, self.deadline - time.monotonic())
                self.raw.settimeout(min(previous, remaining) if previous is not None else remaining)
            try:
                part = self.raw.recv(request)
            finally:
                if self.deadline is not None:
                    self.raw.settimeout(previous)
            if not part or len(part) > request:
                raise LongStreamError("truncated native LONG response")
            parts.append(part)
            amount -= len(part)
        return b"".join(parts)

    def next_packet(self) -> None:
        header = self.exact(8)
        # Thin ConnectMessage switches to full32-bit lengths after ACCEPT.
        size = int.from_bytes(header[:4], "big")
        if not 10 <= size <= self.sdu or header[4] != 6 or header[6:8] != b"\0\0":
            raise LongStreamError("unsupported Oracle LONG packet layout")
        self.header = header
        self.flags = int.from_bytes(self.exact(2), "big")
        self.remaining = size - 10

    def read(self, amount: int) -> bytes:
        if not 0 <= amount <= 65536:
            raise LongStreamError("invalid native LONG read portion")
        parts = []
        while amount:
            if not self.remaining:
                self.next_packet()
            length = min(amount, self.remaining)
            parts.append(self.exact(length))
            self.remaining -= length
            amount -= length
        piece = b"".join(parts)
        if self.capture:
            self.saved.write(piece)
        return piece

    def byte(self) -> int:
        return self.read(1)[0]

    def integer(self, maximum: int = 4, *, signed: bool = False) -> int:
        width = self.byte()
        negative = bool(width & 128)
        width &= 127
        if width > maximum or negative and not signed:
            raise LongStreamError("invalid native LONG integer encoding")
        value = int.from_bytes(self.read(width), "big") if width else 0
        return -value if negative else value

    def variable(self, emit: Callable[[bytes], None] | None = None) -> bool:
        marker = self.byte()
        if marker in (0, 255):
            return False
        if marker == 254:
            while amount := self.integer():
                while amount:
                    piece = self.read(min(65536, amount))
                    if emit is not None:
                        emit(piece)
                    amount -= len(piece)
        else:
            piece = self.read(marker)
            if emit is not None:
                emit(piece)
        return True

    def response(self) -> BinaryIO:
        # Save only the unread current packet. The raw socket is then exactly
        # aligned at the next TNS header and needs no further TTC interpretation.
        while self.remaining:
            self.read(min(self.remaining, 65536))
        output = tempfile.TemporaryFile()
        try:
            length = self.saved.tell()
            self.saved.seek(0)
            capacity = min(self.sdu - 10, 65526)
            offset = 0
            while piece := self.saved.read(capacity):
                offset += len(piece)
                header = bytearray(self.header)
                header[:4] = (len(piece) + 10).to_bytes(4, "big")
                output.write(header)
                output.write((self.flags if offset == length else 0).to_bytes(2, "big"))
                output.write(piece)
            output.seek(0)
            return output
        except BaseException:
            output.close()
            raise

    def close(self) -> None:
        self.saved.close()


class LongFetch:
    """One cursor's last field cache, independent of each fetch's packet state."""

    def __init__(
        self,
        *,
        deadline: float | None = None,
        scalar_prefix: int = 0,
        sdu: int = 8192,
        column_count: int | None = None,
    ) -> None:
        self.deadline = deadline
        self.scalar_prefix = scalar_prefix
        self.sdu = sdu
        self.column_count = column_count if column_count is not None else scalar_prefix + 1
        self.current_value: StreamedLongValue | None = None
        self._pending: StreamedLongValue | None = None
        self._marker: str | None = None
        self._output: BinaryIO | None = None
        self._done = False

    def begin_fetch(self) -> None:
        if self._output is not None:
            self._output.close()
            self._output = None
        self._done = False

    def _transform(self, raw: Any) -> None:
        reader = _PayloadReader(raw, self.deadline, self.sdu)
        vector: int | None = None
        vector_bytes = (self.column_count + 7) // 8
        try:
            while True:
                opcode = reader.byte()
                if opcode == 6:
                    reader.byte()
                    reader.integer(2)
                    reader.integer()
                    reader.integer()
                    reader.integer(2)
                    amount = reader.integer()
                    if amount:
                        reader.byte()
                        if amount < vector_bytes:
                            raise LongStreamError("incomplete native LONG column bit vector")
                        # A table/query can have ordinary columns after LONG;
                        # their mask bytes are preserved for the SDK as well.
                        bits = reader.read(amount)
                        vector = int.from_bytes(bits, "little")
                    if reader.integer():
                        reader.variable()
                elif opcode == 21:
                    reader.integer(2)
                    vector = int.from_bytes(reader.read(vector_bytes), "little")
                elif opcode == 33:
                    reader.integer(8)
                elif opcode == 9:
                    reader.integer()
                    reader.integer(2)
                elif opcode == 4:
                    break
                elif opcode == 7:
                    for index in range(self.scalar_prefix):
                        if vector is None or vector & (1 << index):
                            reader.variable()
                    if vector is not None and not vector & (1 << self.scalar_prefix):
                        if self._marker is None:
                            raise LongStreamError("compressed LONG has no verified previous value")
                        break
                    reader.capture = False
                    # Keep nulls native, and never construct an owner from an
                    # unfinished prefix. Non-null values get one small marker.
                    marker = reader.byte()
                    if marker in (0, 255):
                        replacement = bytes([marker])
                    else:
                        value = self._pending = StreamedLongValue()
                        if marker == 254:
                            while amount := reader.integer():
                                while amount:
                                    piece = reader.read(min(65536, amount))
                                    value.write(piece)
                                    amount -= len(piece)
                        else:
                            value.write(reader.read(marker))
                        token = "rp-long-" + uuid.uuid4().hex
                        encoded = token.encode("ascii")
                        replacement = bytes([len(encoded)]) + encoded
                    reader.capture = True
                    reader.saved.write(replacement)
                    null_indicator = reader.integer(signed=True)
                    return_code = reader.integer()
                    if self._pending is not None:
                        if null_indicator or return_code:
                            raise LongStreamError("unverified native LONG trailer")
                        self._pending.finish()
                        self.current_value = self._pending
                        self._pending = None
                        self._marker = token
                    break
                else:
                    raise LongStreamError(f"unsupported Oracle LONG response opcode {opcode}")
            self._output = reader.response()
            self._done = True
        finally:
            reader.close()

    def recv(self, raw: Any, amount: int, flags: int = 0) -> bytes:
        try:
            _check_deadline(self.deadline)
            if flags:
                raise LongStreamError("flagged native LONG recv is unsupported")
            if amount == 0:
                return b""
            if not self._done:
                self._transform(raw)
            if self._output is not None:
                piece = self._output.read(min(amount, 65536))
                if piece:
                    return piece
                self._output.close()
                self._output = None
            return raw.recv(amount)
        except BaseException:
            try:
                raw.close()
            finally:
                if self._pending is not None:
                    self._pending.close()
                    self._pending = None
                self.current_value = None
                self.close()
            raise

    def convert(self, marker: Any) -> StreamedLongValue | None:
        if marker is None:
            return None
        if isinstance(marker, bytes):
            marker = marker.decode("ascii")
        if marker != self._marker or self.current_value is None:
            raise LongStreamError("native LONG marker was not verified")
        return self.current_value

    def close(self) -> None:
        if self._output is not None:
            self._output.close()
            self._output = None
        if self._pending is not None:
            self._pending.close()
            self._pending = None
        # Returned owners hold their own leases, independently of cursor state.
        self.current_value = None
        self._marker = None


class ConnectionStreams:
    def __init__(self) -> None:
        self.transport: _TrackedSocket | None = None
        self.broken = False

    @contextmanager
    def reading(self, fetch: LongFetch) -> Iterator[None]:
        if self.transport is None:
            raise LongStreamError("untracked Oracle LONG transport")
        fetch.begin_fetch()
        token = _READING.set((self, fetch))
        try:
            yield
        finally:
            _READING.reset(token)


_CONNECTING: ContextVar[ConnectionStreams | None] = ContextVar("oracle_stream_connect", default=None)
_READING: ContextVar[tuple[ConnectionStreams, LongFetch] | None] = ContextVar("oracle_stream_fetch", default=None)
_CONNECTIONS: weakref.WeakKeyDictionary[Any, ConnectionStreams] = weakref.WeakKeyDictionary()
_HOOK_LOCK = threading.RLock()


@contextmanager
def connecting() -> Iterator[ConnectionStreams]:
    state = ConnectionStreams()
    token = _CONNECTING.set(state)
    try:
        yield state
    finally:
        _CONNECTING.reset(token)


def connection_state(connection: Any) -> ConnectionStreams | None:
    try:
        with _HOOK_LOCK:
            return _CONNECTIONS.get(connection)
    except TypeError:
        return None


class _TrackedSocket:
    def __init__(self, raw: Any, state: ConnectionStreams) -> None:
        self._raw, self._state = raw, state
        state.transport = self

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)

    def recv(self, amount: int, flags: int = 0) -> bytes:
        active = _READING.get()
        fetch = active[1] if active is not None and active[0] is self._state else None
        try:
            return fetch.recv(self._raw, amount, flags) if fetch is not None else self._raw.recv(amount, flags)
        except BaseException:
            if fetch is not None:
                self._state.broken = True
            raise

    def close(self) -> None:
        self._state.broken = True
        self._raw.close()

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        active = _READING.get()
        if active is None or active[0] is not self._state:
            return self._raw.recv_into(buffer, nbytes, flags)
        piece = self.recv(min(nbytes or len(buffer), len(buffer)), flags)
        buffer[: len(piece)] = piece
        return len(piece)


def _track(raw: Any) -> Any:
    state = _CONNECTING.get()
    return _TrackedSocket(raw, state) if state is not None else raw


class _SocketNamespace:
    def __init__(self, original: Any) -> None:
        self._original = original

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)

    def socket(self, *args: Any, **kwargs: Any) -> Any:
        return _track(self._original.socket(*args, **kwargs))

    def create_connection(self, *args: Any, **kwargs: Any) -> Any:
        return _track(self._original.create_connection(*args, **kwargs))


class _SSLContext:
    def __init__(self, original: Any) -> None:
        object.__setattr__(self, "_original", original)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._original, name, value)

    def wrap_socket(self, sock: Any, *args: Any, **kwargs: Any) -> Any:
        state = sock._state if isinstance(sock, _TrackedSocket) else _CONNECTING.get()
        raw = sock._raw if isinstance(sock, _TrackedSocket) else sock
        wrapped = self._original.wrap_socket(raw, *args, **kwargs)
        return _TrackedSocket(wrapped, state) if state is not None else wrapped


class _SSLNamespace:
    def __init__(self, original: Any) -> None:
        self._original = original

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)

    def create_default_context(self, *args: Any, **kwargs: Any) -> Any:
        context = self._original.create_default_context(*args, **kwargs)
        return _SSLContext(context) if _CONNECTING.get() is not None else context


def install_driver_hooks(driver: Any) -> bool:
    thin = getattr(driver, "thin_impl", None)
    if thin is None and getattr(driver, "__name__", None) == "oracledb":
        thin = importlib.import_module("oracledb.thin_impl")
    if thin is None or not hasattr(thin, "socket") or not hasattr(thin, "ssl"):
        return False
    with _HOOK_LOCK:
        if not isinstance(thin.socket, _SocketNamespace):
            thin.socket = _SocketNamespace(thin.socket)
        if not isinstance(thin.ssl, _SSLNamespace):
            thin.ssl = _SSLNamespace(thin.ssl)
    return True


def connect_tracked(driver: Any, **kwargs: Any) -> Any:
    if not install_driver_hooks(driver):
        return driver.connect(**kwargs)
    with connecting() as state:
        connection = driver.connect(**kwargs)
        try:
            with _HOOK_LOCK:
                _CONNECTIONS[connection] = state
        except TypeError:
            # Compatibility doubles and externally supplied connections remain
            # usable; LONG discovery alone requires an associated transport.
            pass
        return connection
