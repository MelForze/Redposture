"""Seekable temporary byte ranges for large protocol frames and records."""

from __future__ import annotations

import base64
import codecs
import tempfile
from collections.abc import Iterator
from typing import Any

from .discovery_values import DiskBackedText


class SpoolBytes:
    """Small slices materialize as bytes; large slices remain file-backed."""

    def __init__(self, file: Any | None = None, start: int = 0, length: int = 0) -> None:
        self._file = file if file is not None else tempfile.TemporaryFile()
        self._start = start
        self._length = length

    def write(self, chunk: bytes) -> None:
        if self._start or self._length != self._file.tell():
            raise ValueError("only a root spool can be extended")
        self._file.write(chunk)
        self._length += len(chunk)

    def __len__(self) -> int:
        return self._length

    def __getitem__(self, item: int | slice) -> bytes | SpoolBytes | int:
        if isinstance(item, int):
            if item < 0:
                item += self._length
            if item < 0 or item >= self._length:
                raise IndexError(item)
            self._file.seek(self._start + item)
            result = self._file.read(1)
            return result[0]
        start, end, stride = item.indices(self._length)
        if stride != 1:
            raise ValueError("protocol spool slices require step 1")
        size = max(0, end - start)
        if size > 8:
            return SpoolBytes(self._file, self._start + start, size)
        self._file.seek(self._start + start)
        return self._file.read(size)

    def iter_chunks(self, size: int = 65536) -> Iterator[bytes]:
        offset = 0
        while offset < self._length:
            self._file.seek(self._start + offset)
            chunk = self._file.read(min(size, self._length - offset))
            if not chunk:
                raise OSError("protocol spool disappeared during read")
            offset += len(chunk)
            yield chunk

    def reader(self) -> _SpoolReader:
        return _SpoolReader(self)

    def decode(self, encoding: str, errors: str = "strict") -> str | DiskBackedText:
        if self._length <= 65536:
            self._file.seek(self._start)
            return self._file.read(self._length).decode(encoding, errors=errors)
        output = DiskBackedText()
        decoder = codecs.getincrementaldecoder(encoding)(errors)
        for chunk in self.iter_chunks():
            output.append_text(decoder.decode(chunk, final=False))
        output.append_text(decoder.decode(b"", final=True))
        output.finish()
        return output

    def base64_text(self) -> DiskBackedText:
        output = DiskBackedText()
        output.append_text("base64:")
        carry = b""
        for chunk in self.iter_chunks():
            combined = carry + chunk
            count = len(combined) // 3 * 3
            output.append_text(base64.b64encode(combined[:count]).decode("ascii"))
            carry = combined[count:]
        if carry:
            output.append_text(base64.b64encode(carry).decode("ascii"))
        output.finish()
        return output


class _SpoolReader:
    def __init__(self, spool: SpoolBytes) -> None:
        self.spool = spool
        self.offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.spool) - self.offset
        count = min(size, 65536, len(self.spool) - self.offset)
        if count <= 0:
            return b""
        self.spool._file.seek(self.spool._start + self.offset)
        chunk = self.spool._file.read(count)
        self.offset += len(chunk)
        return chunk

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 2:
            offset += len(self.spool)
        elif whence == 1:
            offset += self.offset
        if offset < 0 or offset > len(self.spool):
            raise ValueError("spool seek out of range")
        self.offset = offset
        return self.offset

    def tell(self) -> int:
        return self.offset

    def __enter__(self) -> _SpoolReader:
        return self

    def __exit__(self, *_args: object) -> None:
        return None
