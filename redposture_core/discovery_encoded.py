"""Decode complete structured text blobs without retaining expanded data in RAM."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import time
import zlib
from typing import TYPE_CHECKING, NamedTuple

from .discovery_values import DiskBackedText
from .secret_detection import _ASSIGNMENT_RE, _SQL_PASSWORD_RE

if TYPE_CHECKING:
    from zlib import _Decompress

_SPACE = re.compile(r"[ \t\r\n\f\v]+")
_ALPHABETS = {"hex": re.compile(r"[0-9a-fA-F]*"), "base64": re.compile(r"[A-Za-z0-9_+/=-]*")}


class DecodedBlob(NamedTuple):
    text: DiskBackedText
    layers: int
    structured: bool


def compressed_text_prefix(text: str | bytes) -> bool:
    for position in range(0, len(text), 4096):
        prefix = text[position : position + 4096].lstrip()
        if prefix:
            if isinstance(prefix, bytes):
                return prefix.startswith(b"H4sI") or prefix[:6].lower() == b"1f8b08"
            return prefix.startswith("H4sI") or prefix[:6].lower() == "1f8b08"
    return False


def encoded_text_prefix(text: str | bytes) -> bool:
    prefix = text[:4096]
    if isinstance(prefix, bytes):
        return re.fullmatch(rb"[A-Za-z0-9_+/=\-\s]{16,}", prefix) is not None
    return re.fullmatch(r"[A-Za-z0-9_+/=\-\s]{16,}", prefix, flags=re.ASCII) is not None


def mime_text_prefix(text: str | bytes) -> bool:
    prefix = text[:4096]
    lines = prefix.splitlines()
    return len(lines) > 1 and len(lines[0]) in {64, 76} and encoded_text_prefix(prefix)


class _TextWriter:
    def __init__(self, value: DiskBackedText, deadline: float | None, *, allow_gzip: bool = True) -> None:
        self.value = value
        self.deadline = deadline
        self.allow_gzip = allow_gzip
        self.decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self.prefix = b""
        self.started = False
        self.gzip: _Decompress | None = None

    def feed(self, raw: bytes) -> None:
        if not self.started:
            needed = 2 - len(self.prefix)
            self.prefix += raw[:needed]
            raw = raw[needed:]
            # Prefix detection never buffers a whole decoded input portion.
            if len(self.prefix) < 2:
                return
            raw = self.prefix + raw
            self.started = True
            self.gzip = (
                zlib.decompressobj(16 + zlib.MAX_WBITS) if self.allow_gzip and self.prefix == b"\x1f\x8b" else None
            )
            self.prefix = b""
        if self.gzip is None:
            self.value.append_text(self.decoder.decode(raw))
            return
        pending = raw
        while pending:
            _check_deadline(self.deadline)
            if self.gzip.eof:
                self.gzip = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decoded = self.gzip.decompress(pending, 65_536)
            self.value.append_text(self.decoder.decode(decoded))
            pending = self.gzip.unconsumed_tail or self.gzip.unused_data

    def finish(self) -> None:
        if not self.started:
            self.value.append_text(self.decoder.decode(self.prefix))
        if self.gzip is not None and not self.gzip.eof:
            raise ValueError("incomplete gzip blob")
        self.value.append_text(self.decoder.decode(b"", final=True))
        self.value.finish()


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("discover_time")


def _decode_once(
    source: DiskBackedText, encoding: str, deadline: float | None, *, allow_gzip: bool = True
) -> DiskBackedText | None:
    value = DiskBackedText()
    writer = _TextWriter(value, deadline, allow_gzip=allow_gzip)
    pending = ""
    padded = False
    total = 0
    try:
        for chunk in source.iter_text_chunks():
            _check_deadline(deadline)
            text = _SPACE.sub("", chunk)
            if not text:
                continue
            if padded or _ALPHABETS[encoding].fullmatch(text) is None:
                raise ValueError("invalid encoded alphabet")
            total += len(text)
            pending += text
            if encoding == "hex":
                count = len(pending) // 2 * 2
                writer.feed(bytes.fromhex(pending[:count]))
                pending = pending[count:]
            else:
                count = len(pending) // 4 * 4
                if count:
                    block, pending = pending[:count], pending[count:]
                    padded = "=" in block
                    writer.feed(base64.b64decode(block, altchars=b"-_", validate=True))
                    if padded and pending:
                        raise ValueError("data after base64 padding")
        if total < 16:
            raise ValueError("not an encoded blob")
        if pending:
            if encoding == "hex" or padded:
                raise ValueError("incomplete encoded unit")
            writer.feed(base64.b64decode(pending + "=" * (-len(pending) % 4), altchars=b"-_", validate=True))
        writer.finish()
        return value
    except (ValueError, UnicodeError, binascii.Error, zlib.error):
        value.close()
        return None
    except BaseException:
        value.close()
        raise


def _structured(value: DiskBackedText, deadline: float | None) -> bool:
    tail = ""
    first = True
    for chunk in value.iter_text_chunks():
        _check_deadline(deadline)
        if first:
            head = chunk.lstrip()
            if head:
                first = False
                if head.startswith(("{", "[", "<")):
                    return True
        text = tail + chunk
        if _ASSIGNMENT_RE.search(text) or _SQL_PASSWORD_RE.search(text):
            return True
        tail = text[-512:]
    return False


def decode_disk_base64_utf8(value: DiskBackedText, *, deadline: float | None = None) -> DiskBackedText | None:
    """Decode a protocol Base64 value once, without hex or gzip interpretation."""
    return _decode_once(value, "base64", deadline, allow_gzip=False)


def _textual(value: DiskBackedText, deadline: float | None) -> bool:
    for chunk in value.iter_text_chunks():
        _check_deadline(deadline)
        if not chunk.isprintable() and any(not char.isprintable() and not char.isspace() for char in chunk):
            return False
    return True


def decode_disk_structured_blob(
    value: DiskBackedText, *, layers: int = 2, deadline: float | None = None
) -> DecodedBlob | None:
    """Return complete UTF-8 text; random decoded binary is never inspected."""
    source = value
    owned: DiskBackedText | None = None
    owned_layers = 0
    try:
        for depth in range(layers):
            decoded = _decode_once(source, "hex", deadline) or _decode_once(source, "base64", deadline)
            if decoded is None:
                break
            if owned is not None:
                owned.close()
            owned = decoded
            owned_layers = depth + 1
            if _structured(decoded, deadline):
                owned = None
                return DecodedBlob(decoded, depth + 1, True)
            source = decoded
        if owned is not None and _textual(owned, deadline):
            decoded, owned = owned, None
            return DecodedBlob(decoded, owned_layers, False)
        return None
    finally:
        if owned is not None:
            owned.close()
