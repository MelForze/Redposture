"""Disk-backed decompression of Kafka record batches during discovery."""

from __future__ import annotations

import gzip
import importlib
import struct
from typing import Any

from .discovery_bytes import SpoolBytes


class CompressedBatchError(ValueError):
    """Compressed Kafka batch is missing, corrupt or uses an unavailable codec."""


def _read_exact(source: Any, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = source.read(length - len(result))
        if not chunk:
            raise CompressedBatchError("incomplete compressed batch")
        result.extend(chunk)
    return bytes(result)


def _snappy_block(block: SpoolBytes) -> SpoolBytes:
    stream = block.reader()
    expected = 0
    shift = 0
    while True:
        byte = _read_exact(stream, 1)[0]
        expected |= (byte & 127) << shift
        if byte < 128:
            break
        shift += 7
        if shift > 35:
            raise CompressedBatchError("invalid Snappy size")
    output = SpoolBytes()
    while len(output) < expected:
        tag = _read_exact(stream, 1)[0]
        kind = tag & 3
        if kind == 0:
            length = tag >> 2
            if length < 60:
                length += 1
            else:
                width = length - 59
                length = int.from_bytes(_read_exact(stream, width), "little") + 1
            if length > expected - len(output):
                raise CompressedBatchError("Snappy literal exceeds declared size")
            for _ in range(0, length, 65536):
                output.write(_read_exact(stream, min(65536, length - _)))
            continue
        if kind == 1:
            length = ((tag >> 2) & 7) + 4
            offset = ((tag & 0xE0) << 3) | _read_exact(stream, 1)[0]
        else:
            length = (tag >> 2) + 1
            offset = int.from_bytes(_read_exact(stream, 2 if kind == 2 else 4), "little")
        if offset <= 0 or offset > len(output) or length > expected - len(output):
            raise CompressedBatchError("invalid Snappy back reference")
        remaining = length
        while remaining:
            count = min(remaining, offset, 65536)
            segment = output[len(output) - offset : len(output) - offset + count]
            assert isinstance(segment, bytes)
            output.write(segment)
            remaining -= count
    if stream.read(1):
        raise CompressedBatchError("trailing Snappy data")
    return output


def _snappy(payload: SpoolBytes) -> SpoolBytes:
    source = payload.reader()
    prefix = source.read(8)
    output = SpoolBytes()
    if prefix != b"\x82SNAPPY\x00":
        source.seek(0)
        return _snappy_block(payload)
    _read_exact(source, 8)  # version and compatible version
    while source.tell() < len(payload):
        length = struct.unpack(">i", _read_exact(source, 4))[0]
        if length <= 0 or length > len(payload) - source.tell():
            raise CompressedBatchError("invalid xerial Snappy chunk size")
        part = payload[source.tell() : source.tell() + length]
        assert isinstance(part, SpoolBytes) or isinstance(part, bytes)
        if isinstance(part, bytes):
            wrapped = SpoolBytes()
            wrapped.write(part)
            part = wrapped
        for chunk in _snappy_block(part).iter_chunks():
            output.write(chunk)
        source.seek(source.tell() + length)
    return output


def decompress(codec: int, payload: SpoolBytes) -> SpoolBytes:
    """Read 64-KiB output portions; an incomplete frame is an error."""
    if codec == 2:
        return _snappy(payload)
    try:
        source = payload.reader()
        if codec == 1:
            reader = gzip.GzipFile(fileobj=source, mode="rb")
        elif codec == 3:
            reader = importlib.import_module("lz4.frame").open(source, mode="rb")
        elif codec == 4:
            reader = importlib.import_module("zstandard").ZstdDecompressor().stream_reader(source)
        else:
            raise CompressedBatchError(f"unsupported Kafka compression codec {codec}")
        output = SpoolBytes()
        with reader:
            while chunk := reader.read(65536):
                output.write(chunk)
        if codec == 4:
            # zstandard's stream_reader accepts a truncated final frame as EOF.
            # Verify frame termination in a second pass with a tiny compressed
            # input chunk, keeping each decompressed block bounded in RAM.
            verifier = importlib.import_module("zstandard").ZstdDecompressor().decompressobj()
            for compressed in payload.iter_chunks(64):
                verifier.decompress(compressed)
            if not verifier.eof or verifier.unused_data:
                raise CompressedBatchError("incomplete Kafka zstd frame")
        return output
    except ModuleNotFoundError as exc:
        raise CompressedBatchError(f"Kafka codec {codec} requires an optional package") from exc
    except CompressedBatchError:
        raise
    except Exception as exc:
        raise CompressedBatchError(f"invalid Kafka compressed batch: {exc}") from exc
