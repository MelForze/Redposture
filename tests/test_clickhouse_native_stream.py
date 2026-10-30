"""Read actual SDK native blocks without its eager whole-String decoder."""

from __future__ import annotations

import hashlib
import struct
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest
from clickhouse_driver import Client
from clickhouse_driver.streams.native import BlockInputStream

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.clickhouse.discover import native_stream
from redposture_core.modules.clickhouse.discover.reader import read_chunk


def _varint(value: int) -> bytes:
    data = bytearray()
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return bytes(data)


class _Wire:
    """File-backed SDK buffer interface; record requested read sizes."""

    def __init__(self, path: Path) -> None:
        self.file = path.open("rb")
        self.largest = 0

    def read(self, size: int) -> bytes:
        self.largest = max(self.largest, size)
        part = self.file.read(size)
        if len(part) != size:
            raise EOFError("truncated native block")
        return part

    def read_one(self) -> int:
        return self.read(1)[0]

    def read_strings(self, n: int, encoding: str | None = None) -> tuple:
        from clickhouse_driver.varint import read_varint

        parts = [self.read(read_varint(self)) for _ in range(n)]
        return tuple(self._decoded(part, encoding) for part in parts)

    @staticmethod
    def _decoded(part: bytes, encoding: str | None):
        try:
            return part.decode(encoding) if encoding else part
        except UnicodeDecodeError:
            return part

    def read_fixed_strings(self, n: int, length: int, encoding: str | None = None) -> tuple:
        parts = [self.read(length).rstrip(b"\0") for _ in range(n)]
        return tuple(self._decoded(part, encoding) for part in parts)


def _block(path: Path, data: bytes, *, spec: str = "String", total: int | None = None) -> _Wire:
    with path.open("wb") as out:
        out.write(b"\x01\x01\x07payload" + _varint(len(spec)) + spec.encode())
        if spec == "String":
            out.write(_varint(len(data) if total is None else total))
        out.write(data)
    return _Wire(path)


def _session(wire: _Wire):
    client = Client("unused")
    client.connection.context.server_info = SimpleNamespace(used_revision=0)
    stream = BlockInputStream(wire, client.connection.context)
    client.connection.block_in = stream
    client.execute_iter = lambda query: iter(stream.read().get_rows())
    return SimpleNamespace(protocol="native", client=client)


def test_native_large_string_is_spooled_before_sdk_decoding(tmp_path: Path) -> None:
    source = ("Aa7-λ/" * 1_500_000).encode()
    expected = hashlib.sha256(source).hexdigest()
    wire = _block(tmp_path / "wire", source)
    del source
    session = _session(wire)
    tracemalloc.start()
    try:
        result = read_chunk(session, "SELECT payload", deadline=time.monotonic() + 20)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        wire.file.close()
    assert result.error is None
    value = result.rows[0][0]
    assert isinstance(value, DiskBackedText)
    assert value.digest == expected
    assert wire.largest <= 65_536
    assert peak < 4_000_000


@pytest.mark.parametrize("data", [b"", b"small", "λ\n\0end".encode(), b"A\xffB"])
def test_native_string_preserves_legacy_small_values(tmp_path: Path, data: bytes) -> None:
    wire = _block(tmp_path / "wire", data)
    try:
        result = read_chunk(_session(wire), "SELECT payload")
        assert result.error is None
        assert result.rows == [[data.decode("utf-8", errors="replace")]]
    finally:
        wire.file.close()


def test_native_truncated_string_is_not_reported_as_complete(tmp_path: Path) -> None:
    wire = _block(tmp_path / "wire", b"password=partial", total=1_000_000)
    try:
        result = read_chunk(_session(wire), "SELECT payload")
        assert not result.rows
        assert result.error and "truncated" in result.error
    finally:
        wire.file.close()


def test_native_fixed_string_strips_only_trailing_nuls(tmp_path: Path) -> None:
    data = (b"Ab7\0" * 25_000) + b"\0" * 200_000
    expected = hashlib.sha256(data.rstrip(b"\0")).hexdigest()
    wire = _block(tmp_path / "wire", data, spec=f"FixedString({len(data)})")
    try:
        result = read_chunk(_session(wire), "SELECT payload")
        assert result.error is None
        value = result.rows[0][0]
        assert isinstance(value, DiskBackedText)
        assert value.digest == expected
        assert wire.largest <= 65_536
    finally:
        wire.file.close()


def test_native_reader_restores_sdk_buffer_after_discovery(tmp_path: Path) -> None:
    wire = _block(tmp_path / "wire", b"small")
    session = _session(wire)
    original = session.client.connection.get_block_in_stream
    try:
        result = read_chunk(session, "SELECT payload")
        assert result.error is None
        assert session.client.connection.block_in.fin is wire
        assert session.client.connection.get_block_in_stream == original
    finally:
        wire.file.close()


@pytest.mark.parametrize("spec", ["Nullable(String)", "Array(String)", "Map(String,String)"])
def test_native_nested_string_retains_sdk_type_and_complete_value(tmp_path: Path, spec: str) -> None:
    value = ("Ab7-λ/" * 100_000).encode()
    encoded = _varint(len(value)) + value
    if spec.startswith("Nullable"):
        payload = b"\0" + encoded
    elif spec.startswith("Array"):
        payload = struct.pack("<Q", 1) + encoded
    else:
        payload = struct.pack("<Q", 1) + b"\x08password" + encoded
    wire = _block(tmp_path / "wire", payload, spec=spec)
    try:
        result = read_chunk(_session(wire), "SELECT payload")
        assert result.error is None
        found = result.rows[0][0]
        if spec.startswith("Array"):
            found = found[0]
        elif spec.startswith("Map"):
            found = found["password"]
        assert isinstance(found, DiskBackedText)
        assert found.digest == hashlib.sha256(value).hexdigest()
        assert wire.largest <= 65_536
    finally:
        wire.file.close()


def test_native_incomplete_next_block_preserves_finished_row(tmp_path: Path) -> None:
    path = tmp_path / "wire"
    wire = _block(path, b"password=first-complete")
    broken = tmp_path / "broken"
    tail = _block(broken, b"incomplete", total=1_000_000)
    tail.file.close()
    with path.open("ab") as out:
        out.write(broken.read_bytes())
    session = _session(wire)
    stream = session.client.connection.block_in

    def blocks(query):
        for _ in range(2):
            yield from stream.read().get_rows()

    session.client.execute_iter = blocks
    try:
        result = read_chunk(session, "SELECT payload")
        assert result.rows == [["password=first-complete"]]
        assert result.error and "truncated" in result.error
        assert stream.fin is wire
    finally:
        wire.file.close()


@pytest.mark.parametrize("failure", [OSError("disk full"), KeyboardInterrupt()])
def test_native_failed_scalar_closes_temporary_value(tmp_path: Path, monkeypatch, failure) -> None:
    wire = _block(tmp_path / "wire", b"Ab7/" * 100_000)
    session = _session(wire)
    stream = session.client.connection.block_in
    values = []
    original_init = DiskBackedText.__init__

    def init(self, **kwargs):
        original_init(self, **kwargs)
        values.append(self)

    def fail(self, text):
        raise failure

    monkeypatch.setattr(DiskBackedText, "__init__", init)
    monkeypatch.setattr(DiskBackedText, "append_text", fail)
    try:
        if isinstance(failure, KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                read_chunk(session, "SELECT payload")
        else:
            result = read_chunk(session, "SELECT payload")
            assert not result.rows and result.error == "disk full"
        assert values and all(not value.path.exists() for value in values)
        assert stream.fin is wire
    finally:
        wire.file.close()


def test_native_deadline_is_checked_between_string_portions(tmp_path: Path, monkeypatch) -> None:
    wire = _block(tmp_path / "wire", b"Ab7/" * 100_000)
    session = _session(wire)
    original = wire.read
    calls = 0

    def read(size):
        nonlocal calls
        if size > 100:
            calls += 1
        return original(size)

    monkeypatch.setattr(wire, "read", read)
    # Expire only after three body portions, independent of CPU timing.
    original_check = native_stream._StringBuffer._check

    def check(self):
        if calls >= 3:
            raise TimeoutError("discover_time")
        return original_check(self)

    monkeypatch.setattr(native_stream._StringBuffer, "_check", check)
    try:
        result = read_chunk(session, "SELECT payload")
        assert not result.rows
        assert result.error == "discover_time"
        assert calls == 3
    finally:
        wire.file.close()


def test_native_many_medium_strings_do_not_accumulate_sdk_block_in_ram(tmp_path: Path) -> None:
    path = tmp_path / "wire"
    count = 1000
    value = b"Ab7/" * 12_500
    with path.open("wb") as out:
        out.write(b"\x01" + _varint(count) + b"\x07payload\x06String")
        for _ in range(count):
            out.write(_varint(len(value)) + value)
    wire = _Wire(path)
    session = _session(wire)
    tracemalloc.start()
    try:
        result = read_chunk(session, "SELECT payload")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        wire.file.close()
    assert result.error is None
    assert len(result.rows) == count
    assert result.rows[0] == result.rows[-1] == [value.decode()]
    assert result.bytes_read == len(value) * count
    assert peak < 8_000_000


def test_native_spooled_nullable_low_cardinality_dictionary_uses_sdk_null_index(tmp_path: Path) -> None:
    dictionary = [b""] + [f"value-{i}".encode() for i in range(99)]
    payload = struct.pack("<QQQ", 1, 1536, len(dictionary))
    payload += b"".join(_varint(len(value)) + value for value in dictionary)
    payload += struct.pack("<Q", 1) + b"\x63"
    wire = _block(tmp_path / "wire", payload, spec="LowCardinality(Nullable(String))")
    try:
        result = read_chunk(_session(wire), "SELECT payload")
        assert result.error is None
        assert result.rows == [["value-98"]]
    finally:
        wire.file.close()


def test_native_spooled_bytes_column_preserves_reader_normalization(tmp_path: Path) -> None:
    path = tmp_path / "wire"
    count = 100
    value = b"A\xffB"
    with path.open("wb") as out:
        out.write(b"\x01" + _varint(count) + b"\x07payload\x06String")
        out.write((_varint(len(value)) + value) * count)
    wire = _Wire(path)
    session = _session(wire)
    session.client.connection.context.client_settings = {**session.client.client_settings, "strings_as_bytes": True}
    try:
        result = read_chunk(session, "SELECT payload")
        assert result.error is None
        assert len(result.rows) == count
        assert result.rows[0] == result.rows[-1] == ["A\ufffdB"]
    finally:
        wire.file.close()
