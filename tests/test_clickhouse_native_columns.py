from __future__ import annotations

import copy
import datetime as dt
import decimal
import io
import struct
import tracemalloc
from types import SimpleNamespace
from uuid import UUID

import pytest
from clickhouse_driver.block import BlockInfo, ColumnOrientedBlock
from clickhouse_driver.streams.native import BlockInputStream, BlockOutputStream

from redposture_core.modules.clickhouse.discover.reader import read_chunk
from tests.test_clickhouse_native_stream import _session, _varint, _Wire


class _Writer(io.BytesIO):
    def write_strings(self, values, encoding=None):
        for value in values:
            data = value.encode(encoding) if encoding and isinstance(value, str) else value
            self.write(_varint(len(data)) + data)

    def write_fixed_strings(self, values, length, encoding=None):
        for value in values:
            data = value.encode(encoding) if encoding and isinstance(value, str) else value
            if len(data) > length:
                raise ValueError("fixture FixedString too long")
            self.write(data.ljust(length, b"\0"))


def _wire_for(tmp_path, spec, values, *, revision=0, settings=None):
    path = tmp_path / "wire"
    path.touch()
    wire = _Wire(path)
    session = _session(wire)
    session.client.connection.context.server_info = SimpleNamespace(used_revision=revision, get_timezone=lambda: "UTC")
    if settings is not None:
        session.client.connection.context.settings = settings
    output = _Writer()
    block = ColumnOrientedBlock([("payload", spec)], [copy.deepcopy(values)])
    BlockOutputStream(output, session.client.connection.context).write(block)
    wire.file.close()
    path.write_bytes(output.getvalue())
    wire = _Wire(path)
    stream = BlockInputStream(wire, session.client.connection.context)
    session.client.connection.block_in = stream
    session.client.execute_iter = lambda query: iter(stream.read().get_rows())
    return wire, session


def test_native_map_repeated_wire_key_keeps_every_completed_value(tmp_path):
    from redposture_core.data_discovery import _scan_portioned_value

    wire, session = _wire_for(
        tmp_path, "Map(String,String)", [{"password": "first-secret", "passw0rd": "second-secret"}]
    )
    path = tmp_path / "wire"
    path.write_bytes(path.read_bytes().replace(b"passw0rd", b"password"))
    result = read_chunk(session, "select payload")
    assert result.error is None
    mapping = result.rows[0][0]
    matches, _, complete = _scan_portioned_value(mapping, "$", 65536)
    assert complete
    assert {(match.detector, match.value) for match in matches} == {
        ("password", "first-secret"),
        ("password", "second-secret"),
    }
    assert mapping["password"] == "second-secret"
    wire.file.close()


@pytest.mark.parametrize(
    ("spec", "values"),
    [
        ("String", ["", "plain", "λ𐐷\n\0tail"]),
        ("FixedString(8)", ["", "abc", "a\0b"]),
        ("Nullable(String)", [None, "", "a", None, "λ"]),
        ("Array(String)", [[], ["a", "b"], ["λ"]]),
        ("Array(Array(String))", [[], [[], ["a", "b"], []], [["λ"]]]),
        ("Array(Nullable(String))", [[None, "", "a", None], []]),
        ("Map(String,String)", [{"password": "first", "note": "ordinary"}, {}]),
        ("Map(String,Array(Nullable(String)))", [{"a": [None, "b"], "c": []}, {}]),
        ("Map(UInt8, String)", [{1: "a", 2: "b"}, {}]),
        ("Map(Tuple(label String, id UInt8), String)", [{("a", 1): "value"}]),
        ("Tuple(String, UInt64)", [("a", 8), ("b", 2**63)]),
        ("Array(Tuple(String, Nullable(Int32)))", [[("a", None), ("b", -7)], []]),
        ("Array(Map(String,Tuple(String, Date)))", [[{"a": ("b", dt.date(2026, 10, 28))}]]),
        ("LowCardinality(String)", ["a", "", "a", "b"]),
        ("LowCardinality(Nullable(String))", [None, "a", "", None, "b"]),
        ("Array(LowCardinality(Nullable(String)))", [[None, "a", "a", "b"], []]),
        ("Tuple(String, UUID, Decimal(9, 2))", [("a", UUID(int=123), decimal.Decimal("12.25"))]),
        ("Tuple(String, DateTime)", [("a", dt.datetime(2026, 10, 28, 12, 0, 0))]),
        ("Tuple(String, Enum8('one'=1, 'two'=2))", [("a", "one"), ("b", "two")]),
    ],
)
def test_native_composed_types_match_sdk_decoding(tmp_path, spec, values):
    wire, session = _wire_for(tmp_path, spec, values)
    try:
        expected = session.client.connection.block_in.read().get_rows()
        wire.file.seek(0)
        result = read_chunk(session, "SELECT payload")
        assert result.error is None
        assert result.rows == [list(row) for row in expected]
    finally:
        wire.file.close()


def test_native_named_tuple_matches_sdk_object_setting(tmp_path):
    wire, session = _wire_for(
        tmp_path,
        "Tuple(password String, retries UInt32)",
        [("secret", 3)],
        settings={"allow_experimental_object_type": True},
    )
    try:
        expected = session.client.connection.block_in.read().get_rows()
        wire.file.seek(0)
        result = read_chunk(session, "SELECT payload")
        assert result.error is None
        assert result.rows == [list(row) for row in expected]
    finally:
        wire.file.close()


def _sparse_wire(tmp_path, *, truncated=False):
    from clickhouse_driver import defines

    revision = defines.DBMS_MIN_REVISION_WITH_CUSTOM_SERIALIZATION
    output = _Writer()
    BlockInfo().write(output)
    output.write(b"\x01\x05\x07payload\x06String\x01\x01")
    output.write(_varint(1) + _varint(2) + _varint(1 << 62))
    output.write(b"\x05first")
    output.write(b"\x06last" if truncated else b"\x06second")
    path = tmp_path / "wire"
    path.write_bytes(output.getvalue())
    wire = _Wire(path)
    session = _session(wire)
    session.client.connection.context.server_info = SimpleNamespace(used_revision=revision, get_timezone=lambda: "UTC")
    return wire, session


def test_native_sparse_string_has_exact_default_positions(tmp_path):
    wire, session = _sparse_wire(tmp_path)
    try:
        result = read_chunk(session, "SELECT payload")
        assert result.error is None
        assert result.rows == [[""], ["first"], [""], [""], ["second"]]
    finally:
        wire.file.close()


def test_native_sparse_partial_preserves_positions_of_completed_rows(tmp_path):
    wire, session = _sparse_wire(tmp_path, truncated=True)
    try:
        result = read_chunk(session, "SELECT payload")
        assert result.error and "truncated" in result.error
        assert result.rows == [[""], ["first"], [""], [""]]
    finally:
        wire.file.close()


def test_native_truncated_map_keys_are_not_exposed_as_values(tmp_path):
    spec = "Map(String,String)"
    path = tmp_path / "wire"
    path.write_bytes(
        b"\x01\x01\x07payload"
        + _varint(len(spec))
        + spec.encode()
        + struct.pack("<Q", 2)
        + b"\x08password"
        + _varint(1000)
        + b"incomplete"
    )
    wire = _Wire(path)
    try:
        result = read_chunk(_session(wire), "SELECT payload")
        assert result.error and not result.rows
    finally:
        wire.file.close()


@pytest.mark.parametrize("kind", ["Nullable(String)", "Array(String)"])
def test_medium_strings_in_composed_native_column_are_bounded(tmp_path, kind):
    count, size = 1000, 50000
    value = b"Ab7/" * (size // 4)
    path = tmp_path / "wire"
    with path.open("wb") as out:
        rows = count if kind.startswith("Nullable") else 1
        out.write(b"\x01" + _varint(rows) + b"\x07payload" + _varint(len(kind)) + kind.encode())
        out.write(b"\0" * count if kind.startswith("Nullable") else struct.pack("<Q", count))
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
    assert len(result.rows) == rows
    assert peak < 8_000_000


def test_completed_first_row_survives_truncation_inside_one_native_block(tmp_path):
    path = tmp_path / "wire"
    with path.open("wb") as out:
        out.write(b"\x01\x02\x07payload\x06String")
        first = b"password=first-complete"
        out.write(_varint(len(first)) + first)
        out.write(_varint(1000000) + b"incomplete")
    wire = _Wire(path)
    try:
        result = read_chunk(_session(wire), "SELECT payload")
        assert result.error and "truncated" in result.error
        assert result.rows == [["password=first-complete"]]
    finally:
        wire.file.close()


@pytest.mark.parametrize(
    ("spec", "value"),
    [
        ("Decimal(38, 2)", decimal.Decimal("123456789012345678901234567890.12")),
        ("Decimal(76, 8)", decimal.Decimal("1234567890" * 6 + "12345678.12345678")),
    ],
)
def test_native_atomic_decoder_preserves_full_decimal_context(tmp_path, spec, value):
    wire, session = _wire_for(tmp_path, f"Tuple(String, {spec})", [("context", value)])
    try:
        expected = session.client.connection.block_in.read().get_rows()
        wire.file.seek(0)
        result = read_chunk(session, "SELECT payload")
        assert result.error is None
        assert result.rows == [list(row) for row in expected]
    finally:
        wire.file.close()


def test_native_tuple_map_keys_keep_sdk_values(tmp_path):
    wire, session = _wire_for(tmp_path, "Map(Tuple(String, UInt8), String)", [{("a", 1): "value"}])
    try:
        expected = session.client.connection.block_in.read().get_rows()
        wire.file.seek(0)
        result = read_chunk(session, "SELECT payload")
        assert result.error is None
        assert list(result.rows[0][0].items()) == list(expected[0][0].items())
    finally:
        wire.file.close()


@pytest.mark.parametrize(
    ("spec", "values"),
    [
        ("Array(String)", [["one"], ["two"]]),
        ("Map(String,String)", [{"a": "one"}, {"a": "two"}]),
        ("Tuple(String, UInt8)", [("one", 1), ("two", 2)]),
    ],
)
def test_native_storage_error_during_row_reconstruction_keeps_first_row(tmp_path, monkeypatch, spec, values):
    from redposture_core.discovery_containers import DiskContainer
    from redposture_core.modules.clickhouse.discover.native_values import NativeValues

    wire, session = _wire_for(tmp_path, spec, values)
    original = NativeValues.append
    failed = False

    def append(self, parent, child):
        nonlocal failed
        if not failed and isinstance(self.view(child), DiskContainer) and self.stats(parent)[0] == 1:
            failed = True
            raise OSError("tree write failed")
        return original(self, parent, child)

    monkeypatch.setattr(NativeValues, "append", append)
    try:
        result = read_chunk(session, "SELECT payload")
        assert result.error == "tree write failed"
        assert result.rows == [[values[0]]]
    finally:
        wire.file.close()


def test_native_array_reconstruction_checks_deadline_inside_one_row(tmp_path, monkeypatch):
    from redposture_core.modules.clickhouse.discover.native_stream import _StringBuffer
    from redposture_core.modules.clickhouse.discover.native_values import NativeValues

    wire, session = _wire_for(tmp_path, "Array(String)", [["value"] * 100])
    original = NativeValues.append
    expired = False
    appended = 0

    def append(self, parent, child):
        nonlocal expired, appended
        # Only the assembly of the first array row copies string nodes into
        # a fresh sequence. The decoded leaf column has count100 already.
        if isinstance(self.view(child), str) and self.stats(parent)[0] < 100:
            appended += 1
            if appended == 110:
                expired = True
        return original(self, parent, child)

    original_check = _StringBuffer._check

    def check(self):
        if expired:
            raise TimeoutError("discover_time")
        return original_check(self)

    monkeypatch.setattr(NativeValues, "append", append)
    monkeypatch.setattr(_StringBuffer, "_check", check)
    try:
        result = read_chunk(session, "SELECT payload")
        assert result.error == "discover_time"
        assert appended < 200
    finally:
        wire.file.close()


def test_native_sparse_map_consumes_groups_before_offsets(tmp_path):
    from clickhouse_driver import defines

    revision = defines.DBMS_MIN_REVISION_WITH_CUSTOM_SERIALIZATION
    spec = "Map(String, String)"
    output = _Writer()
    BlockInfo().write(output)
    output.write(b"\x01\x05\x07payload" + _varint(len(spec)) + spec.encode() + b"\x01\x01\x00\x00")
    output.write(_varint(1) + _varint((1 << 62) | 3))
    output.write(struct.pack("<Q", 1) + b"\x08password\x06secret")
    path = tmp_path / "wire"
    path.write_bytes(output.getvalue())
    wire = _Wire(path)
    session = _session(wire)
    session.client.connection.context.server_info = SimpleNamespace(used_revision=revision)
    try:
        expected = session.client.connection.block_in.read().get_rows()
        wire.file.seek(0)
        result = read_chunk(session, "SELECT payload")
        assert result.error is None
        assert result.rows == [list(row) for row in expected]
    finally:
        wire.file.close()


def test_native_deadline_keeps_completed_row_buffered_before_timeout(tmp_path, monkeypatch):
    from redposture_core.modules.clickhouse.discover import native_stream, reader

    clock = [0.0]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0])
    monkeypatch.setattr(native_stream, "time", fake_time)
    monkeypatch.setattr(reader, "time", fake_time)
    path = tmp_path / "wire"
    first = b"password=first-complete"
    path.write_bytes(b"\x01\x02\x07payload\x06String" + _varint(len(first)) + first + _varint(200000) + b"x" * 200000)
    wire = _Wire(path)
    original = wire.read

    def read(size):
        part = original(size)
        if size >= 65536:
            clock[0] = 2.0
        return part

    monkeypatch.setattr(wire, "read", read)
    try:
        result = read_chunk(_session(wire), "SELECT payload", deadline=1.0)
        assert result.error == "discover_time"
        assert result.rows == [["password=first-complete"]]
    finally:
        wire.file.close()


def test_native_wide_row_does_not_materialize_every_cell_in_ram(tmp_path):
    import tracemalloc

    path = tmp_path / "wire"
    count = 400
    value = b"Ab7/" * 12500
    with path.open("wb") as out:
        out.write(_varint(count) + b"\x01")
        for i in range(count):
            name = f"payload{i}".encode()
            out.write(_varint(len(name)) + name + b"\x06String" + _varint(len(value)) + value)
    wire = _Wire(path)
    session = _session(wire)
    tracemalloc.start()
    try:
        result = read_chunk(session, "SELECT many_columns")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        wire.file.close()
    assert result.error is None
    assert result.bytes_read == count * len(value)
    assert len(result.rows[0]) == count
    assert result.rows[0][0] == result.rows[0][-1] == value.decode()
    assert peak < 8_000_000


def test_native_deadline_recovery_is_lazy_for_large_buffered_prefix(tmp_path, monkeypatch):
    from redposture_core.discovery_spool import SpoolingValues
    from redposture_core.modules.clickhouse.discover import native_stream, reader

    clock = [0.0]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0])
    monkeypatch.setattr(native_stream, "time", fake_time)
    monkeypatch.setattr(reader, "time", fake_time)
    count = 1000
    path = tmp_path / "wire"
    with path.open("wb") as out:
        out.write(b"\x01" + _varint(count) + b"\x07payload\x06String")
        for i in range(count):
            value = f"record-{i:04d}".encode()
            out.write(_varint(len(value)) + value)
    wire = _Wire(path)
    session = _session(wire)
    original_read = wire.read
    decoded = 0

    def read(size):
        nonlocal decoded
        part = original_read(size)
        if size == 11:
            decoded += 1
            if decoded == count:
                clock[0] = 2.0
        return part

    monkeypatch.setattr(wire, "read", read)
    original_append = SpoolingValues.append
    inserted = 0

    def append(self, value):
        nonlocal inserted
        inserted += 1
        return original_append(self, value)

    monkeypatch.setattr(SpoolingValues, "append", append)
    try:
        result = read_chunk(session, "SELECT payload", deadline=1.0)
        assert result.error == "discover_time"
        assert len(result.rows) == count - 1
        assert result.rows[0] == ["record-0000"]
        assert inserted <= 1
    finally:
        wire.file.close()


def test_native_object_json_retains_field_names_without_experimental_client_setting(tmp_path):
    from redposture_core.data_discovery import _scan_portioned_value

    kind = "Object('json')"
    schema = "Tuple(password String, nested Tuple(token String))"
    payload = b"\0" + _varint(len(schema)) + schema.encode()
    for value in (b"object-secret", b"token-payload"):
        payload += _varint(len(value)) + value
    path = tmp_path / "wire"
    path.write_bytes(b"\x01\x01\x07payload" + _varint(len(kind)) + kind.encode() + payload)
    wire = _Wire(path)
    try:
        result = read_chunk(_session(wire), "SELECT payload")
        assert result.error is None
        matches, _, complete = _scan_portioned_value(result.rows[0][0], "$", 65536)
        assert complete
        assert {(m.detector, m.value, m.object_path) for m in matches} == {
            ("password", "object-secret", "$.password"),
            ("generic_secret", "token-payload", "$.nested.token"),
        }
    finally:
        wire.file.close()


def test_native_named_tuple_wire_used_for_real_object_keeps_fields(tmp_path):
    from redposture_core.data_discovery import _scan_portioned_value

    schema = "Tuple(nested Tuple(token String), password String)"
    wire, session = _wire_for(tmp_path, schema, [(("token-payload",), "object-secret")])
    try:
        result = read_chunk(session, "SELECT payload")
        assert result.error is None
        matches, _, complete = _scan_portioned_value(result.rows[0][0], "$", 65536)
        assert complete
        assert {(m.detector, m.value, m.object_path) for m in matches} == {
            ("password", "object-secret", "$.password"),
            ("generic_secret", "token-payload", "$.nested.token"),
        }
    finally:
        wire.file.close()
