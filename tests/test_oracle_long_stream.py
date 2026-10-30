"""Python Oracle LONG streaming preserves values before SDK coalescing."""

from __future__ import annotations

import hashlib
import importlib
import socket
import ssl
import time
from types import SimpleNamespace

import pytest

from redposture_core.clients import oracle
from redposture_core.discovery_values import DiskBackedText


def _module():
    return importlib.import_module("redposture_core.clients.oracle_stream")


def _packed(value):
    if not value:
        return b"\0"
    width = (value.bit_length() + 7) // 8
    return bytes([width]) + value.to_bytes(width, "big")


_HEADER = b"\x06\x22\x01\x01\x00\x01\x01\x00\x00\x00"
_TAIL = b"\x04opaque-oer-tail\x1d"


def _frame(payload, flags=8192):
    return (len(payload) + 10).to_bytes(4, "big") + b"\x06\0\0\0" + flags.to_bytes(2, "big") + payload


def _wire(value, *, before=b"", width=997, tail=_TAIL):
    encoded = (
        b"\0"
        if value is None
        else (
            bytes([len(value)]) + value
            if len(value) < 254
            else b"\xfe" + _packed(4093) + value[:4093] + _packed(len(value) - 4093) + value[4093:] + b"\0"
        )
    )
    payload = _HEADER + b"\x07" + before + encoded + b"\0\0" + tail
    return b"".join(
        _frame(payload[i : i + width], 8192 if i + width >= len(payload) else 0) for i in range(0, len(payload), width)
    )


def _payload(wire):
    result = bytearray()
    offset = 0
    flags = []
    while offset < len(wire):
        length = int.from_bytes(wire[offset : offset + 4], "big")
        assert 10 <= length <= 8192
        flags.append(int.from_bytes(wire[offset + 8 : offset + 10], "big"))
        result.extend(wire[offset + 10 : offset + length])
        offset += length
    assert offset == len(wire)
    return bytes(result), flags


class _Socket:
    def __init__(self, wire, *, seam=13):
        self.wire = wire
        self.offset = 0
        self.seam = seam
        self.closed = False
        self.timeout = 30

    def recv(self, amount, flags=0):
        assert not self.closed
        size = min(amount, self.seam, len(self.wire) - self.offset)
        piece = self.wire[self.offset : self.offset + size]
        self.offset += size
        return piece

    def recv_into(self, buffer, nbytes=0, flags=0):
        value = self.recv(nbytes or len(buffer), flags)
        buffer[: len(value)] = value
        return len(value)

    def close(self):
        self.closed = True

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value

    def fileno(self):
        return 123


def _fetch(value, **kwargs):
    module = _module()
    fetch = module.LongFetch(deadline=time.monotonic() + 30, **kwargs)
    source = _Socket(_wire(value))
    rewritten = fetch.recv(source, 1_000_000)
    payload, flags = _payload(rewritten)
    start = len(_HEADER) + 1
    marker = payload[start + 1 : start + 1 + payload[start]]
    return fetch, source, payload, flags, marker


@pytest.mark.parametrize("value", [b"short-secret", bytes(range(256)) * 400, ("λ😀Ab0" * 17000).encode()])
def test_long_value_spools_exact_bytes_and_keeps_native_packet_tail(value):
    fetch, source, payload, flags, marker = _fetch(value)
    owner = fetch.convert(marker)
    path = owner.path
    try:
        assert owner.byte_length == len(value)
        assert owner.digest == hashlib.sha256(value).hexdigest()
        assert b"".join(owner.iter_bytes(max_bytes=17)) == value
        assert payload == _HEADER + b"\x07" + bytes([len(marker)]) + marker + b"\0\0" + _TAIL
        assert flags[-1] == 8192 and all(flag == 0 for flag in flags[:-1])
        assert source.offset == len(source.wire)
        fetch.close()
        assert path.exists(), "cursor cache teardown invalidated a transferred owner"
        assert b"".join(owner.iter_bytes()) == value
    finally:
        owner.close()
    assert not path.exists()


@pytest.mark.parametrize(
    "raw",
    [
        bytes(range(256)) * 513 + b"'\"\\",
        b"single'quote\\\t\n" * 6000,
        b'double"quote\\\r' * 6000,
        b"no-quotes\\\x00\xff" * 6000,
    ],
    ids=["all-bytes-both-quotes", "single-quote", "double-quote", "no-quotes"],
)
def test_long_raw_text_preserves_legacy_lossless_bytes_representation(raw):
    owner = _module().StreamedLongValue()
    try:
        for offset in range(0, len(raw), 17):
            owner.write(raw[offset : offset + 17])
        owner.finish()
        value = owner.text(binary=True, deadline=time.monotonic() + 30)
        rendered = "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value
        expected = oracle.json_safe(raw)
        assert rendered == expected
        assert hashlib.sha256(rendered.encode()).digest() == hashlib.sha256(expected.encode()).digest()
        assert "\ufffd" not in rendered
        assert hashlib.sha256(b"".join(owner.iter_bytes(max_bytes=31))).hexdigest() == owner.digest
        assert owner.digest == hashlib.sha256(raw).hexdigest()
    finally:
        owner.close()


def test_long_stream_stops_at_current_packet_and_preserves_next_source_packet():
    module = _module()
    following = _frame(b"ordinary-next-response")
    source = _Socket(_wire(b"known-secret") + following)
    fetch = module.LongFetch(deadline=time.monotonic() + 30)
    rewritten = fetch.recv(source, 65536)
    assert _payload(rewritten)[0].endswith(_TAIL)
    assert source.wire[source.offset :] == following
    fetch.close()


def test_long_stream_preserves_known_scalar_before_query_long():
    module = _module()
    # NUMBER's native variable-length encoding: two data bytes, independent of
    # the LONG marker. All bytes must reach the ordinary SDK decoder unchanged.
    scalar = b"\x02\xc1\x02"
    source = _Socket(_wire(b"known-secret", before=scalar))
    fetch = module.LongFetch(deadline=time.monotonic() + 30, scalar_prefix=1)
    payload, _ = _payload(fetch.recv(source, 65536))
    assert payload[:14] == _HEADER + b"\x07" + scalar
    marker_size = payload[14]
    assert fetch.convert(payload[15 : 15 + marker_size]).byte_length == 12
    fetch.close()


def test_long_null_and_pre_row_eof_are_passthrough_without_candidate():
    module = _module()
    fetch = module.LongFetch(deadline=time.monotonic() + 30)
    assert _payload(fetch.recv(_Socket(_wire(None)), 65536))[0] == _HEADER + b"\x07\0\0\0" + _TAIL
    fetch.begin_fetch()
    assert _payload(fetch.recv(_Socket(_frame(b"\x04no-rows\x1d")), 65536))[0] == b"\x04no-rows\x1d"
    fetch.close()


def test_compressed_repeat_reuses_last_owner_without_copying_value_again():
    fetch, _source, _payload_bytes, _flags, marker = _fetch(b"known-secret")
    owner = fetch.convert(marker)
    repeated_header = b"\x06\x22\x01\x01\x00\x01\x01\x00\x01\x01\x01\x00\x00"
    repeated = repeated_header + b"\x07" + _TAIL
    fetch.begin_fetch()
    assert _payload(fetch.recv(_Socket(_frame(repeated)), 65536))[0] == repeated
    assert fetch.convert(marker) is owner
    fetch.close()
    assert b"".join(owner.iter_bytes()) == b"known-secret"
    owner.close()


@pytest.mark.parametrize(
    "wire",
    [_frame(b"\x10unexpected-describe\xfe\x07"), _wire(bytes(range(256)) * 30)[:-100], b"\0\0\0\x09\x06\0\0\0\0"],
)
def test_malformed_or_truncated_long_fails_closed_without_publishing_prefix(wire):
    module = _module()
    fetch = module.LongFetch(deadline=time.monotonic() + 30)
    source = _Socket(wire)
    with pytest.raises(module.LongStreamError):
        fetch.recv(source, 65536)
    assert source.closed
    assert fetch.current_value is None
    fetch.close()


def test_expired_long_deadline_closes_socket_without_reading_value():
    module = _module()
    fetch = module.LongFetch(deadline=time.monotonic() - 1)
    source = _Socket(_wire(b"known-secret"))
    with pytest.raises(TimeoutError, match="discover_time"):
        fetch.recv(source, 65536)
    assert source.closed and source.offset == 0
    assert fetch.current_value is None


def test_long_spool_disk_failure_closes_socket_and_removes_unfinished_file(monkeypatch):
    module = _module()
    paths = []

    def fail(owner, _piece):
        paths.append(owner.path)
        raise OSError("fixture disk full")

    monkeypatch.setattr(module.StreamedLongValue, "write", fail)
    fetch = module.LongFetch(deadline=time.monotonic() + 30)
    source = _Socket(_wire(b"known-secret"))
    with pytest.raises(OSError, match="disk full"):
        fetch.recv(source, 65536)
    assert source.closed and paths and all(not path.exists() for path in paths)
    assert fetch.current_value is None


class _Driver:
    DB_TYPE_LONG = object()
    DB_TYPE_LONG_RAW = object()
    DB_TYPE_JSON = object()
    DB_TYPE_CLOB = object()
    DB_TYPE_BLOB = object()
    DB_TYPE_NCLOB = object()
    DB_TYPE_NUMBER = object()
    DB_TYPE_VARCHAR = object()

    def __init__(self, raw, make_connection):
        self.raw = raw
        self.make_connection = make_connection
        self.thin_impl = SimpleNamespace(
            socket=SimpleNamespace(
                create_connection=lambda *_args, **_kwargs: raw, socket=lambda *_args, **_kwargs: raw
            ),
            ssl=SimpleNamespace(create_default_context=ssl.create_default_context, SSLError=ssl.SSLError),
        )

    def connect(self, **kwargs):
        transport = self.thin_impl.socket.create_connection(("qa", 1521), 3)
        return self.make_connection(transport)


def test_oracle_connect_tracks_only_sdk_namespace_and_preserves_native_connection():
    module = _module()
    before_socket = socket.socket
    before_connect = socket.create_connection
    before_ssl = ssl.create_default_context
    native = SimpleNamespace()
    raw = _Socket(b"auth-bytes")
    seen = []

    def connected(transport):
        seen.append(transport)
        return native

    driver = _Driver(raw, connected)
    result = oracle.connect_oracle(oracle.OracleConnectConfig("qa", 1521, service="FREEPDB1"), driver=driver)
    assert result is native
    assert socket.socket is before_socket and socket.create_connection is before_connect
    assert ssl.create_default_context is before_ssl
    assert seen[0] is not raw and seen[0].recv(10) == b"auth-bytes"
    assert driver.thin_impl.socket.create_connection(("qa", 1521), 3) is raw
    # Non-weakrefable fakes retain compatibility; ordinary connections still
    # work and only a later requested LONG requires a tracked native transport.
    assert module.connection_state(result) is None


def test_oracle_ssl_namespace_keeps_same_context_and_verification_policy():
    module = _module()
    raw = _Socket(b"unused")
    events = []
    wrapped = _Socket(b"decrypted")

    class Context:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, source, *, server_hostname):
            assert source is raw
            events.append(server_hostname)
            return wrapped

    context = Context()
    driver = _Driver(raw, lambda transport: SimpleNamespace())
    driver.thin_impl.ssl.create_default_context = lambda: context
    module.install_driver_hooks(driver)
    original = ssl.create_default_context
    with module.connecting() as state:
        tracked = driver.thin_impl.socket.create_connection(("qa", 2484), 3)
        sdk_context = driver.thin_impl.ssl.create_default_context()
        tls = sdk_context.wrap_socket(tracked, server_hostname="qa")
        assert tls.recv(9) == b"decrypted"
        assert state.transport is tls
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    assert events == ["qa"] and ssl.create_default_context is original
    assert driver.thin_impl.ssl.create_default_context() is context


def test_untracked_connection_refuses_long_before_fetch_but_ordinary_types_still_work(monkeypatch):
    driver = _Driver(_Socket(b""), lambda transport: None)
    monkeypatch.setattr(oracle, "_load_oracledb", lambda: driver)

    class Cursor:
        description = [("PASSWORD", driver.DB_TYPE_LONG)]

        def var(self, *args, **kwargs):
            return object()

        def execute(self, *args):
            assert self.arraysize == 1 and self.prefetchrows == 0

        def fetchone(self):
            pytest.fail("untracked LONG reached the eager SDK fetch")

        def close(self):
            pass

    connection = SimpleNamespace(cursor=lambda: Cursor())
    with pytest.raises(oracle.OracleClientError, match="(?i)(untracked|transport|stream)"):
        list(oracle.OracleAuditClient(connection).iter_table_rows("QA", "DOCS", remaining_bytes=lambda: 2**63 - 1))


def test_oracle_table_long_projection_coexists_with_json_and_restores_original_column_order(monkeypatch):
    module = _module()
    text = "λ😀Ab0" * 20000
    source = _Socket(_wire(text.encode()))
    statements = []
    driver = _Driver(source, lambda transport: Connection(transport))
    monkeypatch.setattr(oracle, "_load_oracledb", lambda: driver)

    class JsonLob:
        def size(self):
            return len('{"password":"json-secret"}')

        def read(self, offset, amount):
            return '{"password":"json-secret"}'[offset - 1 : offset - 1 + amount]

    class Cursor:
        def __init__(self, connection):
            self.connection = connection
            self.calls = 0
            self.description = [
                ("ID", driver.DB_TYPE_NUMBER),
                ("PASSWORD", driver.DB_TYPE_LONG),
                ("PAYLOAD", driver.DB_TYPE_JSON),
                ('quote"field', driver.DB_TYPE_VARCHAR),
            ]

        def var(self, datatype, **kwargs):
            return SimpleNamespace(outconverter=kwargs.get("outconverter"))

        def execute(self, sql, params):
            statements.append(sql)
            assert self.arraysize == 1 and self.prefetchrows == 0
            if sql != "select * from QA.DOCS":
                self.description = [
                    ("PASSWORD", driver.DB_TYPE_LONG),
                    ("ID", driver.DB_TYPE_NUMBER),
                    ("PAYLOAD", driver.DB_TYPE_CLOB),
                    ('quote"field', driver.DB_TYPE_VARCHAR),
                ]

        def fetchone(self):
            self.calls += 1
            if self.calls > 1:
                return None
            assert statements[-1].startswith('select "PASSWORD", "ID", json_serialize(')
            payload, _ = _payload(self.connection.transport.recv(65536))
            size = payload[11]
            marker = payload[12 : 12 + size].decode("ascii")
            var = self.outputtypehandler(self, SimpleNamespace(type_code=driver.DB_TYPE_LONG))
            return var.outconverter(marker), 7, JsonLob(), "ordinary"

        def close(self):
            self.connection.cursor_closed = True

    class Connection:
        call_timeout = 30000

        def __init__(self, transport):
            self.transport = transport

        def cursor(self):
            return Cursor(self)

    connection = oracle.connect_oracle(oracle.OracleConnectConfig("qa", 1521, service="FREEPDB1"), driver=driver)
    assert module.connection_state(connection) is not None
    rows = list(oracle.OracleAuditClient(connection).iter_table_rows("QA", "DOCS", remaining_bytes=lambda: 2**63 - 1))
    assert list(rows[0]) == ["id", "password", "payload", 'quote"field']
    assert rows[0]["id"] == 7 and rows[0]["payload"] == {"password": "json-secret"}
    assert rows[0]['quote"field'] == "ordinary"
    value = rows[0]["password"]
    assert isinstance(value, DiskBackedText) and "".join(value.iter_text_chunks()) == text
    assert connection.cursor_closed
    value.close()


def test_discovery_query_iterator_rejects_unknown_long_prefix_layout_before_fetch(monkeypatch):
    driver = _Driver(_Socket(b""), lambda transport: None)
    object_type = object()
    monkeypatch.setattr(oracle, "_load_oracledb", lambda: driver)

    class Cursor:
        description = [("COMPLEX_OBJECT", object_type), ("PASSWORD", driver.DB_TYPE_LONG)]

        def var(self, *args, **kwargs):
            return object()

        def execute(self, *args):
            assert self.prefetchrows == 0

        def fetchone(self):
            pytest.fail("unknown object-before-LONG layout reached eager SDK fetch")

        def close(self):
            pass

    class Connection:
        def cursor(self):
            return Cursor()

    driver.make_connection = lambda transport: Connection()
    connection = oracle.connect_oracle(oracle.OracleConnectConfig("qa", 1521, service="FREEPDB1"), driver=driver)
    client = oracle.OracleAuditClient(connection)
    with pytest.raises(oracle.OracleClientError, match="(?i)(complex|layout)"):
        list(client.iter_query_rows("select complex_object,password from docs", deadline=time.monotonic() + 30))


@pytest.mark.parametrize("binary", [False, True])
def test_tracked_first_column_query_decodes_unicode_or_preserves_raw_bytes_repr(monkeypatch, binary):
    value = b"x" * 65535 + "😀λ".encode() + b"password=last-secret" + (b"\xff" if binary else b"")
    source = _Socket(_wire(value))
    driver = _Driver(source, lambda transport: Connection(transport))
    datatype = driver.DB_TYPE_LONG_RAW if binary else driver.DB_TYPE_LONG
    monkeypatch.setattr(oracle, "_load_oracledb", lambda: driver)

    class Cursor:
        description = [("PASSWORD", datatype)]
        calls = 0

        def __init__(self, connection):
            self.connection = connection

        def var(self, datatype, **kwargs):
            return SimpleNamespace(outconverter=kwargs.get("outconverter"))

        def execute(self, sql, params):
            assert sql == "select password from docs"
            assert self.arraysize == 1 and self.prefetchrows == 0

        def fetchone(self):
            self.calls += 1
            if self.calls > 1:
                return None
            payload, _ = _payload(self.connection.transport.recv(65536))
            marker = payload[12 : 12 + payload[11]]
            var = self.outputtypehandler(self, SimpleNamespace(type_code=datatype))
            return (var.outconverter(marker if binary else marker.decode()),)

        def close(self):
            pass

    class Connection:
        call_timeout = 30000

        def __init__(self, transport):
            self.transport = transport

        def cursor(self):
            return Cursor(self)

    connection = oracle.connect_oracle(oracle.OracleConnectConfig("qa", 1521, service="FREEPDB1"), driver=driver)
    rows = list(
        oracle.OracleAuditClient(connection).iter_query_rows(
            "select password from docs",
            deadline=time.monotonic() + 30,
        )
    )
    result = rows[0]["password"]
    assert isinstance(result, DiskBackedText)
    expected = oracle.json_safe(value) if binary else value.decode("utf-8", errors="strict")
    assert "".join(result.iter_text_chunks()) == expected
    result.close()


def test_discovery_query_failure_keeps_completed_table_and_query_findings():
    from redposture_core.modules.oracle.actions import _collect_oracle_data
    from tests.test_oracle_discover import _OracleDiscoveryClient

    class Client(_OracleDiscoveryClient):
        def iter_table_rows(self, _schema, _table, **_kwargs):
            yield {"password": "early-secret"}

        def iter_query_rows(self, sql, **kwargs):
            assert sql == "select password from docs"
            assert kwargs["deadline"] > time.monotonic()
            yield {"password": "query-secret"}
            raise oracle.OracleClientError("unsupported LONG layout in later query row")

        def query(self, *_args, **_kwargs):
            pytest.fail("discovery query reached the eager query() API")

    record = _collect_oracle_data(
        Client(),
        host="qa",
        port=1521,
        protocol="tcp",
        insecure=False,
        listener_dump=False,
        nne_check=False,
        show_pdbs=False,
        show_users=False,
        show_roles=False,
        show_privs=False,
        show_schemas=False,
        show_tables=False,
        schema="QA",
        table="FIRST",
        dump_rows=True,
        dump_limit=0,
        query="select password from docs",
        privesc_check=False,
        privesc_chain=False,
        exec_cmd=None,
        exec_method="auto",
        reverse_shell=None,
        reverse_shell_type="nc",
        os_read=None,
        os_write=None,
        download=None,
        delete=None,
        wallet_search=False,
        hashes=False,
        sensitive_scan=False,
        dblink_check=False,
        discover=True,
        discover_time=900,
        discover_implicit_dump=True,
        discover_ctx=SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=1521),
    )
    result = record["content_discovery"]
    assert result["status"] == "partial"
    values = {f["value"] for f in result["findings"]}
    assert {"early-secret", "query-secret"} <= values
    assert record["query_rows"] == [{"password": "query-secret"}]


def test_discovery_query_reads_beyond_old_200_row_preview_and_reaches_eof():
    from redposture_core.modules.oracle.actions import _collect_oracle_data
    from tests.test_oracle_discover import _OracleDiscoveryClient

    events = {"eof": False}

    class Client(_OracleDiscoveryClient):
        def iter_query_rows(self, _sql, **_kwargs):
            for index in range(200):
                yield {"message": f"ordinary row {index}"}
            yield {"password": "late-query-secret"}
            events["eof"] = True

        def query(self, *_args, **_kwargs):
            pytest.fail("discover fell back to capped eager query()")

    record = _collect_oracle_data(
        Client(),
        host="qa",
        port=1521,
        protocol="tcp",
        insecure=False,
        listener_dump=False,
        nne_check=False,
        show_pdbs=False,
        show_users=False,
        show_roles=False,
        show_privs=False,
        show_schemas=False,
        show_tables=False,
        schema=None,
        table=None,
        dump_rows=False,
        dump_limit=None,
        query="select password from docs",
        privesc_check=False,
        privesc_chain=False,
        exec_cmd=None,
        exec_method="auto",
        reverse_shell=None,
        reverse_shell_type="nc",
        os_read=None,
        os_write=None,
        download=None,
        delete=None,
        wallet_search=False,
        hashes=False,
        sensitive_scan=False,
        dblink_check=False,
        discover=True,
        discover_time=900,
        discover_ctx=SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=1521),
    )
    assert events["eof"] and record["content_discovery"]["status"] == "complete"
    assert any(
        f["value"] == "late-query-secret" and f["object_path"] == "$.query_rows[200].password"
        for f in record["content_discovery"]["findings"]
    )


def test_discovery_query_preview_reads_only_a_bounded_prefix_of_disk_values():
    from redposture_core.modules.oracle.actions import _format_detail_records

    read_chars = []

    class Value(DiskBackedText):
        def iter_text_chunks(self, *, max_chars=65536):
            for chunk in super().iter_text_chunks(max_chars=max_chars):
                read_chars.append(len(chunk))
                yield chunk

    value = Value()
    value.append_text("A" * 100_000)
    value.finish()
    try:
        record = {
            "host": "qa",
            "port": 1521,
            "query_rows": [{"password": value}],
            "content_discovery": {"status": "complete", "findings": []},
        }
        lines = _format_detail_records(record, "txt")
        assert any('{"password":"AAAA' in line for line in lines)
        assert max(map(len, lines)) < 400 and all("\x1b" not in line and "object at" not in line for line in lines)
        assert 0 < sum(read_chars) <= 65536
    finally:
        value.close()


def test_native_json_discovery_query_serializes_server_side_and_preserves_order_subset_and_binds(monkeypatch):
    driver = _Driver(_Socket(b""), lambda transport: None)
    monkeypatch.setattr(oracle, "_load_oracledb", lambda: driver)
    sql = "select id,payload from docs where id>=:first order by id desc fetch first 2 rows only"
    statements = []

    class Lob:
        def __init__(self, value):
            self.value = value

        def size(self):
            return len(self.value)

        def read(self, offset, amount):
            return self.value[offset - 1 : offset - 1 + amount]

    class Cursor:
        description = [("ID", driver.DB_TYPE_NUMBER), ("PAYLOAD", driver.DB_TYPE_JSON)]
        calls = 0

        def var(self, *args, **kwargs):
            return object()

        def execute(self, statement, params):
            assert self.arraysize == 1 and self.prefetchrows == 0
            assert params == {"first": 2}
            statements.append(statement)
            if len(statements) == 2:
                assert "json_serialize" in statement.lower() and sql in statement
                self.description = [("ID", driver.DB_TYPE_NUMBER), ("PAYLOAD", driver.DB_TYPE_CLOB)]

        def fetchone(self):
            assert len(statements) == 2, "native JSON reached eager SDK decoding"
            self.calls += 1
            return (
                (3, Lob('{"password":"third-secret"}'))
                if self.calls == 1
                else (2, Lob('{"password":"second-secret"}'))
                if self.calls == 2
                else None
            )

        def close(self):
            pass

    connection = SimpleNamespace(cursor=lambda: Cursor())
    rows = list(oracle.OracleAuditClient(connection).iter_query_rows(sql, {"first": 2}, deadline=time.monotonic() + 30))
    assert rows == [
        {"id": 3, "payload": {"password": "third-secret"}},
        {"id": 2, "payload": {"password": "second-secret"}},
    ]
    assert statements[0] == sql


def test_ambiguous_native_json_query_aliases_fail_before_eager_fetch(monkeypatch):
    driver = _Driver(_Socket(b""), lambda transport: None)
    monkeypatch.setattr(oracle, "_load_oracledb", lambda: driver)

    class Cursor:
        description = [("PAYLOAD", driver.DB_TYPE_JSON), ("PAYLOAD", driver.DB_TYPE_NUMBER)]

        def var(self, *args, **kwargs):
            return object()

        def execute(self, *args):
            pass

        def fetchone(self):
            pytest.fail("ambiguous JSON aliases reached eager decoding")

        def close(self):
            pass

    client = oracle.OracleAuditClient(SimpleNamespace(cursor=lambda: Cursor()))
    with pytest.raises(oracle.OracleClientError, match="(?i)alias"):
        list(client.iter_query_rows("select payload,payload from docs", deadline=time.monotonic() + 30))
