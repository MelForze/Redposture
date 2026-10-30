"""Native Oracle LOBs must reach discovery as complete bounded disk values."""

from __future__ import annotations

import hashlib
import tracemalloc
from types import SimpleNamespace

import pytest

from redposture_core.clients.oracle import OracleAuditClient
from redposture_core.discovery_values import DiskBackedText


@pytest.mark.parametrize("nested", [False, True])
def test_oracle_row_conversion_preserves_full_disk_json_keys(nested):
    from redposture_core.clients.oracle import _rows_to_dicts
    from redposture_core.discovery_values import iter_json_chunks
    from redposture_core.json_stream import DiskJSONKey

    key = DiskJSONKey()
    key.append_text("catalog_" + "q" * 100_000)
    key.finish()
    original = {key: {"password": "known-secret"}}
    payload = {"items": [original]} if nested else original
    row = _rows_to_dicts(SimpleNamespace(description=[("PAYLOAD",)]), [(payload,)])[0]
    restored = row["payload"]["items"][0] if nested else row["payload"]
    restored_key = next(iter(restored))
    assert isinstance(restored_key, DiskBackedText)
    assert (restored_key.byte_length, restored_key.digest) == (key.byte_length, key.digest)
    assert "".join(iter_json_chunks(row)).find("DiskJSONKey object") == -1
    assert restored[restored_key] == {"password": "known-secret"}


@pytest.mark.parametrize("binary", [False, True])
def test_oracle_large_lob_is_read_and_returned_without_materializing_whole_value(binary) -> None:
    payload = (b"Sa7/" if binary else "Sa7/") * 2_500_000
    calls = []

    class Lob:
        def size(self):
            return len(payload)

        def read(self, offset, amount):
            calls.append(amount)
            return payload[offset - 1 : offset - 1 + amount]

    class Cursor:
        description = [("PAYLOAD",)]
        closed = False
        calls = 0

        def execute(self, *args, **kwargs):
            pass

        def fetchone(self):
            self.calls += 1
            return (Lob(),) if self.calls == 1 else None

        def close(self):
            self.closed = True

    cursor = Cursor()
    connection = SimpleNamespace(cursor=lambda: cursor, call_timeout=30000)
    tracemalloc.start()
    try:
        rows = list(OracleAuditClient(connection).iter_table_rows("QA", "DOCS", remaining_bytes=lambda: 2**63 - 1))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    value = rows[0]["payload"]
    assert cursor.closed and calls and max(calls) <= 65536
    assert peak < 4_000_000, f"Oracle LOB materialized {peak} bytes"
    assert isinstance(value, DiskBackedText)
    expected = payload if binary else payload.encode()
    assert value.byte_length == len(expected) and value.digest == hashlib.sha256(expected).hexdigest()
    value.close()


def test_oracle_partial_lob_never_becomes_a_complete_value_but_keeps_previous_row() -> None:
    class Lob:
        def size(self):
            return 150_000

        def read(self, offset, amount):
            if offset > 65536:
                raise OSError("transport interrupted")
            return "Sa7/" * (amount // 4)

    class Cursor:
        description = [("PASSWORD",)]
        closed = False
        calls = 0

        def execute(self, *args, **kwargs):
            pass

        def fetchone(self):
            self.calls += 1
            return ("first-secret",) if self.calls == 1 else (Lob(),) if self.calls == 2 else None

        def close(self):
            self.closed = True

    cursor = Cursor()
    stream = OracleAuditClient(SimpleNamespace(cursor=lambda: cursor, call_timeout=30000)).iter_table_rows(
        "QA", "DOCS", remaining_bytes=lambda: 2**63 - 1
    )
    assert next(stream) == {"password": "first-secret"}
    with pytest.raises(OSError, match="interrupted"):
        next(stream)
    assert cursor.closed


def test_oracle_discovery_rows_spool_instead_of_retaining_the_whole_table() -> None:
    from tests.test_oracle_discover import _collect

    class Client:
        def current_context(self):
            return {"session_user": "QA"}

        def server_banner(self):
            return {"version": "23ai"}

        def iter_tables(self, schema):
            yield {"owner": "QA", "table_name": "DOCS"}

        def iter_table_rows(self, schema, table):
            for i in range(100_000):
                yield {"password": f"secret-{i:08d}"}

    tracemalloc.start()
    try:
        result = _collect(Client(), implicit=True, discover_time=900)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert not result["discover_partial"], result["discover_reasons"]
    assert len(result["rows"]) == 100_000
    assert result["rows"][0]["row"]["password"] == "secret-00000000"
    assert result["rows"][-1]["row"]["password"] == "secret-00099999"
    assert peak < 8_000_000, f"Oracle rows retained {peak} bytes"


def test_oracle_expired_query_keeps_cleanup_inside_remaining_timeout() -> None:
    import time

    from redposture_core.clients.oracle import OracleReadBudgetError

    connection = SimpleNamespace(call_timeout=5000)
    close_timeouts = []

    class Cursor:
        description = [("PASSWORD",)]

        def execute(self, *args):
            pass

        def fetchone(self):
            time.sleep(0.02)
            return ("late-secret",)

        def close(self):
            close_timeouts.append(connection.call_timeout)
            if connection.call_timeout > 10:
                time.sleep(0.5)

    connection.cursor = lambda: Cursor()
    started = time.monotonic()
    with pytest.raises(OracleReadBudgetError, match="discover_time"):
        list(OracleAuditClient(connection).iter_table_rows("QA", "DOCS", deadline=started + 0.01))
    elapsed = time.monotonic() - started
    assert elapsed < 0.2, f"cleanup outlived the target deadline ({elapsed:.3f}s)"
    assert close_timeouts and close_timeouts[0] <= 10
    assert connection.call_timeout == 5000


@pytest.mark.parametrize("kind", ["CLOB", "BLOB", "NCLOB"])
def test_oracle_stream_cursor_requests_lob_locators_instead_of_driver_eager_values(monkeypatch, kind) -> None:
    from redposture_core.clients import oracle

    types = {name: object() for name in ("CLOB", "BLOB", "NCLOB")}
    driver = SimpleNamespace(**{"DB_TYPE_" + name: value for name, value in types.items()})
    monkeypatch.setattr(oracle, "_load_oracledb", lambda: driver)
    requested = []

    class Cursor:
        description = []
        outputtypehandler = None

        def var(self, type_code, *, arraysize):
            requested.append((type_code, arraysize))
            return "locator-var"

        def execute(self, *args):
            assert callable(self.outputtypehandler), "eager LOB conversion was not overridden on the discovery cursor"
            assert self.outputtypehandler(self, SimpleNamespace(type_code=types[kind])) == "locator-var"
            assert self.outputtypehandler(self, SimpleNamespace(type_code=object())) is None

        def fetchone(self):
            return None

        def close(self):
            pass

    cursor = Cursor()
    list(
        OracleAuditClient(SimpleNamespace(cursor=lambda: cursor)).iter_table_rows(
            "QA", "DOCS", remaining_bytes=lambda: 2**63 - 1
        )
    )
    assert requested == [(types[kind], 1)]


def test_oracle_native_json_is_projected_as_lob_before_fetch_and_restored_as_structure(monkeypatch):
    from redposture_core.clients import oracle

    json_type, clob_type = object(), object()
    driver = SimpleNamespace(DB_TYPE_JSON=json_type, DB_TYPE_CLOB=clob_type)
    monkeypatch.setattr(oracle, "_load_oracledb", lambda: driver)
    payload = '{"password":"' + "v" * 200000 + '"}'
    statements = []

    class Lob:
        def size(self):
            return len(payload)

        def read(self, offset, amount):
            return payload[offset - 1 : offset - 1 + amount]

    class Cursor:
        description = [("PAYLOAD", json_type), ('quote"field', object())]
        calls = 0

        def var(self, *args, **kwargs):
            return object()

        def execute(self, sql, params):
            statements.append(sql)
            assert self.prefetchrows == 0, "metadata request must not prefetch a large native JSON"
            if len(statements) == 2:
                self.description = [("PAYLOAD", clob_type), ('quote"field', object())]

        def fetchone(self):
            assert len(statements) == 2, "native JSON would be materialized by the driver"
            self.calls += 1
            return (Lob(), "ordinary") if self.calls == 1 else None

        def close(self):
            pass

    cursor = Cursor()
    rows = list(
        OracleAuditClient(SimpleNamespace(cursor=lambda: cursor)).iter_table_rows(
            "QA", "DOCS", remaining_bytes=lambda: 2**63 - 1
        )
    )
    assert statements == [
        "select * from QA.DOCS",
        'select json_serialize("PAYLOAD" returning CLOB) as "PAYLOAD", "quote""field" from QA.DOCS',
    ]
    assert rows[0]['quote"field'] == "ordinary"
    value = rows[0]["payload"]["password"]
    assert isinstance(value, DiskBackedText)
    assert value.byte_length == 200000 and value.digest == hashlib.sha256(b"v" * 200000).hexdigest()


def test_oracle_completed_row_is_emitted_before_fetching_next_row():
    from tests.test_oracle_discover import _collect, _OracleDiscoveryClient

    events = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=900),
        host="qa",
        port=1521,
        live_emit=lambda lines: events.extend(lines),
        live_discovery_value=None,
    )

    class Client(_OracleDiscoveryClient):
        def iter_table_rows(self, schema, table):
            yield {"password": "early-secret"}
            assert any('Value="early-secret"' in event for event in events), "first finding waited for the next row"
            yield {"password": "later-secret"}

    record = _collect(Client(), schema="QA", table="FIRST", implicit=True, discover_ctx=ctx)
    result = record["content_discovery"]
    assert result["status"] == "complete" and len(result["findings"]) == 2
    assert all(finding["object_path"] == "$.table.QA.FIRST.password" for finding in result["findings"])
    assert len(events) == 2 and result["live_emitted"]


def test_oracle_early_findings_survive_later_row_failure_without_reemission():
    from redposture_core.data_discovery import iter_discovery_finding_lines
    from tests.test_oracle_discover import _collect, _OracleDiscoveryClient

    events = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=900),
        host="qa",
        port=1521,
        live_emit=lambda lines: events.extend(lines),
        live_discovery_value=None,
    )

    class Client(_OracleDiscoveryClient):
        def iter_table_rows(self, schema, table):
            yield {"password": "early-secret"}
            raise OSError("truncated following row")

    record = _collect(Client(), schema="QA", table="FIRST", implicit=True, discover_ctx=ctx)
    assert record["content_discovery"]["status"] == "partial"
    assert [finding["value"] for finding in record["content_discovery"]["findings"]] == ["early-secret"]
    assert len(events) == 1
    assert list(iter_discovery_finding_lines("oracle", record)) == []


def test_oracle_verified_credentials_prefix_is_emitted_once_with_complete_metadata():
    from redposture_core.modules.oracle import actions

    lines = []
    ctx = SimpleNamespace(live_emit=lambda batch: lines.extend(batch))
    record = {
        "host": "qa",
        "port": 1521,
        "status": "valid_credentials",
        "provided_username": "qauser",
        "provided_password": "qapass",
    }
    metadata = {"con_name": "FREEPDB1", "server_version": "23.26.3.0.0"}
    actions._emit_oracle_discovery_prefix(record, ctx, metadata)
    actions._emit_oracle_discovery_prefix(record, ctx, metadata)
    assert len(lines) == 1 and "[+] qauser:qapass" in lines[0]
    assert "(con:FREEPDB1)" in lines[0] and "(version:23.26.3.0.0)" in lines[0]
    assert actions._format_record(record, "txt") == ""
    assert actions._format_credential_attempts_records(record, "txt") == []


class _ClosedTimeoutConnection:
    def __init__(self):
        self.healthy = True
        self.timeout = 5000

    def is_healthy(self):
        return self.healthy

    @property
    def call_timeout(self):
        assert self.healthy, "unsafe timeout access after transport closure"
        return self.timeout

    @call_timeout.setter
    def call_timeout(self, value):
        assert self.healthy, "unsafe timeout restore after transport closure"
        self.timeout = value


def test_oracle_timeout_does_not_touch_native_timeout_on_broken_connection() -> None:
    import time

    connection = _ClosedTimeoutConnection()
    closed = []

    class Cursor:
        description = [("PASSWORD",)]

        def execute(self, *args):
            pass

        def fetchone(self):
            connection.healthy = False
            raise TimeoutError("driver closed transport")

        def close(self):
            closed.append(True)

    connection.cursor = lambda: Cursor()
    with pytest.raises(TimeoutError, match="driver closed transport"):
        list(OracleAuditClient(connection).iter_table_rows("QA", "DOCS", deadline=time.monotonic() + 1))
    assert closed == [True]


def test_oracle_outer_discovery_preserves_timeout_reason_after_driver_disconnect() -> None:
    from redposture_core.clients.oracle import OracleReadBudgetError
    from tests.test_oracle_discover import _collect

    class Client:
        connection = _ClosedTimeoutConnection()

        def current_context(self):
            return {"session_user": "QA"}

        def server_banner(self):
            return {}

        def iter_tables(self, schema):
            yield {"owner": "QA", "table_name": "DOCS"}

        def iter_table_rows(self, schema, table):
            yield {"password": "first-secret"}
            self.connection.healthy = False
            raise OracleReadBudgetError("discover_time")

    result = _collect(Client(), implicit=True, discover_time=30)
    assert result["discover_partial"]
    assert "discover_time" in result["discover_reasons"]
    assert result["rows"][0]["row"]["password"] == "first-secret"


def test_oracle_native_error_after_deadline_is_reported_as_discover_time() -> None:
    import time

    from redposture_core.clients.oracle import OracleReadBudgetError

    connection = _ClosedTimeoutConnection()

    class Cursor:
        description = []

        def execute(self, *args):
            pass

        def fetchone(self):
            time.sleep(0.02)
            connection.healthy = False
            raise TimeoutError("driver transport recovery failed")

        def close(self):
            pass

    connection.cursor = lambda: Cursor()
    with pytest.raises(OracleReadBudgetError, match="discover_time"):
        list(OracleAuditClient(connection).iter_table_rows("QA", "DOCS", deadline=time.monotonic() + 0.01))
