from __future__ import annotations

import datetime as dt
import json
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from redposture_core import stage_clickhouse as clickhouse_stage


class _DummyClient:
    def __init__(self, rows: list[object] | None = None, error: Exception | None = None) -> None:
        self.rows = rows or []
        self.error = error
        self.closed = False
        self.queries: list[str] = []

    def execute(self, query: str) -> list[object]:
        self.queries.append(query)
        if self.error is not None:
            raise self.error
        return list(self.rows)

    def query(self, query: str) -> SimpleNamespace:
        self.queries.append(query)
        if self.error is not None:
            raise self.error
        return SimpleNamespace(result_rows=list(self.rows))

    def close(self) -> None:
        self.closed = True

    def disconnect(self) -> None:
        self.closed = True


class _RecordingConsole:
    def __init__(self) -> None:
        self.paint_calls: list[tuple[str, str]] = []
        self.lines: list[str] = []

    def _paint(self, text: str, color: str, _stream) -> str:
        self.paint_calls.append((text, color))
        return text

    def plain(self, text: str, color: str | None = None) -> None:
        _ = color
        self.lines.append(text)


class _FakeConsole:
    def __init__(self, debug: bool = False) -> None:
        self.debug = debug
        self.errors: list[str] = []
        self.infos: list[str] = []
        self.successes: list[str] = []
        self.plains: list[str] = []

    def error(self, text: str) -> None:
        self.errors.append(text)

    def info(self, text: str) -> None:
        self.infos.append(text)

    def success(self, text: str) -> None:
        self.successes.append(text)

    def plain(self, text: str, color: str | None = None) -> None:
        _ = color
        self.plains.append(text)

    def render_tagged_payload_line(self, line: str, _tag: str, payload_color: str = "white") -> bool:
        _ = payload_color
        self.plains.append(line)
        return True

    def _paint(self, text: str, _color: str, _stream) -> str:
        return text


def _session(
    protocol: str = "native",
    client: object | None = None,
    database: str = "default",
) -> clickhouse_stage._ChSession:
    return clickhouse_stage._ChSession(
        protocol=protocol,
        client=client if client is not None else _DummyClient(),
        username="default",
        password="",
        database=database,
    )


def _base_args(**kwargs: object) -> SimpleNamespace:
    args: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "retries": 0,
        "workers": 1,
        "username": None,
        "password": None,
        "port": 9000,
        "ports": None,
        "protocol": "native",
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "database": "default",
        "show_databases": False,
        "show_tables": False,
        "show_columns": False,
        "tables": None,
        "dump": False,
        "columns": None,
        "execute": None,
        "sql_cmd": None,
        "os_shell": False,
        "sql_shell": False,
        "output": None,
        "output_format": "txt",
        "defcreds": False,
        "log": None,
    }
    args.update(kwargs)
    return SimpleNamespace(**args)


@pytest.mark.parametrize(
    ("text", "width", "expected"),
    [
        ("abc", 5, "abc"),
        ("abcdef", 5, "ab..."),
        ("abcdef", 2, "ab"),
    ],
)
def test_clip_variants(text: str, width: int, expected: str) -> None:
    assert clickhouse_stage._clip(text, width) == expected


@pytest.mark.parametrize(
    ("attempt", "expected"),
    [
        (0, 0.2),
        (1, 0.4),
        (2, 0.8),
        (3, 1.5),
        (6, 1.5),
    ],
)
def test_retry_delay_capped(attempt: int, expected: float) -> None:
    assert clickhouse_stage._retry_delay(attempt) == expected


def test_friendly_error_timeout_refused_and_clip() -> None:
    assert clickhouse_stage._friendly_error_from_exception(TimeoutError("boom")) == "connection timeout"
    assert (
        clickhouse_stage._friendly_error_from_exception(ConnectionRefusedError("[Errno 61] Connection refused"))
        == "connection refused (service is not listening on target port)"
    )
    long_text = "x" * 500
    assert clickhouse_stage._friendly_error_from_exception(RuntimeError(long_text)).endswith("...")


@pytest.mark.parametrize(
    ("value", "is_timeout", "is_refused"),
    [
        ("connection timeout", True, False),
        ("timed out", True, False),
        ("connection refused", False, True),
        ("ok", False, False),
    ],
)
def test_error_predicates(value: str, is_timeout: bool, is_refused: bool) -> None:
    assert clickhouse_stage._is_timeout_error(value) is is_timeout
    assert clickhouse_stage._is_connection_refused_error(value) is is_refused


def test_fail_record_predicates() -> None:
    assert clickhouse_stage._is_connection_timeout_fail_record({"status": "fail", "error": "timeout"}) is True
    assert (
        clickhouse_stage._is_connection_refused_fail_record({"status": "fail", "error": "connection refused"}) is True
    )
    assert clickhouse_stage._is_connection_timeout_fail_record({"status": "open_no_auth", "error": "timeout"}) is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Code: 516. Authentication failed", True),
        ("unauthorized", True),
        ("access denied", True),
        ("all good", False),
    ],
)
def test_is_auth_error_markers(value: str, expected: bool) -> None:
    assert clickhouse_stage._is_auth_error(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("DB::Exception", True),
        ("Unexpected packet from server", True),
        ("Code: 210", True),
        ("random text", False),
    ],
)
def test_looks_like_clickhouse_error_markers(value: str, expected: bool) -> None:
    assert clickhouse_stage._looks_like_clickhouse_error(value) is expected


def test_bool_and_password_text_helpers() -> None:
    assert clickhouse_stage._bool_text(True) == "true"
    assert clickhouse_stage._bool_text(False) == "false"
    assert clickhouse_stage._bool_text(None) == "unknown"
    assert clickhouse_stage._password_text("") == "<empty>"
    assert clickhouse_stage._password_text(None) == "<none>"
    assert clickhouse_stage._password_text("secret") == "secret"


def test_quote_ident_escapes_backticks() -> None:
    assert clickhouse_stage._quote_ident("a`b") == "`a``b`"


def test_normalize_column_names_filters_duplicates() -> None:
    columns, error = clickhouse_stage._normalize_column_names([" id,Name ", "name", "AGE"])
    assert error is None
    assert columns == ["id", "Name", "AGE"]


def test_normalize_column_names_returns_error_on_invalid() -> None:
    columns, error = clickhouse_stage._normalize_column_names(["id", "bad-name"])
    assert columns == []
    assert error == "invalid column name: bad-name"


def test_normalize_table_targets_dedupes_case_insensitive() -> None:
    assert clickhouse_stage._normalize_table_targets(["db.events,db.users", "DB.events"]) == ["db.events", "db.users"]


def test_split_table_name_variants() -> None:
    assert clickhouse_stage._split_table_name("db.events", "default") == ("db", "events")
    assert clickhouse_stage._split_table_name("events", "default") == ("default", "events")
    assert clickhouse_stage._split_table_name("bad-name", "default") == (None, None)


def test_row_text_decodes_bytes() -> None:
    assert clickhouse_stage._row_text([b"a", 1]) == json.dumps(["a", 1], ensure_ascii=False)


def test_row_text_serializes_datetime_decimal_uuid_types() -> None:
    ts = dt.datetime(2026, 3, 11, 10, 20, 30)
    payload = clickhouse_stage._row_text(
        [
            ts,
            dt.date(2026, 3, 11),
            dt.time(10, 20, 30),
            dt.timedelta(seconds=61),
            Decimal("10.50"),
            UUID("12345678-1234-5678-1234-567812345678"),
        ]
    )
    assert json.loads(payload) == [
        ts.isoformat(),
        "2026-03-11",
        "10:20:30",
        "0:01:01",
        "10.50",
        "12345678-1234-5678-1234-567812345678",
    ]


def test_row_text_normalizes_nested_values_and_non_string_dict_keys() -> None:
    payload = clickhouse_stage._row_text(
        [
            {
                "bytes": b"abc",
                7: dt.datetime(2026, 3, 11, 11, 0, 0),
                "tuple": (Decimal("1.2"), b"x"),
                "set": {2, 1},
            }
        ]
    )
    parsed = json.loads(payload)
    assert parsed[0]["bytes"] == "abc"
    assert parsed[0]["7"] == "2026-03-11T11:00:00"
    assert parsed[0]["tuple"] == ["1.2", "x"]
    assert parsed[0]["set"] == [1, 2]


def test_row_text_uses_string_fallback_for_unknown_object() -> None:
    class _Opaque:
        def __str__(self) -> str:
            return "opaque-value"

    assert json.loads(clickhouse_stage._row_text([_Opaque()])) == ["opaque-value"]


def test_protocol_attempt_order_variants() -> None:
    assert clickhouse_stage._protocol_attempt_order("http") == ("http",)
    assert clickhouse_stage._protocol_attempt_order("native") == ("native",)
    assert clickhouse_stage._protocol_attempt_order("auto") == ("native", "http")
    assert clickhouse_stage._protocol_attempt_order("weird") == ("native",)


def test_query_rows_native_success() -> None:
    session = _session(protocol="native", client=_DummyClient(rows=[(1, "a"), 2]))
    rows, err = clickhouse_stage._query_rows(session, "SELECT 1")
    assert err is None
    assert rows == [[1, "a"], [2]]


def test_query_rows_http_success_with_none_result_rows() -> None:
    class _HttpClient:
        def query(self, _query: str) -> SimpleNamespace:
            return SimpleNamespace(result_rows=None)

    session = _session(protocol="http", client=_HttpClient())
    rows, err = clickhouse_stage._query_rows(session, "SELECT 1")
    assert err is None
    assert rows == []


def test_query_rows_handles_driver_exception() -> None:
    session = _session(protocol="native", client=_DummyClient(error=RuntimeError("boom")))
    rows, err = clickhouse_stage._query_rows(session, "SELECT 1")
    assert rows is None
    assert err == "boom"


def test_query_database_names_and_readable_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "_query_rows", lambda *_args, **_kwargs: ([["a"], ["b"]], None))
    names, err = clickhouse_stage._query_database_names(_session())
    assert err is None
    assert names == ["a", "b"]

    monkeypatch.setattr(clickhouse_stage, "_query_rows", lambda *_args, **_kwargs: ([["db", "t"], ["db"]], None))
    tables, err2 = clickhouse_stage._query_readable_tables(_session())
    assert err2 is None
    assert tables == ["db.t"]


def test_query_table_columns_with_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "_query_rows", lambda *_args, **_kwargs: ([["id"], ["name"]], None))
    cols, err = clickhouse_stage._query_table_columns(_session(), "db", "events", only_columns=["name"])
    assert err is None
    assert cols == ["name"]


def test_query_table_rows_builds_sql_and_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_query(_session, query: str):  # type: ignore[no-untyped-def]
        seen.append(query)
        return [[b"a", 1]], None

    monkeypatch.setattr(clickhouse_stage, "_query_rows", fake_query)
    rows, err = clickhouse_stage._query_table_rows(_session(), "db", "events", columns=["id"], max_rows=0)
    assert err is None
    assert rows == [json.dumps(["a", 1], ensure_ascii=False)]
    assert "SELECT `id` FROM `db`.`events` LIMIT 1" in seen[0]


def test_query_table_rows_serializes_datetime_without_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    ts = dt.datetime(2026, 3, 11, 12, 34, 56)
    monkeypatch.setattr(clickhouse_stage, "_query_rows", lambda *_args, **_kwargs: ([[ts, b"ok"]], None))
    rows, err = clickhouse_stage._query_table_rows(_session(), "db", "events", columns=None, max_rows=10)
    assert err is None
    assert rows is not None
    assert json.loads(rows[0]) == [ts.isoformat(), "ok"]


def test_query_show_grants_joins_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "_query_rows", lambda *_args, **_kwargs: ([["GRANT", "SELECT", None]], None))
    grants, err = clickhouse_stage._query_show_grants(_session())
    assert err is None
    assert grants == ["GRANT SELECT"]


def test_collect_capabilities_from_grants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "_query_database_names", lambda *_args, **_kwargs: (["default"], None))
    monkeypatch.setattr(
        clickhouse_stage,
        "_query_show_grants",
        lambda *_args, **_kwargs: (["GRANT SELECT ON *.*", "GRANT CREATE ON *.*", "ACCESS MANAGEMENT"], None),
    )
    read, execute, admin, db_count, db_names, err = clickhouse_stage._collect_capabilities(_session())
    assert (read, execute, admin, db_count, db_names, err) == (True, True, True, 1, ["default"], None)


def test_collect_capabilities_upgrades_read_when_probe_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(clickhouse_stage, "_query_database_names", lambda *_args, **_kwargs: (["default"], None))
    monkeypatch.setattr(
        clickhouse_stage, "_query_show_grants", lambda *_args, **_kwargs: (["GRANT USAGE ON *.*"], None)
    )

    def fake_query_rows(_session, query: str):  # type: ignore[no-untyped-def]
        if query == "SELECT name FROM system.tables LIMIT 1":
            return [["events"]], None
        if query.startswith("SELECT output FROM executable("):
            return [], None
        raise AssertionError(f"unexpected query: {query}")

    monkeypatch.setattr(clickhouse_stage, "_query_rows", fake_query_rows)

    read, execute, admin, db_count, db_names, err = clickhouse_stage._collect_capabilities(_session())
    assert (read, execute, admin, db_count, db_names, err) == (True, True, False, 1, ["default"], None)


@pytest.mark.parametrize(
    ("probe_error", "expected_read", "expected_execute", "expected_err"),
    [
        (None, True, True, "db error; grants error"),
        ("Code: 516. Authentication failed", False, False, "db error; grants error"),
        ("other error", None, None, "db error; grants error; other error"),
    ],
)
def test_collect_capabilities_probe_fallback(
    monkeypatch: pytest.MonkeyPatch,
    probe_error: str | None,
    expected_read: bool | None,
    expected_execute: bool | None,
    expected_err: str,
) -> None:
    monkeypatch.setattr(clickhouse_stage, "_query_database_names", lambda *_args, **_kwargs: (None, "db error"))
    monkeypatch.setattr(clickhouse_stage, "_query_show_grants", lambda *_args, **_kwargs: (None, "grants error"))
    monkeypatch.setattr(clickhouse_stage, "_query_rows", lambda *_args, **_kwargs: ([], probe_error))
    read, execute, admin, db_count, db_names, err = clickhouse_stage._collect_capabilities(_session())
    assert read is expected_read
    assert execute is expected_execute
    assert admin is None
    assert db_count is None
    assert db_names is None
    assert err == expected_err


def test_run_sql_query_truncates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "_query_rows", lambda *_args, **_kwargs: ([[1], [2], [3]], None))
    output, err = clickhouse_stage._run_sql_query(_session(), "SELECT 1", max_lines=2)
    assert err is None
    assert output == ["[1]", "[2]", "<output truncated at 2 lines>"]


def test_run_execute_command_uses_executable_for_os_command(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_query_rows(_session, query: str):  # type: ignore[no-untyped-def]
        seen.append(query)
        return [["uid=101(clickhouse)"]], None

    monkeypatch.setattr(clickhouse_stage, "_query_rows", fake_query_rows)

    output, err = clickhouse_stage._run_execute_command(_session(), "id")
    assert err is None
    assert output == ['["uid=101(clickhouse)"]']
    assert len(seen) == 1
    assert seen[0].startswith("SELECT output FROM executable(")
    assert "SELECT 'id'" in seen[0]


def test_run_execute_command_keeps_system_statement(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_query_rows(_session, query: str):  # type: ignore[no-untyped-def]
        seen.append(query)
        return [], None

    monkeypatch.setattr(clickhouse_stage, "_query_rows", fake_query_rows)

    output, err = clickhouse_stage._run_execute_command(_session(), "SYSTEM FLUSH LOGS")
    assert err is None
    assert output == []
    assert seen == ["SYSTEM FLUSH LOGS"]


def test_open_operational_session_fallback_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_connect(
        protocol: str,
        host: str,
        port: int,
        timeout: float,
        username: str,
        password: str,
        *,
        database: str = "default",
    ):
        _ = (protocol, host, port, timeout, username, password)
        calls.append(database)
        if database == "analytics":
            return None, "Unknown database analytics"
        return _session(database="default"), None

    monkeypatch.setattr(clickhouse_stage, "_connect_and_probe", fake_connect)
    session, err = clickhouse_stage._open_operational_session(
        "native",
        "127.0.0.1",
        9000,
        1.0,
        "default",
        "",
        "analytics",
    )
    assert session is not None
    assert err == "database 'analytics' unavailable; connected to default"
    assert calls == ["analytics", "default"]


def test_open_operational_session_no_fallback_when_database_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        clickhouse_stage,
        "_connect_and_probe",
        lambda *_args, **_kwargs: (None, "connection refused"),
    )
    session, err = clickhouse_stage._open_operational_session(
        "native",
        "127.0.0.1",
        9000,
        1.0,
        "default",
        "",
        "default",
    )
    assert session is None
    assert err == "connection refused"


def test_nxc_prefix_and_caps_suffix() -> None:
    prefix = clickhouse_stage._nxc_prefix({"host": "127.0.0.1", "port": 9000})
    assert prefix.startswith("CLICKHOUSE")
    suffix = clickhouse_stage._caps_suffix(
        {
            "read_capability": True,
            "execute_capability": False,
            "admin_capability": None,
            "database_names": ["a", "b"],
        }
    )
    assert suffix == "(read:true) (execute:false) (admin:unknown) (DBs:2)"


def test_format_detect_record_json_and_format_record_json_redacts() -> None:
    detect = json.loads(
        clickhouse_stage._format_detect_record(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "host": "127.0.0.1",
                "port": 9000,
                "protocol": "native",
                "is_clickhouse": True,
                "auth_required": False,
            },
            "json",
        )
    )
    assert detect["service"] == "clickhouse"
    assert detect["detected"] is True

    payload = json.loads(
        clickhouse_stage._format_record(
            {
                "host": "127.0.0.1",
                "port": 9000,
                "status": "valid_credentials",
                "provided_password": "secret",
                "effective_password": "secret",
                "auth_attempts": [{"username": "u"}],
            },
            "json",
        )
    )
    assert "provided_password" not in payload
    assert "effective_password" not in payload
    assert "auth_attempts" not in payload


def test_format_detail_records_for_json_and_txt() -> None:
    record = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "127.0.0.1",
        "port": 9000,
        "show_databases": True,
        "database_names": ["default"],
        "show_tables": True,
        "table_names": ["default.events"],
        "table_columns_info": [{"table": "default.events", "columns": ["id"], "error": None}],
        "table_dump_enabled": True,
        "table_dumps": [{"table": "default.events", "columns": ["id"], "rows": ['["1"]'], "error": None}],
        "table_columns": ["id"],
        "sql_command": "SELECT 1",
        "sql_attempted": True,
        "sql_ok": True,
        "sql_output": ["[1]"],
        "sql_error": None,
    }
    assert len(clickhouse_stage._format_databases_detail_records(record, "txt")) == 2
    assert len(clickhouse_stage._format_tables_detail_records(record, "txt")) == 2
    assert len(clickhouse_stage._format_table_columns_detail_records(record, "txt")) == 2
    assert len(clickhouse_stage._format_table_dump_detail_records(record, "txt")) == 3
    assert len(clickhouse_stage._format_sql_detail_records(record, "txt")) == 3

    for formatter in (
        clickhouse_stage._format_databases_detail_records,
        clickhouse_stage._format_tables_detail_records,
        clickhouse_stage._format_table_columns_detail_records,
        clickhouse_stage._format_table_dump_detail_records,
        clickhouse_stage._format_sql_detail_records,
    ):
        lines = formatter(record, "json")
        assert lines
        json.loads(lines[0])


def test_format_auth_attempt_detail_records_ignores_non_txt() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9000,
        "auth_attempts": ["bad", {"username": "a", "password": "", "ok": True}],
    }
    assert clickhouse_stage._format_auth_attempt_detail_records(record, "json") == []
    lines = clickhouse_stage._format_auth_attempt_detail_records(record, "txt")
    assert len(lines) == 1
    assert "[+] a:<empty>" in lines[0]


def test_format_sql_detail_records_skips_not_attempted() -> None:
    assert (
        clickhouse_stage._format_sql_detail_records(
            {"sql_command": "SELECT 1", "sql_attempted": False},
            "txt",
        )
        == []
    )
    assert (
        clickhouse_stage._format_sql_detail_records(
            {"sql_command": "SELECT 1", "sql_attempted": False},
            "json",
        )
        == []
    )


def test_render_colored_clickhouse_line_with_markers() -> None:
    console = _RecordingConsole()
    line = (
        "CLICKHOUSE\t127.0.0.1\t9000\t [+] default:<empty> "
        "(read:true) (execute:false) (admin:unknown) (DBs:1) (auth required:unknown)"
    )
    assert clickhouse_stage._render_colored_clickhouse_line(console, line) is True
    assert any(marker == "[+]" and color == "bright_green" for marker, color in console.paint_calls)
    assert any("(DBs:1)" in text and color == "orange" for text, color in console.paint_calls)


def test_render_colored_clickhouse_line_returns_false_for_non_clickhouse() -> None:
    console = _RecordingConsole()
    assert clickhouse_stage._render_colored_clickhouse_line(console, "OTHER\t127.0.0.1\t1\t [+] x") is False


def test_emit_line_writes_file_and_callback(tmp_path: Path) -> None:
    file_path = tmp_path / "out.txt"
    captured: list[str] = []
    with open(file_path, "w", encoding="utf-8") as out_fh:
        clickhouse_stage._emit_line(out_fh, captured.append, "line1")
    assert file_path.read_text(encoding="utf-8").strip() == "line1"
    assert captured == ["line1"]


def test_run_sql_query_once_retries_and_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_open(
        protocol: str,
        host: str,
        port: int,
        timeout: float,
        username: str,
        password: str,
        database: str,
    ):
        _ = (protocol, host, port, timeout, username, password, database)
        calls.append(1)
        if len(calls) == 1:
            return None, "connection timeout"
        return _session(), None

    monkeypatch.setattr(clickhouse_stage, "_open_operational_session", fake_open)
    monkeypatch.setattr(clickhouse_stage, "_run_sql_query", lambda *_args, **_kwargs: (["[1]"], None))
    monkeypatch.setattr(clickhouse_stage, "_close_client", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(clickhouse_stage.time, "sleep", lambda *_args, **_kwargs: None)
    output, err = clickhouse_stage._run_sql_query_once(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=1,
        protocol="native",
        username="default",
        password="",
        database="default",
        query="SELECT 1",
    )
    assert err is None
    assert output == ["[1]"]
    assert len(calls) == 2


def test_resolve_port_protocols_and_ports() -> None:
    assert clickhouse_stage._resolve_port_protocols("native", 9000, []) == [(9000, "native")]
    assert clickhouse_stage._resolve_port_protocols("http", 9000, []) == [(8123, "http")]
    assert clickhouse_stage._resolve_port_protocols("auto", 19000, []) == [(19000, "auto")]
    assert clickhouse_stage._resolve_port_protocols("native", 9000, [9000, 9000, 18123]) == [
        (9000, "native"),
        (18123, "native"),
    ]
    assert clickhouse_stage._resolve_ports("native", 9000, [9000, 8123]) == [9000, 8123]


def test_audit_clickhouse_host_with_port_fallback_returns_last_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_audit(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        defcreds: bool,
        database: str,
        protocol: str,
        show_databases: bool,
        show_tables: bool,
        show_columns: bool,
        table_targets: list[str],
        table_columns: list[str],
        dump_table_rows: bool,
        execute_command: str | None,
        sql_command: str | None,
    ) -> dict[str, object]:
        _ = (
            host,
            timeout,
            retries,
            username,
            password,
            defcreds,
            database,
            protocol,
            show_databases,
            show_tables,
            show_columns,
            table_targets,
            table_columns,
            dump_table_rows,
            execute_command,
            sql_command,
        )
        return {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": host,
            "port": port,
            "protocol": protocol,
            "is_clickhouse": False,
            "status": "fail",
            "error": f"fail-{port}",
        }

    monkeypatch.setattr(clickhouse_stage, "_audit_clickhouse_host_on_protocol", fake_audit)
    record = clickhouse_stage._audit_clickhouse_host_with_port_fallback(
        host="127.0.0.1",
        port_protocols=[(9000, "native"), (8123, "http")],
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        database="default",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )
    assert record["port"] == 8123
    assert record["status"] == "fail"


def test_audit_clickhouse_host_with_port_fallback_supports_auto_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_host(*_args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(str(kwargs["protocol"]))
        return {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": kwargs["host"],
            "port": kwargs["port"],
            "protocol": kwargs["protocol"],
            "is_clickhouse": True,
            "status": "auth_required",
            "auth_required": True,
            "error": None,
        }

    monkeypatch.setattr(clickhouse_stage, "_audit_clickhouse_host", fake_host)
    monkeypatch.setattr(
        clickhouse_stage,
        "_audit_clickhouse_host_on_protocol",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected on_protocol call")),
    )

    record = clickhouse_stage._audit_clickhouse_host_with_port_fallback(
        host="127.0.0.1",
        port_protocols=[(19000, "auto")],
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        database="default",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )
    assert calls == ["auto"]
    assert record["status"] == "auth_required"


def test_run_clickhouse_stage_validation_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "Console", _FakeConsole)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    assert (
        clickhouse_stage.run_clickhouse_stage(_base_args(timeout=0), logger=SimpleNamespace(log=lambda *_a, **_k: None))
        == 2
    )
    assert (
        clickhouse_stage.run_clickhouse_stage(
            _base_args(retries=-1), logger=SimpleNamespace(log=lambda *_a, **_k: None)
        )
        == 2
    )
    assert (
        clickhouse_stage.run_clickhouse_stage(
            _base_args(username="user", password=None),
            logger=SimpleNamespace(log=lambda *_a, **_k: None),
        )
        == 2
    )
    assert (
        clickhouse_stage.run_clickhouse_stage(
            _base_args(execute="FLUSH LOGS", sql_cmd="SELECT 1"),
            logger=SimpleNamespace(log=lambda *_a, **_k: None),
        )
        == 2
    )
    assert (
        clickhouse_stage.run_clickhouse_stage(
            _base_args(os_shell=True, sql_shell=True),
            logger=SimpleNamespace(log=lambda *_a, **_k: None),
        )
        == 2
    )


def test_run_clickhouse_stage_no_hosts_and_bad_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "Console", _FakeConsole)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: [])
    assert clickhouse_stage.run_clickhouse_stage(_base_args(), logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2

    monkeypatch.setattr(
        clickhouse_stage,
        "collect_scan_ports",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad ports")),
    )
    assert clickhouse_stage.run_clickhouse_stage(_base_args(), logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2


def test_run_clickhouse_stage_sql_shell_requires_single_target_and_txt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "Console", _FakeConsole)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1", "127.0.0.2"])

    assert (
        clickhouse_stage.run_clickhouse_stage(
            _base_args(sql_shell=True),
            logger=SimpleNamespace(log=lambda *_a, **_k: None),
        )
        == 2
    )

    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    assert (
        clickhouse_stage.run_clickhouse_stage(
            _base_args(sql_shell=True, output_format="json"),
            logger=SimpleNamespace(log=lambda *_a, **_k: None),
        )
        == 2
    )


def test_run_clickhouse_stage_sql_shell_uses_first_default_port(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[tuple[int, str]] = []
    monkeypatch.setattr(clickhouse_stage, "Console", _FakeConsole)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    def fake_audit(*_args, **kwargs):  # type: ignore[no-untyped-def]
        called.append((int(kwargs["port"]), str(kwargs["protocol"])))
        return {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": kwargs["port"],
            "protocol": kwargs["protocol"],
            "is_clickhouse": True,
            "status": "auth_required",
            "auth_required": True,
            "auth_attempts": [],
            "show_databases": False,
            "show_tables": False,
            "show_columns": False,
            "table_columns_info": [],
            "table_dump_enabled": False,
            "table_dumps": [],
            "sql_command": None,
        }

    monkeypatch.setattr(clickhouse_stage, "_audit_clickhouse_host", fake_audit)
    rc = clickhouse_stage.run_clickhouse_stage(
        _base_args(sql_shell=True),
        logger=SimpleNamespace(log=lambda *_a, **_k: None),
    )
    assert rc == 1
    assert called == [(9000, "native")]


def test_run_clickhouse_stage_calls_audit_with_port_protocols(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(clickhouse_stage, "Console", _FakeConsole)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    def fake_audit(*_args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(kwargs)
        return (1, 0, 0, 0, 0, 1)

    monkeypatch.setattr(clickhouse_stage, "audit_clickhouse_targets", fake_audit)
    exit_code = clickhouse_stage.run_clickhouse_stage(
        _base_args(debug=False, output=None),
        logger=SimpleNamespace(log=lambda *_a, **_k: None),
    )
    assert exit_code == 0
    assert len(calls) == 1
    assert calls[0]["port"] == 9000
    assert calls[0]["protocol"] == "native"
    assert "port_protocols" not in calls[0]
    assert calls[0]["suppress_timeout_status_lines"] is True


def test_audit_clickhouse_host_on_protocol_collects_details(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_connect(
        protocol: str,
        host: str,
        port: int,
        timeout: float,
        username: str,
        password: str,
        *,
        database: str = "default",
    ):
        _ = (protocol, host, port, timeout, database)
        if username == "default" and password == "":
            return None, "Code: 516. Authentication failed"
        if username == "analyst" and password == "good":
            return _session(), None
        return None, "Code: 516. Authentication failed"

    monkeypatch.setattr(clickhouse_stage, "_connect_and_probe", fake_connect)
    monkeypatch.setattr(clickhouse_stage, "_open_operational_session", lambda *_args, **_kwargs: (_session(), None))
    monkeypatch.setattr(
        clickhouse_stage,
        "_collect_capabilities",
        lambda *_args, **_kwargs: (True, False, None, 2, ["default", "analytics"], None),
    )
    monkeypatch.setattr(
        clickhouse_stage,
        "_query_readable_tables",
        lambda *_args, **_kwargs: (["default.events"], None),
    )
    monkeypatch.setattr(
        clickhouse_stage,
        "_query_table_columns",
        lambda *_args, **_kwargs: (["id"], None),
    )
    monkeypatch.setattr(
        clickhouse_stage,
        "_query_table_rows",
        lambda *_args, **_kwargs: (['["1"]'], None),
    )
    monkeypatch.setattr(
        clickhouse_stage,
        "_run_sql_query",
        lambda *_args, **_kwargs: (["[1]"], None),
    )
    monkeypatch.setattr(clickhouse_stage, "_close_client", lambda *_args, **_kwargs: None)

    record = clickhouse_stage._audit_clickhouse_host_on_protocol(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=0,
        username="analyst",
        password="good",
        defcreds=False,
        database="default",
        protocol="native",
        show_databases=True,
        show_tables=True,
        show_columns=True,
        table_targets=["default.events", "invalid table"],
        table_columns=["id"],
        dump_table_rows=True,
        execute_command=None,
        sql_command="SELECT 1",
    )
    assert record["status"] == "valid_credentials"
    assert record["sql_attempted"] is True
    assert record["sql_ok"] is True
    assert record["database_count"] == 2
    assert record["table_names"] == ["default.events"]
    assert any(str(item.get("error", "")).startswith("invalid table name:") for item in record["table_columns_info"])
    assert any(item.get("table") == "default.events" for item in record["table_dumps"])


def test_audit_clickhouse_host_on_protocol_dump_without_explicit_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_connect(
        protocol: str,
        host: str,
        port: int,
        timeout: float,
        username: str,
        password: str,
        *,
        database: str = "default",
    ):
        _ = (protocol, host, port, timeout, database)
        if username == "default" and password == "":
            return _session(), None
        return None, "Code: 516. Authentication failed"

    monkeypatch.setattr(clickhouse_stage, "_connect_and_probe", fake_connect)
    monkeypatch.setattr(clickhouse_stage, "_open_operational_session", lambda *_args, **_kwargs: (_session(), None))
    monkeypatch.setattr(
        clickhouse_stage,
        "_collect_capabilities",
        lambda *_args, **_kwargs: (True, False, False, 1, ["default"], None),
    )
    monkeypatch.setattr(
        clickhouse_stage, "_query_readable_tables", lambda *_args, **_kwargs: (["default.events"], None)
    )
    monkeypatch.setattr(
        clickhouse_stage,
        "_query_table_rows",
        lambda *_args, **_kwargs: (['["row"]'], None),
    )
    monkeypatch.setattr(clickhouse_stage, "_close_client", lambda *_args, **_kwargs: None)

    record = clickhouse_stage._audit_clickhouse_host_on_protocol(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        database="default",
        protocol="native",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=True,
        execute_command=None,
        sql_command=None,
    )
    assert record["status"] == "open_no_auth"
    assert record["table_targets"] == ["default.events"]
    assert record["table_dumps"] == [{"table": "default.events", "columns": [], "rows": ['["row"]'], "error": None}]


def test_audit_clickhouse_host_on_protocol_dump_serializes_datetime_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ts = dt.datetime(2026, 3, 11, 14, 0, 0)

    def fake_connect(
        protocol: str,
        host: str,
        port: int,
        timeout: float,
        username: str,
        password: str,
        *,
        database: str = "default",
    ):
        _ = (protocol, host, port, timeout, database)
        if username == "default" and password == "":
            return _session(), None
        return None, "Code: 516. Authentication failed"

    def fake_query_rows(_session_obj, query: str):  # type: ignore[no-untyped-def]
        if "FROM `default`.`events`" in query:
            return [[ts, b"ok"]], None
        return [], None

    monkeypatch.setattr(clickhouse_stage, "_connect_and_probe", fake_connect)
    monkeypatch.setattr(clickhouse_stage, "_open_operational_session", lambda *_args, **_kwargs: (_session(), None))
    monkeypatch.setattr(
        clickhouse_stage,
        "_collect_capabilities",
        lambda *_args, **_kwargs: (True, False, False, 1, ["default"], None),
    )
    monkeypatch.setattr(
        clickhouse_stage, "_query_readable_tables", lambda *_args, **_kwargs: (["default.events"], None)
    )
    monkeypatch.setattr(clickhouse_stage, "_query_rows", fake_query_rows)
    monkeypatch.setattr(clickhouse_stage, "_close_client", lambda *_args, **_kwargs: None)

    record = clickhouse_stage._audit_clickhouse_host_on_protocol(
        host="127.0.0.1",
        port=19000,
        timeout=1.0,
        retries=0,
        username="default",
        password="default",
        defcreds=False,
        database="default",
        protocol="native",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=True,
        execute_command=None,
        sql_command=None,
    )
    assert record["status"] == "invalid_credentials_anonymous"
    assert record["table_dumps"]
    rows = record["table_dumps"][0]["rows"]
    assert isinstance(rows, list)
    assert json.loads(rows[0]) == [ts.isoformat(), "ok"]


def test_audit_clickhouse_host_on_protocol_retries_then_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        clickhouse_stage,
        "_connect_and_probe",
        lambda *_args, **_kwargs: (None, "network unreachable"),
    )
    monkeypatch.setattr(clickhouse_stage.time, "sleep", lambda *_args, **_kwargs: None)

    record = clickhouse_stage._audit_clickhouse_host_on_protocol(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=1,
        username=None,
        password=None,
        defcreds=False,
        database="default",
        protocol="native",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )
    assert record["status"] == "fail"
    assert record["is_clickhouse"] is False
    assert record["error"] == "network unreachable"


def test_audit_clickhouse_host_on_protocol_clickhouse_like_fail_is_not_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        clickhouse_stage,
        "_connect_and_probe",
        lambda *_args, **_kwargs: (None, "Code: 102. Unexpected packet from server"),
    )

    record = clickhouse_stage._audit_clickhouse_host_on_protocol(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        database="default",
        protocol="native",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )
    assert record["status"] == "fail"
    assert record["is_clickhouse"] is False


def test_run_clickhouse_stage_sql_shell_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_console = _FakeConsole(debug=True)
    monkeypatch.setattr(clickhouse_stage, "Console", lambda debug=False: fake_console)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    monkeypatch.setattr(clickhouse_stage, "collect_scan_ports", lambda *_args, **_kwargs: [9000])
    monkeypatch.setattr(
        clickhouse_stage,
        "_audit_clickhouse_host",
        lambda *_args, **_kwargs: {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9000,
            "protocol": "native",
            "is_clickhouse": True,
            "status": "valid_credentials",
            "auth_required": True,
            "effective_username": "default",
            "effective_password": "",
            "auth_attempts": [],
            "show_databases": False,
            "show_tables": False,
            "show_columns": False,
            "table_columns_info": [],
            "table_dump_enabled": False,
            "table_dumps": [],
            "sql_command": None,
        },
    )
    monkeypatch.setattr(clickhouse_stage, "_run_sql_query_once", lambda *_args, **_kwargs: (["[1]"], None))
    inputs = iter(["SELECT 1", "exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(inputs))

    rc = clickhouse_stage.run_clickhouse_stage(
        _base_args(sql_shell=True, debug=True),
        logger=SimpleNamespace(log=lambda *_a, **_k: None),
    )
    assert rc == 0
    assert any("sql-shell ready" in msg for msg in fake_console.successes)


def test_run_clickhouse_stage_sql_shell_returns_1_on_auth_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "Console", _FakeConsole)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    monkeypatch.setattr(clickhouse_stage, "collect_scan_ports", lambda *_args, **_kwargs: [9000])
    monkeypatch.setattr(
        clickhouse_stage,
        "_audit_clickhouse_host",
        lambda *_args, **_kwargs: {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9000,
            "protocol": "native",
            "is_clickhouse": True,
            "status": "auth_required",
            "auth_required": True,
            "auth_attempts": [],
            "show_databases": False,
            "show_tables": False,
            "show_columns": False,
            "table_columns_info": [],
            "table_dump_enabled": False,
            "table_dumps": [],
            "sql_command": None,
        },
    )
    rc = clickhouse_stage.run_clickhouse_stage(
        _base_args(sql_shell=True),
        logger=SimpleNamespace(log=lambda *_a, **_k: None),
    )
    assert rc == 1


def test_run_clickhouse_stage_runtime_error_and_target_parse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "Console", _FakeConsole)
    monkeypatch.setattr(
        clickhouse_stage,
        "_load_clickhouse_driver_client",
        lambda: (_ for _ in ()).throw(RuntimeError("driver missing")),
    )
    assert clickhouse_stage.run_clickhouse_stage(_base_args(), logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2

    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(
        clickhouse_stage,
        "collect_scan_targets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad targets")),
    )
    assert clickhouse_stage.run_clickhouse_stage(_base_args(), logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2


def test_run_clickhouse_stage_debug_info_and_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_console = _FakeConsole(debug=True)
    monkeypatch.setattr(clickhouse_stage, "Console", lambda debug=False: fake_console)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    monkeypatch.setattr(
        clickhouse_stage,
        "audit_clickhouse_targets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("write failed")),
    )
    rc = clickhouse_stage.run_clickhouse_stage(
        _base_args(debug=True, output="out.txt"),
        logger=SimpleNamespace(log=lambda *_a, **_k: None),
    )
    assert rc == 2
    assert any("clickhouse audit started" in msg for msg in fake_console.infos)
    assert any("failed to process clickhouse output" in msg for msg in fake_console.errors)
