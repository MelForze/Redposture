from __future__ import annotations

import argparse
import base64
import struct

import pytest

from redposture_core import stage_postgres as postgres
from redposture_core.stage_postgres import (
    _audit_postgres_host,
    _caps_suffix,
    _format_databases_detail_records,
    _format_execute_detail_records,
    _format_os_read_detail_records,
    _format_privesc_detail_records,
    _format_record,
    _format_sql_detail_records,
    _format_table_columns_detail_records,
    _format_table_dump_detail_records,
    _format_table_row_count_detail_records,
    _format_tables_detail_records,
    _merge_query_error,
    _parse_bool,
    _pg_collect_privesc_checks,
    _pg_display_table_name,
    _pg_group_table_targets,
    _pg_normalize_column_names,
    _pg_normalize_table_name,
    _pg_parse_data_row,
    _pg_parse_error,
    _pg_parse_parameter_status,
    _pg_parse_table_reference,
    _pg_quote_ident,
    _pg_quote_literal,
    _pg_try_read_server_file,
    _PgAuditError,
    _PgSession,
    _scram_client_final,
    _scram_client_first,
    audit_postgres_targets,
)


class _DummySocket:
    def __enter__(self) -> _DummySocket:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False

    def settimeout(self, timeout: float) -> None:
        _ = timeout

    def close(self) -> None:
        return


class _ProtocolSocket(_DummySocket):
    def __init__(self, payload: bytes = b"") -> None:
        self.payload = payload
        self.sent: list[bytes] = []
        self._timeout = 1.0

    def recv(self, size: int) -> bytes:
        if not self.payload:
            return b""
        chunk = self.payload[:size]
        self.payload = self.payload[size:]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def gettimeout(self) -> float:
        return self._timeout


class _ConsoleCapture:
    instances: list[_ConsoleCapture] = []

    def __init__(self, debug: bool = False) -> None:
        self.debug = debug
        self.messages: list[tuple[str, str]] = []
        type(self).instances.append(self)

    def error(self, message: str) -> None:
        self.messages.append(("error", message))

    def warn(self, message: str) -> None:
        self.messages.append(("warn", message))

    def info(self, message: str) -> None:
        self.messages.append(("info", message))

    def success(self, message: str) -> None:
        self.messages.append(("success", message))

    def plain(self, message: str, color: str | None = None) -> None:
        _ = color
        self.messages.append(("plain", message))

    def render_tagged_payload_line(self, line: str, tag: str, payload_color: str | None = None) -> bool:
        _ = (line, tag, payload_color)
        return False


def _postgres_args(**overrides: object) -> argparse.Namespace:
    data: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "retries": 0,
        "username": None,
        "password": None,
        "ports": None,
        "port": 5432,
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "output": None,
        "output_format": "txt",
        "execute": None,
        "os_read": None,
        "sql_cmd": None,
        "database": None,
        "tables": [],
        "columns": [],
        "rows": False,
        "dump": None,
        "show_columns": False,
        "show_databases": False,
        "show_tables": False,
        "os_shell": False,
        "sql_shell": False,
        "defcreds": False,
        "workers": 1,
    }
    data.update(overrides)
    return argparse.Namespace(**data)


def test_postgres_parsing_helpers_cover_error_status_and_data_rows() -> None:
    sqlstate, message = _pg_parse_error(b"SERROR\x00C28000\x00Mpermission denied\x00\x00")
    assert sqlstate == "28000"
    assert message == "permission denied"

    key, value = _pg_parse_parameter_status(b"server_version\x0016.3\x00")
    assert (key, value) == ("server_version", "16.3")
    assert _pg_parse_parameter_status(b"broken") == (None, None)

    payload = struct.pack(">h", 2) + struct.pack(">i", 3) + b"foo" + struct.pack(">i", -1)
    assert _pg_parse_data_row(payload) == ["foo", None]


def test_postgres_name_and_value_helpers_cover_valid_and_invalid_inputs() -> None:
    assert _parse_bool("yes") is True
    assert _parse_bool("off") is False
    assert _parse_bool("maybe") is None

    assert _pg_quote_literal("o'hai") == "'o''hai'"
    assert _pg_quote_ident('bad"name') == '"bad""name"'

    assert _pg_normalize_table_name("public.users") == ('"public"."users"', "public.users", None)
    assert _pg_normalize_table_name("bad-name") == (None, None, "unsupported table identifier: bad-name")

    assert _pg_parse_table_reference("appdb.public.users") == ("appdb", "public.users", None)
    assert _pg_parse_table_reference("public.users") == (None, "public.users", None)
    assert _pg_parse_table_reference("bad-name") == (None, None, "unsupported table identifier: bad-name")

    assert _pg_normalize_column_names(["id,email", "email", "created_at"]) == (
        ["id", "email", "created_at"],
        None,
    )
    assert _pg_normalize_column_names(["bad-name"]) == ([], "unsupported column identifier: bad-name")

    assert _merge_query_error(None, "first") == "first"
    assert _merge_query_error("first", "second") == "first; second"
    assert _pg_display_table_name("appdb", "public.users") == "appdb.public.users"
    assert _pg_display_table_name(None, "public.users") == "public.users"


def test_postgres_protocol_helpers_and_startup_auth_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    assert postgres._clip("abcdef", 3) == "abc"
    assert postgres._retry_delay(10) == 1.5
    assert postgres._is_timeout_error("operation timed out") is True
    assert postgres._is_connection_timeout_fail_record({"status": "fail", "error": "connection timeout"}) is True
    assert postgres._is_connection_refused_fail_record({"status": "fail", "error": "connection refused"}) is True
    assert postgres._parse_sasl_mechanisms(b"SCRAM-SHA-256\x00PLAIN\x00\x00") == ["SCRAM-SHA-256", "PLAIN"]

    with pytest.raises(ConnectionError, match="unexpected EOF"):
        postgres._recv_exact(_ProtocolSocket(b""), 1)

    read_sock = _ProtocolSocket(b"R" + struct.pack(">i", 8) + b"pong")
    assert postgres._pg_read_message(read_sock) == (b"R", b"pong")

    with pytest.raises(ValueError, match="invalid postgres message length"):
        postgres._pg_read_message(_ProtocolSocket(b"R" + struct.pack(">i", 3)))

    send_sock = _ProtocolSocket()
    postgres._pg_send_message(send_sock, b"Q", b"AB")
    postgres._pg_send_startup(send_sock, "alice", "appdb")
    postgres._pg_send_password(send_sock, "secret")
    postgres._pg_send_sasl_initial(send_sock, "SCRAM-SHA-256", "n,,n=alice,r=nonce")
    postgres._pg_send_sasl_response(send_sock, "c=biws,r=nonce")
    postgres._pg_send_query(send_sock, "select 1")
    postgres._pg_send_terminate(send_sock)
    assert send_sock.sent[0] == b"Q" + struct.pack(">i", 6) + b"AB"
    assert b"user\x00alice\x00database\x00appdb\x00" in send_sock.sent[1]
    assert send_sock.sent[2].endswith(b"secret\x00")
    assert send_sock.sent[3].startswith(b"p")
    assert send_sock.sent[4].startswith(b"p")
    assert send_sock.sent[5].endswith(b"select 1\x00")
    assert send_sock.sent[6] == b"X" + struct.pack(">i", 4)

    sends: list[tuple[str, str]] = []
    monkeypatch.setattr(
        postgres, "_pg_send_startup", lambda _sock, username, database: sends.append((username, database))
    )
    monkeypatch.setattr(postgres, "_pg_send_password", lambda _sock, password: sends.append(("password", password)))
    monkeypatch.setattr(
        postgres,
        "_pg_send_sasl_initial",
        lambda _sock, mechanism, initial_response: sends.append((mechanism, initial_response)),
    )
    monkeypatch.setattr(
        postgres, "_pg_send_sasl_response", lambda _sock, response: sends.append(("scram-final", response))
    )

    messages = iter(
        [
            (b"R", struct.pack(">i", 3)),
            (b"S", b"server_version\x0016.1\x00"),
            (b"Z", b"I"),
        ]
    )
    monkeypatch.setattr(postgres, "_pg_read_message", lambda *_args: next(messages))
    session = postgres._pg_startup_and_auth(_ProtocolSocket(), "alice", "secret", "appdb")
    assert session == postgres._PgSession(auth_required=True, auth_method="cleartext", server_version="16.1")
    assert ("password", "secret") in sends

    md5_messages = iter([(b"R", struct.pack(">i", 5) + b"salt")])
    monkeypatch.setattr(postgres, "_pg_read_message", lambda *_args: next(md5_messages))
    with pytest.raises(_PgAuditError, match="md5 authentication required") as excinfo:
        postgres._pg_startup_and_auth(_ProtocolSocket(), "alice", None, "postgres")
    assert excinfo.value.auth_required is True
    assert excinfo.value.auth_method == "md5"

    scram_messages = iter([(b"R", struct.pack(">i", 10) + b"PLAIN\x00\x00")])
    monkeypatch.setattr(postgres, "_pg_read_message", lambda *_args: next(scram_messages))
    with pytest.raises(_PgAuditError, match="unsupported SASL mechanisms"):
        postgres._pg_startup_and_auth(_ProtocolSocket(), "alice", "secret", "postgres")

    error_messages = iter([(b"E", b"C28P01\x00Mpassword authentication failed\x00\x00")])
    monkeypatch.setattr(postgres, "_pg_read_message", lambda *_args: next(error_messages))
    with pytest.raises(_PgAuditError, match="password authentication failed") as error_info:
        postgres._pg_startup_and_auth(_ProtocolSocket(), "alice", "secret", "postgres")
    assert error_info.value.sqlstate == "28P01"
    assert error_info.value.auth_required is True


def test_collect_postgres_privileges_and_query_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    bool_results = iter([(True, None), (False, None)])
    monkeypatch.setattr(postgres, "_pg_query_scalar_bool", lambda *_args, **_kwargs: next(bool_results))
    monkeypatch.setattr(postgres, "_pg_query_scalar_int", lambda *_args, **_kwargs: (2, None))
    assert postgres._collect_postgres_privileges(object()) == (True, True, True, 2, None)

    bool_results = iter([(None, "superuser denied"), (None, "program denied")])
    monkeypatch.setattr(postgres, "_pg_query_scalar_bool", lambda *_args, **_kwargs: next(bool_results))
    monkeypatch.setattr(postgres, "_pg_query_scalar_int", lambda *_args, **_kwargs: (None, "read denied"))
    assert postgres._collect_postgres_privileges(object()) == (
        None,
        None,
        None,
        None,
        "superuser denied; program denied; read denied",
    )

    monkeypatch.setattr(
        postgres,
        "_pg_query_rows",
        lambda *_args, **_kwargs: (
            [["public", "users"], ["public", ""], ["audit", "events"]],
            None,
        ),
    )
    assert postgres._pg_query_readable_tables(object()) == (["public.users", "audit.events"], None)

    monkeypatch.setattr(postgres, "_pg_query_rows", lambda *_args, **_kwargs: ([["postgres"], [None], ["appdb"]], None))
    assert postgres._pg_query_databases(object()) == (["postgres", "appdb"], None)
    assert postgres._pg_query_accessible_databases(object()) == (["postgres", "appdb"], None)


def test_postgres_os_read_prefers_pg_read_file(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    def fake_query(_sock, query: str):  # type: ignore[no-untyped-def]
        queries.append(query)
        return [["pg-host"]], None

    monkeypatch.setattr(postgres, "_pg_query_rows", fake_query)

    output, error, method, attempts = _pg_try_read_server_file(object(), "/etc/hostname")

    assert output == ["pg-host"]
    assert error is None
    assert method == "pg_read_file"
    assert attempts == [{"method": "pg_read_file", "ok": True, "error": None}]
    assert queries == ["SELECT pg_read_file('/etc/hostname')"]


def test_postgres_os_read_falls_back_to_lo_import(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    def fake_query(_sock, query: str):  # type: ignore[no-untyped-def]
        queries.append(query)
        if "pg_read_file" in query:
            return [], "permission denied"
        if "pg_switch_wal" in query:
            return [["0/1"]], None
        if "pg_ls_dir" in query:
            return [["hostname"]], None
        if "lo_import" in query:
            return [["12345"]], None
        if "lo_get" in query:
            return [["fallback-host"]], None
        if "lo_unlink" in query:
            return [["1"]], None
        return [], "unexpected"

    monkeypatch.setattr(postgres, "_pg_query_rows", fake_query)

    output, error, method, attempts = _pg_try_read_server_file(object(), "/etc/hostname")

    assert output == ["fallback-host"]
    assert error is None
    assert method == "lo_import"
    assert attempts[0]["method"] == "pg_read_file"
    assert attempts[0]["ok"] is False
    assert attempts[-1]["method"] == "lo_import"
    assert attempts[-1]["ok"] is True
    assert any("SELECT pg_ls_dir('/etc', FALSE, TRUE)" == query for query in queries)
    assert any("SELECT lo_import('/etc/hostname')" == query for query in queries)
    assert any("SELECT encode(lo_get(12345), 'escape')" == query for query in queries)


def test_postgres_os_read_reports_both_method_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_query(_sock, query: str):  # type: ignore[no-untyped-def]
        if "pg_read_file" in query:
            return [], "permission denied"
        if "lo_import" in query:
            return [], "large object denied"
        return [], None

    monkeypatch.setattr(postgres, "_pg_query_rows", fake_query)

    output, error, method, attempts = _pg_try_read_server_file(object(), "/etc/hostname")

    assert output is None
    assert method is None
    assert "pg_read_file failed: permission denied" in str(error)
    assert "lo_import failed: large object denied" in str(error)
    assert [item["method"] for item in attempts] == ["pg_read_file", "lo_import"]


@pytest.mark.parametrize(
    ("overrides", "expected_message"),
    [
        ({"timeout": 0}, "--timeout must be > 0"),
        ({"retries": -1}, "--retries must be >= 0"),
        ({"username": "alice", "password": None}, "--password is required when --username is set"),
        ({"ports": "bad"}, "failed to parse --port"),
        ({"targets": None, "hosts": None}, "postgres requires -t/--targets"),
        ({"tables": ["bad-name"]}, "unsupported table identifier: bad-name"),
        ({"columns": ["bad-name"]}, "unsupported column identifier: bad-name"),
        ({"show_columns": True}, "--show-columns requires --table"),
        ({"execute": "id", "sql_cmd": "select 1"}, "--execute cannot be combined with --sql-cmd"),
        ({"execute": "id", "os_read": "/etc/hostname"}, "--execute cannot be combined with --os-read"),
        ({"sql_cmd": "select 1", "os_read": "/etc/hostname"}, "--os-read cannot be combined with --sql-cmd"),
        ({"os_shell": True, "sql_shell": True}, "--os-shell cannot be combined with --sql-shell"),
        ({"os_shell": True, "os_read": "/etc/hostname"}, "--os-shell cannot be combined with --os-read"),
        ({"sql_shell": True, "os_read": "/etc/hostname"}, "--sql-shell cannot be combined with --os-read"),
    ],
)
def test_run_postgres_stage_validation_errors(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], expected_message: str
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(postgres, "Console", _ConsoleCapture)
    rc = postgres.run_postgres_stage(_postgres_args(**overrides), logger=object())  # type: ignore[arg-type]
    assert rc == 2
    assert any(
        expected_message in message for level, message in _ConsoleCapture.instances[-1].messages if level == "error"
    )


def test_run_postgres_stage_shell_modes_and_main_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(postgres, "Console", _ConsoleCapture)
    monkeypatch.setattr(postgres, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(postgres, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    base_record = {
        "timestamp": "2026-03-27T00:00:00Z",
        "host": "127.0.0.1",
        "port": 5432,
        "database": "postgres",
        "auth_database": "postgres",
        "is_postgres": True,
        "status": "valid_credentials",
        "auth_required": True,
        "auth_method": "cleartext",
        "effective_username": "postgres",
        "can_execute_commands": True,
        "show_databases": False,
        "database_names": [],
        "database_count": 0,
        "show_tables": False,
        "show_row_counts": False,
        "show_columns": False,
        "table_names": [],
        "table_targets": [],
        "table_columns": [],
        "table_row_counts": [],
        "table_columns_info": [],
        "table_dumps": [],
        "execute_command": None,
        "execute_attempted": False,
        "execute_ok": None,
        "execute_output": None,
        "execute_error": None,
        "sql_command": None,
        "sql_attempted": False,
        "sql_ok": None,
        "sql_output": None,
        "sql_error": None,
        "server_version": "16.0",
        "superuser": False,
        "can_read_tables": False,
        "readable_tables": 0,
        "elapsed_ms": 1,
        "error": None,
    }

    monkeypatch.setattr(postgres, "_audit_postgres_host", lambda **_kwargs: dict(base_record))
    monkeypatch.setattr(postgres, "_format_detect_record", lambda *_args, **_kwargs: "DETECT")
    monkeypatch.setattr(postgres, "_format_record", lambda *_args, **_kwargs: "SUMMARY")
    monkeypatch.setattr(postgres, "_format_databases_detail_records", lambda *_args, **_kwargs: ["DBS"])
    monkeypatch.setattr(postgres, "_format_tables_detail_records", lambda *_args, **_kwargs: ["TABLES"])
    monkeypatch.setattr(postgres, "_format_table_columns_detail_records", lambda *_args, **_kwargs: ["COLS"])
    monkeypatch.setattr(postgres, "_format_table_row_count_detail_records", lambda *_args, **_kwargs: ["ROWS"])
    monkeypatch.setattr(postgres, "_format_table_dump_detail_records", lambda *_args, **_kwargs: ["DUMP"])
    monkeypatch.setattr(
        postgres,
        "_format_execute_detail_records",
        lambda record, *_args, **_kwargs: [f"EXEC:{record['execute_command']}"],
    )
    monkeypatch.setattr(
        postgres, "_format_sql_detail_records", lambda record, *_args, **_kwargs: [f"SQL:{record['sql_command']}"]
    )

    executed_commands: list[str] = []
    monkeypatch.setattr(
        postgres,
        "_pg_execute_remote_command",
        lambda **kwargs: (executed_commands.append(str(kwargs["command"])) or ["uid=1000"], None),
    )
    sql_queries: list[str] = []
    monkeypatch.setattr(
        postgres,
        "_pg_execute_sql_query",
        lambda **kwargs: (sql_queries.append(str(kwargs["query"])) or ["1"], None),
    )
    shell_inputs = iter(["id", "exit", "select 1", "quit"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(shell_inputs))

    rc = postgres.run_postgres_stage(_postgres_args(os_shell=True), logger=object())  # type: ignore[arg-type]
    assert rc == 0
    assert executed_commands == ["id"]

    rc = postgres.run_postgres_stage(_postgres_args(sql_shell=True), logger=object())  # type: ignore[arg-type]
    assert rc == 0
    assert sql_queries == ["select 1"]

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        kwargs["emit_line"]("POSTGRES\t127.0.0.1\t5432\t[*] Postgres Database")
        return 1, 0, 0, 1, 0, 0

    monkeypatch.setattr(postgres, "audit_postgres_targets", fake_audit_targets)
    rc = postgres.run_postgres_stage(
        _postgres_args(debug=True, output_format="txt", execute=None, sql_cmd=None),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    assert captured and captured[0]["suppress_timeout_status_lines"] is False


def test_run_postgres_stage_additional_output_and_error_paths(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(postgres, "Console", _ConsoleCapture)
    monkeypatch.setattr(postgres, "collect_scan_ports", lambda *_args, **_kwargs: [5432, 15432])
    monkeypatch.setattr(
        postgres,
        "collect_scan_targets",
        lambda targets: ["127.0.0.1", "127.0.0.2"] if "hosts.txt" in str(targets) else ["127.0.0.1"],
    )

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        kwargs["emit_line"]('{"type":"detect"}')
        return 1, 0, 0, 0, 1, 0

    monkeypatch.setattr(postgres, "audit_postgres_targets", fake_audit_targets)
    rc = postgres.run_postgres_stage(
        _postgres_args(
            debug=True,
            output_format="json",
            output="postgres.json",
            password="secret",
            targets=None,
            hosts_file="hosts.txt",
            tables=["public.users,public.users", "public.audit"],
            dump=5,
            rows=True,
        ),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    assert len(captured) == 2
    assert captured[0]["username"] == "postgres"
    assert captured[0]["table_targets"] == ["public.users", "public.audit"]
    assert captured[0]["dump_row_limit"] == 5
    assert captured[0]["show_row_counts"] is True
    assert '"type":"detect"' in capsys.readouterr().out

    monkeypatch.setattr(
        postgres, "audit_postgres_targets", lambda **_kwargs: (_ for _ in ()).throw(OSError("disk full"))
    )
    rc = postgres.run_postgres_stage(_postgres_args(output="postgres.json"), logger=object())  # type: ignore[arg-type]
    assert rc == 2
    assert any(
        "failed to process postgres output: disk full" in msg
        for level, msg in _ConsoleCapture.instances[-1].messages
        if level == "error"
    )

    monkeypatch.setattr(postgres, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(postgres, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1", "127.0.0.2"])
    rc = postgres.run_postgres_stage(_postgres_args(os_shell=True), logger=object())  # type: ignore[arg-type]
    assert rc == 2
    assert any(
        "--os-shell requires exactly one target host" in msg
        for level, msg in _ConsoleCapture.instances[-1].messages
        if level == "error"
    )


def test_run_postgres_stage_multi_port_verbose_uses_single_outer_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(postgres, "Console", _ConsoleCapture)
    monkeypatch.setattr(postgres, "collect_scan_ports", lambda *_args, **_kwargs: [5432, 25432, 25433, 25434, 25435])
    monkeypatch.setattr(postgres, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    show_progress_flags: list[bool] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        show_progress_flags.append(bool(kwargs["show_progress"]))
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        kwargs["emit_line"]("POSTGRES\t127.0.0.1\t5432\t[*] Postgres Database")
        return 1, 0, 0, 1, 0, 0

    monkeypatch.setattr(postgres, "audit_postgres_targets", fake_audit_targets)

    progress_totals: list[int] = []
    progress_advanced: list[int] = []
    progress_closed = 0

    class DummyProgressBar:
        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            del enabled, leave
            progress_totals.append(total)

        def advance(self, amount: int = 1) -> None:
            progress_advanced.append(amount)

        def close(self) -> None:
            nonlocal progress_closed
            progress_closed += 1

    monkeypatch.setattr(
        postgres,
        "start_command_progress",
        lambda _args, label, total, **kwargs: DummyProgressBar(label, total, **kwargs),
    )

    rc = postgres.run_postgres_stage(
        _postgres_args(
            username="postgres",
            password="postgres",
            show_databases=True,
        ),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    assert show_progress_flags == [False, False, False, False, False]
    assert progress_totals == [5]
    assert sum(progress_advanced) == 5
    assert progress_closed == 1


def test_dump_without_table_uses_all_readable_tables(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dumped_tables: list[str] = []
    dumped_columns_queries: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 2, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_readable_tables",
        lambda *_args, **_kwargs: (["public.users", "public.audit_events"], None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_table_columns",
        lambda _sock, table_name, **_kwargs: (
            dumped_columns_queries.append(table_name) or table_name,
            ["id", "payload"],
            None,
        ),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_query_table_rows(
        _sock: object,
        table_name: str,
        *,
        columns: list[str] | None = None,
        max_rows: int = 100,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = max_rows
        assert columns is None
        dumped_tables.append(table_name)
        return table_name, ['{"ok":true}'], None

    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_rows", fake_query_table_rows)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=True,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert dumped_tables == ["public.users", "public.audit_events"]
    assert dumped_columns_queries == ["public.users", "public.audit_events"]
    assert record["table_targets"] == ["public.users", "public.audit_events"]
    assert isinstance(record["table_dumps"], list) and len(record["table_dumps"]) == 2
    assert record["table_dumps"][0]["columns"] == ["id", "payload"]


def test_dump_with_table_and_columns_uses_only_selected(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dumped: list[tuple[str, list[str] | None]] = []
    column_targets: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 1, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_readable_tables",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected")),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_query_table_columns(
        _sock: object,
        table_name: str,
        *,
        only_columns: list[str] | None = None,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = only_columns
        column_targets.append(table_name)
        return table_name, ["id"], None

    def fake_query_table_rows(
        _sock: object,
        table_name: str,
        *,
        columns: list[str] | None = None,
        max_rows: int = 100,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = max_rows
        dumped.append((table_name, columns))
        return table_name, ['{"id":1}'], None

    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_columns", fake_query_table_columns)
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_rows", fake_query_table_rows)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=["public.users"],
        table_targets_by_database={},
        table_columns=["id"],
        dump_table_rows=True,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert column_targets == []
    assert dumped == [("public.users", ["id"])]
    assert record["table_targets"] == ["public.users"]


def test_show_columns_with_dump_prints_columns_and_dump(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dumped: list[tuple[str, list[str] | None]] = []
    column_targets: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 1, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_readable_tables",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected")),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_query_table_columns(
        _sock: object,
        table_name: str,
        *,
        only_columns: list[str] | None = None,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = only_columns
        column_targets.append(table_name)
        return table_name, ["id"], None

    def fake_query_table_rows(
        _sock: object,
        table_name: str,
        *,
        columns: list[str] | None = None,
        max_rows: int = 100,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = max_rows
        dumped.append((table_name, columns))
        return table_name, ['{"id":1}'], None

    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_columns", fake_query_table_columns)
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_rows", fake_query_table_rows)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=True,
        table_targets=["public.users"],
        table_targets_by_database={},
        table_columns=["id"],
        dump_table_rows=True,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert column_targets == ["public.users"]
    assert dumped == [("public.users", ["id"])]
    table_columns_info = record.get("table_columns_info")
    assert isinstance(table_columns_info, list) and len(table_columns_info) == 1


def test_table_dump_txt_renders_columns_header_line() -> None:
    record = {
        "timestamp": "2026-03-11T00:00:00Z",
        "host": "127.0.0.1",
        "port": 5432,
        "database": "postgres",
        "table_dump_enabled": True,
        "table_columns": [],
        "table_dumps": [
            {
                "table": "public.users",
                "columns": ["id", "email"],
                "rows": ['{"id":1,"email":"admin@example.com"}'],
                "error": None,
            }
        ],
    }

    lines = _format_table_dump_detail_records(record, "txt")

    assert any("(columns:auto)" in line for line in lines)
    assert any("[id, email]" in line for line in lines)
    assert any('{"id":1,"email":"admin@example.com"}' in line for line in lines)


def test_audit_postgres_suppresses_connection_refused_when_suppression_enabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-02T00:00:00Z",
            "host": "127.0.0.1",
            "port": 5432,
            "database": "postgres",
            "is_postgres": False,
            "status": "fail",
            "auth_required": None,
            "auth_method": None,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "defcreds_enabled": False,
            "effective_username": "postgres",
            "show_databases": False,
            "database_names": None,
            "database_count": None,
            "show_tables": False,
            "show_columns": False,
            "table_names": None,
            "table_targets": [],
            "table_columns": [],
            "table_dump_enabled": False,
            "table_columns_info": [],
            "table_dumps": [],
            "execute_command": None,
            "execute_attempted": False,
            "execute_ok": None,
            "execute_output": None,
            "execute_error": None,
            "sql_command": None,
            "sql_attempted": False,
            "sql_ok": None,
            "sql_output": None,
            "sql_error": None,
            "server_version": None,
            "superuser": None,
            "can_execute_commands": None,
            "can_read_tables": None,
            "readable_tables": None,
            "elapsed_ms": None,
            "error": "[Errno 111] Connection refused",
        }

    monkeypatch.setattr("redposture_core.stage_postgres._audit_postgres_host", fake_audit)

    lines: list[str] = []
    total, open_no_auth, weak, valid, auth_required, failed = audit_postgres_targets(
        hosts=["127.0.0.1"],
        port=5432,
        timeout=0.2,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_timeout_status_lines=True,
    )

    assert (total, open_no_auth, weak, valid, auth_required, failed) == (1, 0, 0, 0, 0, 1)
    assert lines == []


def test_caps_suffix_reports_database_count_and_not_tables() -> None:
    suffix = _caps_suffix(
        {
            "superuser": False,
            "can_execute_commands": False,
            "can_read_tables": True,
            "database_count": 7,
            "database_names": None,
            "readable_tables": 99,
        }
    )

    assert "(DBs:7)" in suffix
    assert "(tables:" not in suffix


def test_defcreds_is_reported_when_anonymous_access_is_allowed(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=False, auth_method=None, server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, False, None, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert record["auth_required"] is False
    assert record["status"] == "weak_default_creds"


def test_show_tables_without_database_walks_all_accessible_databases(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    remote_calls: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, False, None, None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_databases",
        lambda *_args, **_kwargs: (["postgres", "appdb", "analytics"], None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_accessible_databases",
        lambda *_args, **_kwargs: (["postgres", "appdb"], None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_collect_database_artifacts",
        lambda _sock, **_kwargs: (
            ["postgres.public.users"],
            [],
            [{"database": "postgres", "table": "postgres.public.users", "row_count": 42, "error": None}],
            [],
            1,
            None,
        ),
    )

    def fake_remote(
        _host: str,
        _port: int,
        _timeout: float,
        _retries: int,
        _username: str,
        _password: str | None,
        database_name: str,
        **_kwargs,
    ):
        remote_calls.append(database_name)
        return (
            ["appdb.audit.events"],
            [],
            [{"database": "appdb", "table": "appdb.audit.events", "row_count": 7, "error": None}],
            [],
            1,
            None,
        )

    monkeypatch.setattr("redposture_core.stage_postgres._pg_collect_database_artifacts_remote", fake_remote)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database=None,
        show_databases=False,
        show_tables=True,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert remote_calls == ["appdb"]
    assert record["database_count"] == 3
    assert record["table_names"] == ["postgres.public.users", "appdb.audit.events"]
    assert record["table_row_counts"] == [
        {"database": "postgres", "table": "postgres.public.users", "row_count": 42, "error": None},
        {"database": "appdb", "table": "appdb.audit.events", "row_count": 7, "error": None},
    ]
    assert record["show_tables"] is True
    assert record["show_row_counts"] is False
    assert record["can_read_tables"] is True
    assert record["readable_tables"] == 2


def test_database_limits_table_enumeration_to_selected_database(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    current_calls: list[str] = []
    remote_calls: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, False, None, None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_databases",
        lambda *_args, **_kwargs: (["postgres", "appdb", "analytics"], None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_accessible_databases",
        lambda *_args, **_kwargs: (["postgres", "appdb"], None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_current(_sock, *, database_name: str, **_kwargs):
        current_calls.append(database_name)
        return (["public.accounts"], [], [], [], 1, None)

    def fake_remote(
        _host: str,
        _port: int,
        _timeout: float,
        _retries: int,
        _username: str,
        _password: str | None,
        database_name: str,
        **_kwargs,
    ):
        remote_calls.append(database_name)
        return ([f"{database_name}.public.accounts"], [], [], [], 1, None)

    monkeypatch.setattr("redposture_core.stage_postgres._pg_collect_database_artifacts", fake_current)
    monkeypatch.setattr("redposture_core.stage_postgres._pg_collect_database_artifacts_remote", fake_remote)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="appdb",
        show_databases=False,
        show_tables=True,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert current_calls == ["appdb"]
    assert remote_calls == []
    assert record["table_names"] == ["public.accounts"]
    assert record["database"] == "appdb"
    assert record["auth_database"] == "appdb"


def test_group_table_targets_accepts_database_schema_table() -> None:
    normalized_targets, grouped, error = _pg_group_table_targets(
        ["appdb.public.users", "public.sessions", "appdb.public.users"],
        None,
    )

    assert error is None
    assert normalized_targets == ["appdb.public.users", "public.sessions"]
    assert grouped == {"appdb": ["public.users"], None: ["public.sessions"]}


def test_table_rows_detail_txt_renders_row_counts() -> None:
    record = {
        "timestamp": "2026-03-11T00:00:00Z",
        "host": "127.0.0.1",
        "port": 5432,
        "show_row_counts": True,
        "table_row_counts": [
            {"table": "public.users", "row_count": 42, "error": None},
            {"table": "public.audit", "row_count": None, "error": "permission denied"},
        ],
    }

    lines = _format_table_row_count_detail_records(record, "txt")

    assert any("[*] Table Rows" in line for line in lines)
    assert any("public.users (rows:42)" in line for line in lines)
    assert any("public.audit <error:permission denied>" in line for line in lines)


def test_show_tables_txt_renders_inline_row_counts() -> None:
    record = {
        "timestamp": "2026-03-11T00:00:00Z",
        "host": "127.0.0.1",
        "port": 5432,
        "show_tables": True,
        "table_names": ["appdb.public.users", "appdb.public.audit", "appdb.public.events"],
        "table_row_counts": [
            {"table": "appdb.public.users", "row_count": 42, "error": None},
            {"table": "appdb.public.audit", "row_count": None, "error": "permission denied"},
            {"table": "appdb.public.events", "row_count": None, "error": None},
        ],
    }

    lines = _format_tables_detail_records(record, "txt")

    assert any("[*] Dump Tables" in line for line in lines)
    assert any("appdb.public.users (Rows:42)" in line for line in lines)
    assert any("appdb.public.audit <error:permission denied>" in line for line in lines)
    assert any("appdb.public.events (Rows:unknown)" in line for line in lines)


def test_rows_flag_enables_show_tables_and_inline_counts(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 1, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_accessible_databases",
        lambda *_args, **_kwargs: (["postgres"], None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_readable_tables",
        lambda *_args, **_kwargs: (["public.users"], None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_table_row_count",
        lambda _sock, table_name, **_kwargs: (table_name, 42, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database=None,
        show_databases=False,
        show_tables=False,
        show_row_counts=True,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert record["show_tables"] is True
    assert record["show_row_counts"] is True
    assert record["table_names"] == ["public.users"]
    assert record["table_row_counts"] == [
        {"database": "postgres", "table": "public.users", "row_count": 42, "error": None}
    ]
    lines = _format_tables_detail_records(record, "txt")
    assert any("public.users (Rows:42)" in line for line in lines)
    assert _format_table_row_count_detail_records(record, "txt") == []


def test_show_databases_keeps_full_inventory_while_table_walk_uses_only_accessible_databases(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    remote_calls: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 1, None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_databases",
        lambda *_args, **_kwargs: (["postgres", "appdb", "offline_db"], None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_accessible_databases",
        lambda *_args, **_kwargs: (["postgres", "appdb"], None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_collect_database_artifacts",
        lambda _sock, **_kwargs: (
            ["postgres.public.users"],
            [],
            [{"database": "postgres", "table": "postgres.public.users", "row_count": 1, "error": None}],
            [],
            1,
            None,
        ),
    )

    def fake_remote(
        _host: str,
        _port: int,
        _timeout: float,
        _retries: int,
        _username: str,
        _password: str | None,
        database_name: str,
        **_kwargs,
    ):
        remote_calls.append(database_name)
        return (
            [f"{database_name}.public.audit"],
            [],
            [{"database": database_name, "table": f"{database_name}.public.audit", "row_count": 2, "error": None}],
            [],
            1,
            None,
        )

    monkeypatch.setattr("redposture_core.stage_postgres._pg_collect_database_artifacts_remote", fake_remote)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database=None,
        show_databases=True,
        show_tables=True,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert record["database_names"] == ["postgres", "appdb", "offline_db"]
    assert remote_calls == ["appdb"]


def test_dump_with_limit_passes_limit_to_query(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    seen_limits: list[int | None] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 1, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_readable_tables",
        lambda *_args, **_kwargs: (["public.users"], None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_table_columns",
        lambda _sock, table_name, **_kwargs: (table_name, ["id"], None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_query_table_rows(
        _sock: object,
        table_name: str,
        *,
        columns: list[str] | None = None,
        max_rows: int | None = None,
    ) -> tuple[str, list[str] | None, str | None]:
        _ = columns
        seen_limits.append(max_rows)
        return table_name, ['{"id":1}'], None

    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_table_rows", fake_query_table_rows)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=True,
        dump_row_limit=5,
        execute_command=None,
        sql_command=None,
    )

    assert seen_limits == [5]
    assert record["dump_row_limit"] == 5


def test_database_prefixed_table_target_routes_to_matching_database(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    current_calls: list[str] = []
    remote_calls: list[tuple[str, list[str]]] = []

    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (False, False, True, 1, None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_query_databases",
        lambda *_args, **_kwargs: (["postgres", "appdb"], None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    def fake_current(_sock, *, database_name: str, table_targets: list[str], **_kwargs):
        current_calls.append(database_name)
        return ([], [], [], [], 0, None)

    def fake_remote(
        _host: str,
        _port: int,
        _timeout: float,
        _retries: int,
        _username: str,
        _password: str | None,
        database_name: str,
        *,
        table_targets: list[str],
        **_kwargs,
    ):
        remote_calls.append((database_name, table_targets))
        return ([], [], [], [], 0, None)

    monkeypatch.setattr("redposture_core.stage_postgres._pg_collect_database_artifacts", fake_current)
    monkeypatch.setattr("redposture_core.stage_postgres._pg_collect_database_artifacts_remote", fake_remote)

    _, grouped, error = _pg_group_table_targets(["appdb.public.users"], None)
    assert error is None

    _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database=None,
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=["appdb.public.users"],
        table_targets_by_database=grouped,
        table_columns=[],
        dump_table_rows=True,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert current_calls == []
    assert remote_calls == [("appdb", ["public.users"])]


def test_scram_client_final_avoids_zip_strict_for_py39_compat(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def forbidden_zip(*_args, **_kwargs):
        raise AssertionError("zip() should not be used in SCRAM proof generation")

    monkeypatch.setattr("redposture_core.stage_postgres.zip", forbidden_zip, raising=False)

    state, _ = _scram_client_first("postgres")
    salt_b64 = base64.b64encode(b"redposture-salt").decode("ascii")
    server_first = f"r={state.client_nonce}server,s={salt_b64},i=4096"

    final_message, server_signature = _scram_client_final(state, "postgres", server_first)

    assert final_message.startswith("c=biws,r=")
    assert ",p=" in final_message
    assert isinstance(server_signature, str) and server_signature != ""


def test_audit_postgres_handles_pg_audit_error_paths(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )

    def fake_auth_required(*_args, **_kwargs):
        raise _PgAuditError("password authentication failed", detected=True, auth_required=True, auth_method="md5")

    monkeypatch.setattr("redposture_core.stage_postgres._pg_startup_and_auth", fake_auth_required)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username="postgres",
        password="wrong",
        defcreds=False,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )

    assert record["status"] == "auth_required"
    assert record["is_postgres"] is True
    assert record["auth_method"] == "md5"
    assert record["provided_credentials"] is True

    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(_PgAuditError("not postgres", detected=False)),
    )
    fail_record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )
    assert fail_record["status"] == "fail"
    assert fail_record["is_postgres"] is False
    assert fail_record["error"] == "not postgres"


def test_audit_postgres_collects_execute_and_sql_outputs(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "redposture_core.stage_postgres.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_startup_and_auth",
        lambda *_args, **_kwargs: _PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._collect_postgres_privileges",
        lambda *_args, **_kwargs: (True, True, True, 2, None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_query_databases", lambda *_args, **_kwargs: ([], None))
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_try_execute_command",
        lambda *_args, **_kwargs: (["uid=1000(postgres)"], None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_postgres._pg_try_query_sql",
        lambda *_args, **_kwargs: (["1 | hello"], None),
    )
    monkeypatch.setattr("redposture_core.stage_postgres._pg_send_terminate", lambda *_args, **_kwargs: None)

    record = _audit_postgres_host(
        host="127.0.0.1",
        port=5432,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command="id",
        sql_command="select 1, 'hello'",
    )

    assert record["status"] == "weak_default_creds"
    assert record["execute_attempted"] is True
    assert record["execute_ok"] is True
    assert record["execute_output"] == ["uid=1000(postgres)"]
    assert record["sql_attempted"] is True
    assert record["sql_ok"] is True
    assert record["sql_output"] == ["1 | hello"]


def test_postgres_privesc_check_collector(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_bool(_sock: object, query: str) -> tuple[bool | None, str | None]:
        if "rolsuper" in query:
            return True, None
        if "pg_catalog.pg_shadow" in query:
            return True, None
        if "pg_execute_server_program" in query:
            return False, None
        if "pg_read_server_files" in query:
            return True, None
        if "pg_write_server_files" in query:
            return False, None
        if "lo_import" in query or "lo_export" in query:
            return False, None
        if "rolcreaterole" in query:
            return True, None
        if "rolcreatedb" in query:
            return False, None
        if "has_database_privilege" in query:
            return True, None
        return None, "unexpected bool query"

    monkeypatch.setattr(postgres, "_pg_query_scalar_bool", fake_bool)
    monkeypatch.setattr(postgres, "_pg_query_scalar_int", lambda *_args, **_kwargs: (2, None))
    monkeypatch.setattr(postgres, "_pg_query_rows", lambda *_args, **_kwargs: ([["public.safe_definer"]], None))

    checks, summary = _pg_collect_privesc_checks(object(), None)  # type: ignore[arg-type]
    assert len(checks) == 11
    assert checks[0]["name"] == "Superuser session"
    assert checks[1]["name"] == "pg_shadow readable"
    assert any(
        item["id"] == "security_definer_accessible" and "public.safe_definer" in item["evidence"] for item in checks
    )
    assert summary == {"critical": 3, "high": 4, "medium": 3, "unknown": 0, "total": 11}


def test_postgres_detail_and_status_renderers_cover_text_and_json_paths() -> None:
    record = {
        "timestamp": "2026-03-27T00:00:00Z",
        "host": "127.0.0.1",
        "port": 5432,
        "database": "postgres",
        "show_databases": True,
        "database_names": ["appdb", "postgres"],
        "table_columns_info": [
            {"table": "public.users", "columns": ["id", "email"], "error": None},
            {"table": "public.audit", "columns": None, "error": "permission denied"},
        ],
        "execute_command": "id",
        "execute_ok": False,
        "execute_output": None,
        "execute_error": "permission denied",
        "sql_command": "select 1",
        "sql_ok": True,
        "sql_output": ["1"],
        "sql_error": None,
        "os_read_path": "/etc/hostname",
        "os_read_attempted": True,
        "os_read_ok": True,
        "os_read_method": "pg_read_file",
        "os_read_output": ["pg-host"],
        "os_read_error": None,
        "os_read_methods": [{"method": "pg_read_file", "ok": True, "error": None}],
        "privesc_check": True,
        "privesc_summary": {"critical": 1, "high": 1, "medium": 0, "unknown": 1, "total": 3},
        "privesc_checks": [
            {
                "id": "superuser_session",
                "severity": "CRITICAL",
                "name": "Superuser session",
                "description": "full database takeover via current superuser role",
                "vulnerable": True,
                "evidence": "current_user rolsuper=True",
                "error": None,
            },
            {
                "id": "pg_read_file",
                "severity": "HIGH",
                "name": "pg_read_file()",
                "description": "arbitrary server-side file read",
                "vulnerable": False,
                "evidence": "pg_read_server_files=False",
                "error": None,
            },
        ],
        "status": "valid_credentials",
        "effective_username": "postgres",
        "provided_password": "",
        "superuser": True,
        "can_execute_commands": True,
        "can_read_tables": True,
        "readable_tables": 2,
        "database_count": 2,
    }

    db_lines = _format_databases_detail_records(record, "txt")
    assert any("[*] Dump Databases" in line for line in db_lines)
    assert any("appdb" in line for line in db_lines)
    assert any('"type": "databases_dump"' in line for line in _format_databases_detail_records(record, "json"))

    column_lines = _format_table_columns_detail_records(record, "txt")
    assert any("[*] Table Columns public.users" in line for line in column_lines)
    assert any("<error:permission denied>" in line for line in column_lines)

    execute_lines = _format_execute_detail_records(record, "txt")
    assert any("command=id" in line for line in execute_lines)
    assert any("<error:permission denied>" in line for line in execute_lines)
    assert any('"type": "execute_dump"' in line for line in _format_execute_detail_records(record, "json"))

    sql_lines = _format_sql_detail_records(record, "txt")
    assert any("query=select 1" in line for line in sql_lines)
    assert any(" 1" in line or line.endswith("\t1") for line in sql_lines)
    assert any('"type": "sql_dump"' in line for line in _format_sql_detail_records(record, "json"))

    os_read_lines = _format_os_read_detail_records(record, "txt")
    assert any("[*] OS Read" in line for line in os_read_lines)
    assert any("path=/etc/hostname" in line for line in os_read_lines)
    assert any("method=pg_read_file" in line for line in os_read_lines)
    assert any("pg-host" in line for line in os_read_lines)
    assert any('"type": "os_read_dump"' in line for line in _format_os_read_detail_records(record, "json"))

    privesc_lines = _format_privesc_detail_records(record, "txt")
    assert any("[*] PrivEsc Check" in line for line in privesc_lines)
    assert not any("critical:" in line or "result:" in line or "evidence=" in line for line in privesc_lines)
    assert any(
        "CRITICAL - Superuser session - full database takeover via current superuser role" in line
        for line in privesc_lines
    )
    assert not any("HIGH - pg_read_file()" in line for line in privesc_lines)
    privesc_debug_lines = _format_privesc_detail_records(record, "txt", debug=True)
    assert any("CRITICAL - Superuser session" in line and "result:True" in line for line in privesc_debug_lines)
    assert any(
        "HIGH - pg_read_file() - arbitrary server-side file read result:False" in line for line in privesc_debug_lines
    )
    assert any('"type": "privesc_check"' in line for line in _format_privesc_detail_records(record, "json"))

    status_line = _format_record(record, "txt")
    assert "[+] postgres:<empty>" in status_line


def test_audit_postgres_targets_emits_detect_status_and_all_detail_sections(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 5432,
            "database": "postgres",
            "is_postgres": True,
            "status": "valid_credentials",
            "auth_required": True,
            "auth_method": "cleartext",
            "provided_credentials": True,
            "provided_username": "postgres",
            "provided_password": "postgres",
            "defcreds_enabled": False,
            "effective_username": "postgres",
            "show_databases": True,
            "database_names": ["appdb"],
            "database_count": 1,
            "show_tables": True,
            "show_row_counts": False,
            "show_columns": True,
            "table_names": ["appdb.public.users"],
            "table_targets": [],
            "table_columns": [],
            "table_row_counts": [{"table": "appdb.public.users", "row_count": 42, "error": None}],
            "table_dump_enabled": True,
            "dump_row_limit": 2,
            "table_columns_info": [{"table": "appdb.public.users", "columns": ["id"], "error": None}],
            "table_dumps": [{"table": "appdb.public.users", "columns": ["id"], "rows": ['{"id":1}'], "error": None}],
            "execute_command": "id",
            "execute_attempted": True,
            "execute_ok": True,
            "execute_output": ["uid=1000"],
            "execute_error": None,
            "sql_command": "select 1",
            "sql_attempted": True,
            "sql_ok": True,
            "sql_output": ["1"],
            "sql_error": None,
            "os_read_path": "/etc/hostname",
            "os_read_attempted": True,
            "os_read_ok": True,
            "os_read_method": "pg_read_file",
            "os_read_output": ["pg-host"],
            "os_read_error": None,
            "os_read_methods": [{"method": "pg_read_file", "ok": True, "error": None}],
            "privesc_check": True,
            "privesc_summary": {"critical": 1, "high": 0, "medium": 0, "unknown": 0, "total": 1},
            "privesc_checks": [
                {
                    "id": "superuser_session",
                    "severity": "CRITICAL",
                    "name": "Superuser session",
                    "description": "full database takeover via current superuser role",
                    "vulnerable": True,
                    "evidence": "current_user rolsuper=True",
                    "error": None,
                }
            ],
            "server_version": "16.0",
            "superuser": True,
            "can_execute_commands": True,
            "can_read_tables": True,
            "readable_tables": 1,
            "elapsed_ms": 5,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.stage_postgres._audit_postgres_host", fake_audit)

    lines: list[str] = []
    total, open_no_auth, weak, valid, auth_required, failed = audit_postgres_targets(
        hosts=["127.0.0.1"],
        port=5432,
        timeout=1.0,
        retries=0,
        workers=1,
        username="postgres",
        password="postgres",
        defcreds=False,
        database="postgres",
        show_databases=True,
        show_tables=True,
        show_row_counts=False,
        show_columns=True,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=True,
        dump_row_limit=2,
        execute_command="id",
        sql_command="select 1",
        privesc_check=True,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_timeout_status_lines=False,
    )

    assert (total, open_no_auth, weak, valid, auth_required, failed) == (1, 0, 0, 1, 0, 0)
    assert any("[*] Postgres Database" in line for line in lines)
    assert any("[*] Dump Databases" in line for line in lines)
    assert any("[*] Dump Tables" in line for line in lines)
    assert any("[*] Table Columns appdb.public.users" in line for line in lines)
    assert any("[*] Dump Table appdb.public.users" in line for line in lines)
    assert any("[*] Execute Command" in line for line in lines)
    assert any("[*] SQL Query" in line for line in lines)
    assert any("[*] OS Read" in line for line in lines)
    assert any("[*] PrivEsc Check" in line for line in lines)


def test_call_audit_postgres_host_with_stage_debug_adds_stage_telemetry(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 5432,
            "is_postgres": True,
            "status": "valid_credentials",
            "auth_required": True,
            "provided_credentials": True,
            "defcreds_enabled": False,
            "error": None,
        }

    monkeypatch.setattr(postgres, "_audit_postgres_host", fake_audit)
    debug_lines: list[str] = []
    result = postgres._call_audit_postgres_host_with_stage_debug(
        "127.0.0.1",
        5432,
        1.0,
        1,
        "postgres",
        "postgres",
        False,
        "postgres",
        False,
        False,
        False,
        False,
        [],
        {},
        [],
        False,
        None,
        None,
        None,
        run_deep_checks=True,
        debug=True,
        debug_emit=debug_lines.append,
    )
    assert isinstance(result.get("stages"), list)
    assert result.get("stage_durations_ms") is not None
    assert any("stage_trace stage_name=detect_protocol" in line for line in debug_lines)


def test_audit_postgres_targets_emits_two_pass_debug_markers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_stage_call(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        defcreds: bool,
        database: str | None,
        show_databases: bool,
        show_tables: bool,
        show_row_counts: bool,
        show_columns: bool,
        table_targets: list[str],
        table_targets_by_database: dict[str | None, list[str]],
        table_columns: list[str],
        dump_table_rows: bool,
        dump_row_limit: int | None,
        execute_command: str | None,
        sql_command: str | None,
        os_read_path: str | None = None,
        privesc_check: bool = False,
        *,
        run_deep_checks: bool,
        debug: bool,
        debug_emit,
    ) -> dict[str, object]:
        _ = (
            port,
            timeout,
            retries,
            username,
            password,
            defcreds,
            database,
            show_databases,
            show_tables,
            show_row_counts,
            show_columns,
            table_targets,
            table_targets_by_database,
            table_columns,
            dump_table_rows,
            dump_row_limit,
            execute_command,
            sql_command,
            os_read_path,
            privesc_check,
            debug,
            debug_emit,
        )
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 5432,
            "is_postgres": True,
            "status": "valid_credentials",
            "auth_required": True,
            "provided_credentials": True,
            "defcreds_enabled": False,
            "show_databases": bool(run_deep_checks),
            "show_tables": False,
            "show_columns": False,
            "table_columns_info": [],
            "table_dumps": [],
            "database_names": ["appdb"] if run_deep_checks else None,
            "database_count": 1 if run_deep_checks else None,
            "error": None,
            "debug_events": [],
            "debug_events_streamed": True,
            "stages": [],
            "stage_durations_ms": {},
            "stage_attempts": {},
            "stage_failed_at": None,
        }

    monkeypatch.setattr(postgres, "_call_audit_postgres_host_with_stage_debug", fake_stage_call)
    debug_lines: list[str] = []
    emitted: list[str] = []
    totals = audit_postgres_targets(
        hosts=["127.0.0.1"],
        port=5432,
        timeout=1.0,
        retries=0,
        workers=1,
        username="postgres",
        password="postgres",
        defcreds=False,
        database="postgres",
        show_databases=True,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        debug_emit=debug_lines.append,
        show_progress=False,
    )
    assert totals == (1, 0, 0, 1, 0, 0)
    assert any("pass=1 detect start total=1" in line for line in debug_lines)
    assert any("stage2_gate=run reason=status=valid_credentials" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=1" in line for line in debug_lines)


def test_postgres_execute_and_query_helper_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    assert postgres._pg_text("a\nb") == "a\\nb"

    query_calls: list[str] = []

    def fake_query_rows(_sock: object, query: str):
        query_calls.append(query)
        if query.startswith("CREATE TEMP TABLE"):
            return [], None
        if query.startswith("COPY "):
            return [], None
        if query.startswith("SELECT line FROM"):
            return [["line-1"], [None], ["line-2"]], None
        if query.startswith("DROP TABLE IF EXISTS"):
            return [], None
        if query == "select x from t":
            return [["1", None], [], ["3", "ok"]], None
        return [], "query error"

    monkeypatch.setattr(postgres, "_pg_query_rows", fake_query_rows)
    out, err = postgres._pg_try_execute_command(object(), "id", max_lines=2)
    assert err is None
    assert out == ["line-1", "", "line-2"]
    assert any(call.startswith("DROP TABLE IF EXISTS") for call in query_calls)

    monkeypatch.setattr(postgres, "_pg_query_rows", lambda *_args, **_kwargs: ([], "boom"))
    out, err = postgres._pg_try_execute_command(object(), "id")
    assert out is None and err == "boom"

    monkeypatch.setattr(
        postgres,
        "_pg_query_rows",
        lambda *_args, **_kwargs: (
            [["1", None], [], ["3", "ok"]],
            None,
        ),
    )
    sql_out, sql_err = postgres._pg_try_query_sql(object(), "select x from t", max_rows=2)
    assert sql_err is None
    assert sql_out == ["1 | NULL", "", "<truncated:1>"]


def test_postgres_remote_command_and_sql_retry_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("redposture_core.stage_postgres._retry_delay", lambda _i: 0.0)

    class _Conn(_DummySocket):
        pass

    monkeypatch.setattr("redposture_core.stage_postgres.socket.create_connection", lambda *_a, **_k: _Conn())
    monkeypatch.setattr(postgres, "_pg_startup_and_auth", lambda *_a, **_k: _PgSession(True, "cleartext", "16.0"))
    monkeypatch.setattr(postgres, "_pg_send_terminate", lambda *_a, **_k: None)
    monkeypatch.setattr(postgres, "_pg_try_execute_command", lambda *_a, **_k: (["ok"], None))
    monkeypatch.setattr(postgres, "_pg_try_query_sql", lambda *_a, **_k: (["1"], None))

    exec_out, exec_err = postgres._pg_execute_remote_command(
        "127.0.0.1", 5432, 1.0, 0, "postgres", None, "postgres", "id"
    )
    assert exec_err is None and exec_out == ["ok"]
    sql_out, sql_err = postgres._pg_execute_sql_query(
        "127.0.0.1", 5432, 1.0, 0, "postgres", None, "postgres", "select 1"
    )
    assert sql_err is None and sql_out == ["1"]

    attempts = {"n": 0}

    def flaky_connection(*_a, **_k):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise OSError("temporary fail")
        return _Conn()

    monkeypatch.setattr("redposture_core.stage_postgres.socket.create_connection", flaky_connection)
    exec_out, exec_err = postgres._pg_execute_remote_command(
        "127.0.0.1", 5432, 1.0, 1, "postgres", None, "postgres", "id"
    )
    assert exec_err is None and exec_out == ["ok"]
    assert attempts["n"] == 2

    monkeypatch.setattr(
        postgres,
        "_pg_startup_and_auth",
        lambda *_a, **_k: (_ for _ in ()).throw(_PgAuditError("auth denied", detected=True, auth_required=True)),
    )
    exec_out, exec_err = postgres._pg_execute_remote_command(
        "127.0.0.1", 5432, 1.0, 0, "postgres", None, "postgres", "id"
    )
    assert exec_out is None and exec_err == "auth denied"


def test_postgres_table_query_helpers_and_colored_renderer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(postgres, "_pg_query_rows", lambda *_a, **_k: ([['{"id":1}']], None))
    display, rows, err = postgres._pg_query_table_rows(object(), "public.users", columns=["id"], max_rows=5)
    assert (display, rows, err) == ("public.users", ['{"id":1}'], None)

    monkeypatch.setattr(postgres, "_pg_query_rows", lambda *_a, **_k: ([], "permission denied"))
    display, rows, err = postgres._pg_query_table_rows(object(), "public.users")
    assert display == "public.users" and rows is None and err == "permission denied"

    monkeypatch.setattr(postgres, "_pg_query_scalar_int", lambda *_a, **_k: (42, None))
    assert postgres._pg_query_table_row_count(object(), "public.users") == ("public.users", 42, None)
    monkeypatch.setattr(postgres, "_pg_query_scalar_int", lambda *_a, **_k: (None, "denied"))
    assert postgres._pg_query_table_row_count(object(), "public.users") == ("public.users", None, "denied")
    assert postgres._pg_query_table_row_count(object(), "bad-name") == (
        "bad-name",
        None,
        "unsupported table identifier: bad-name",
    )

    class _Painter:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, color: str, _stream: object) -> str:
            return f"<{color}>{text}</{color}>"

        def plain(self, line: str) -> None:
            self.lines.append(line)

    painter = _Painter()
    assert postgres._render_colored_postgres_line(painter, "NOPE") is False
    assert postgres._render_colored_postgres_line(
        painter,
        "POSTGRES\t127.0.0.1\t5432\t [+] anonymous access (auth required:False) "
        "(superuser:True) (execute:False) (read:unknown) (DBs:2)",
    )
    assert painter.lines and "auth required:False" in painter.lines[0]
    assert postgres._render_colored_postgres_line(
        painter,
        "POSTGRES\t127.0.0.1\t5432\t [!] CRITICAL - COPY TO/FROM PROGRAM - OS command execution",
    )
    assert "<orange>CRITICAL - COPY TO/FROM PROGRAM - OS command execution</orange>" in painter.lines[-1]
