from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from redposture_core import stage_clickhouse as clickhouse_stage


class _DummyClient:
    pass


def _session(protocol: str = "native", username: str = "default", password: str = "", database: str = "default"):
    return clickhouse_stage._ChSession(
        protocol=protocol,
        client=_DummyClient(),
        username=username,
        password=password,
        database=database,
    )


def test_configure_clickhouse_loggers_suppresses_warning_propagation() -> None:
    logger = logging.getLogger("clickhouse_driver.connection")
    logger.setLevel(logging.WARNING)
    logger.propagate = True
    logger.handlers = []

    clickhouse_stage._configure_clickhouse_loggers()

    assert logger.propagate is False
    assert logger.level >= logging.ERROR
    assert any(isinstance(handler, logging.NullHandler) for handler in logger.handlers)


def test_build_credential_candidates_with_defcreds() -> None:
    candidates = clickhouse_stage._build_credential_candidates(None, None, True)
    assert candidates == [("default", "", "default"), ("default", "default", "default")]


def test_build_credential_candidates_with_provided_and_defcreds_deduplicates() -> None:
    candidates = clickhouse_stage._build_credential_candidates("default", "", True)
    assert candidates == [("default", "", "provided"), ("default", "default", "default")]


def test_audit_clickhouse_marks_invalid_credentials_anonymous_when_provided_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
        lambda *_args, **_kwargs: (True, False, False, 2, ["default", "analytics"], None),
    )
    monkeypatch.setattr(clickhouse_stage, "_close_client", lambda *_args, **_kwargs: None)

    record = clickhouse_stage._audit_clickhouse_host_on_protocol(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=0,
        username="admin",
        password="bad",
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

    assert record["status"] == "invalid_credentials_anonymous"
    assert int(record["attempted_credentials"]) == 1
    assert record["is_clickhouse"] is True
    assert record["provided_credentials_ok"] is False
    attempts = record.get("auth_attempts")
    assert isinstance(attempts, list)
    assert len(attempts) == 1
    assert bool(attempts[0].get("ok")) is False


def test_audit_clickhouse_defcreds_always_attempts_two_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
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
        if username == "default" and password == "default":
            return None, "Code: 516. Authentication failed"
        return None, "Code: 516. Authentication failed"

    monkeypatch.setattr(clickhouse_stage, "_connect_and_probe", fake_connect)
    monkeypatch.setattr(clickhouse_stage, "_open_operational_session", lambda *_args, **_kwargs: (_session(), None))
    monkeypatch.setattr(
        clickhouse_stage,
        "_collect_capabilities",
        lambda *_args, **_kwargs: (True, False, False, 1, ["default"], None),
    )
    monkeypatch.setattr(clickhouse_stage, "_close_client", lambda *_args, **_kwargs: None)

    record = clickhouse_stage._audit_clickhouse_host_on_protocol(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
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

    assert record["status"] == "weak_default_creds"
    assert int(record["attempted_credentials"]) == 2
    attempts = record.get("auth_attempts")
    assert isinstance(attempts, list)
    assert [f"{item.get('username')}:{item.get('password')}" for item in attempts] == [
        "default:",
        "default:default",
    ]


def test_audit_clickhouse_auth_required_when_all_credentials_fail(monkeypatch: pytest.MonkeyPatch) -> None:
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
        _ = (protocol, host, port, timeout, username, password, database)
        return None, "Code: 516. Authentication failed"

    monkeypatch.setattr(clickhouse_stage, "_connect_and_probe", fake_connect)

    record = clickhouse_stage._audit_clickhouse_host_on_protocol(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
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

    assert record["status"] == "auth_required"
    assert record["is_clickhouse"] is True
    assert int(record["attempted_credentials"]) == 2


def test_audit_clickhouse_marks_valid_credentials_when_provided_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
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
        if username == "auditor" and password == "auditor":
            return _session(username="auditor", password="auditor"), None
        return None, "Code: 516. Authentication failed"

    monkeypatch.setattr(clickhouse_stage, "_connect_and_probe", fake_connect)
    monkeypatch.setattr(
        clickhouse_stage,
        "_open_operational_session",
        lambda *_args, **_kwargs: (_session(username="auditor", password="auditor"), None),
    )
    monkeypatch.setattr(
        clickhouse_stage,
        "_collect_capabilities",
        lambda *_args, **_kwargs: (True, True, True, 3, ["default", "analytics", "billing"], None),
    )
    monkeypatch.setattr(clickhouse_stage, "_close_client", lambda *_args, **_kwargs: None)

    record = clickhouse_stage._audit_clickhouse_host_on_protocol(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=0,
        username="auditor",
        password="auditor",
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

    assert record["status"] == "valid_credentials"
    assert record["provided_credentials_ok"] is True
    assert record["effective_username"] == "auditor"


def test_audit_clickhouse_fallbacks_to_http_when_auto_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    called_protocols: list[str] = []

    def fake_single_protocol(
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
            port,
            timeout,
            retries,
            username,
            password,
            defcreds,
            database,
            show_databases,
            show_tables,
            show_columns,
            table_targets,
            table_columns,
            dump_table_rows,
            execute_command,
            sql_command,
        )
        called_protocols.append(protocol)
        if protocol == "native":
            return {
                "timestamp": "2026-03-01T00:00:00Z",
                "host": "127.0.0.1",
                "port": 9000,
                "protocol": "native",
                "is_clickhouse": False,
                "status": "fail",
                "error": "connection refused (service is not listening on target port)",
            }
        return {
            "timestamp": "2026-03-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9000,
            "protocol": "http",
            "is_clickhouse": True,
            "status": "open_no_auth",
            "auth_required": False,
            "database_count": 1,
            "database_names": ["default"],
            "read_capability": True,
            "execute_capability": False,
            "admin_capability": False,
            "error": None,
        }

    monkeypatch.setattr(clickhouse_stage, "_audit_clickhouse_host_on_protocol", fake_single_protocol)

    record = clickhouse_stage._audit_clickhouse_host(
        host="127.0.0.1",
        port=9000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        database="default",
        protocol="auto",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )

    assert called_protocols == ["native", "http"]
    assert record["protocol"] == "http"
    assert record["status"] == "open_no_auth"


def test_audit_clickhouse_fallbacks_when_first_protocol_fails_with_clickhouse_like_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called_protocols: list[str] = []

    def fake_single_protocol(
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
            port,
            timeout,
            retries,
            username,
            password,
            defcreds,
            database,
            show_databases,
            show_tables,
            show_columns,
            table_targets,
            table_columns,
            dump_table_rows,
            execute_command,
            sql_command,
        )
        called_protocols.append(protocol)
        if protocol == "native":
            return {
                "timestamp": "2026-03-01T00:00:00Z",
                "host": "127.0.0.1",
                "port": 8123,
                "protocol": "native",
                "is_clickhouse": True,
                "status": "fail",
                "auth_required": None,
                "error": "Code: 102. Unexpected packet from server",
            }
        return {
            "timestamp": "2026-03-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 8123,
            "protocol": "http",
            "is_clickhouse": True,
            "status": "auth_required",
            "auth_required": True,
            "error": None,
        }

    monkeypatch.setattr(clickhouse_stage, "_audit_clickhouse_host_on_protocol", fake_single_protocol)

    record = clickhouse_stage._audit_clickhouse_host(
        host="127.0.0.1",
        port=8123,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        database="default",
        protocol="auto",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
    )

    assert called_protocols == ["native", "http"]
    assert record["protocol"] == "http"
    assert record["status"] == "auth_required"


def test_format_record_status_variants() -> None:
    base = {
        "host": "127.0.0.1",
        "port": 9000,
        "read_capability": False,
        "execute_capability": None,
        "admin_capability": True,
        "database_count": 2,
    }

    line_anon = clickhouse_stage._format_record({**base, "status": "open_no_auth"}, "txt")
    assert "[+] anonymous access" in line_anon
    assert "(read:false)" in line_anon

    line_auth = clickhouse_stage._format_record(
        {**base, "status": "auth_required", "attempted_credentials": 2},
        "txt",
    )
    assert "authentication required (credentials invalid)" in line_auth

    line_fail = clickhouse_stage._format_record({**base, "status": "fail", "error": "connection timeout"}, "txt")
    assert "[!] connection failed" in line_fail


def test_format_detect_record_txt() -> None:
    line = clickhouse_stage._format_detect_record(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9000,
            "is_clickhouse": True,
            "auth_required": True,
        },
        "txt",
    )
    assert "[*] ClickHouse Database" in line
    assert "(auth required:True)" in line


def test_format_auth_attempt_detail_records_contains_two_lines() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9000,
        "auth_attempts": [
            {"username": "default", "password": "", "ok": True},
            {"username": "default", "password": "default", "ok": False},
        ],
    }
    lines = clickhouse_stage._format_auth_attempt_detail_records(record, "txt")
    assert len(lines) == 2
    assert "[+] default:<empty>" in lines[0]
    assert "[-] default:default" in lines[1]


def test_audit_clickhouse_targets_suppresses_timeout_and_refused_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9000,
            "protocol": "native",
            "is_clickhouse": False,
            "status": "fail",
            "auth_required": None,
            "error": "connection refused (service is not listening on target port)",
            "read_capability": None,
            "execute_capability": None,
            "admin_capability": None,
            "database_count": None,
            "database_names": None,
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

    emitted: list[str] = []
    totals = clickhouse_stage.audit_clickhouse_targets(
        hosts=["127.0.0.1"],
        port=9000,
        timeout=1.0,
        retries=0,
        workers=1,
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
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        logger=None,
        append_output=False,
        suppress_timeout_status_lines=True,
    )

    assert totals == (1, 0, 0, 0, 0, 1)
    assert emitted == []


def test_audit_clickhouse_targets_emits_detect_attempts_status_and_details(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9000,
            "protocol": "native",
            "is_clickhouse": True,
            "status": "weak_default_creds",
            "auth_required": False,
            "error": None,
            "read_capability": True,
            "execute_capability": False,
            "admin_capability": False,
            "database_count": 1,
            "database_names": ["default"],
            "auth_attempts": [
                {"username": "default", "password": "", "ok": True},
                {"username": "default", "password": "default", "ok": False},
            ],
            "effective_username": "default",
            "effective_password": "",
            "show_databases": True,
            "show_tables": False,
            "show_columns": False,
            "table_columns_info": [],
            "table_dump_enabled": False,
            "table_dumps": [],
            "sql_command": None,
        }

    monkeypatch.setattr(clickhouse_stage, "_audit_clickhouse_host", fake_audit)

    emitted: list[str] = []
    clickhouse_stage.audit_clickhouse_targets(
        hosts=["127.0.0.1"],
        port=9000,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=True,
        database="default",
        protocol="native",
        show_databases=True,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        logger=None,
        append_output=False,
    )

    assert "[*] ClickHouse Database" in emitted[0]
    assert "[+] default:<empty>" in emitted[1]
    assert "[-] default:default" in emitted[2]
    assert "[+] default:<empty>" in emitted[3]
    assert any("[*] Dump Databases" in line for line in emitted)


def test_audit_clickhouse_targets_skips_auth_required_status_when_attempts_are_printed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9000,
            "protocol": "native",
            "is_clickhouse": True,
            "status": "auth_required",
            "auth_required": True,
            "attempted_credentials": 1,
            "auth_attempts": [{"username": "default", "password": "bad", "ok": False}],
            "error": None,
            "show_databases": False,
            "show_tables": False,
            "show_columns": False,
            "table_columns_info": [],
            "table_dump_enabled": False,
            "table_dumps": [],
            "sql_command": None,
        }

    monkeypatch.setattr(clickhouse_stage, "_audit_clickhouse_host", fake_audit)

    emitted: list[str] = []
    clickhouse_stage.audit_clickhouse_targets(
        hosts=["127.0.0.1"],
        port=9000,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password="bad",
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
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        logger=None,
        append_output=False,
    )

    assert any("[*] ClickHouse Database" in line for line in emitted)
    assert any("[-] default:bad" in line for line in emitted)
    assert not any("authentication required (credentials invalid)" in line for line in emitted)


def test_audit_clickhouse_targets_skips_plain_auth_required_status_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9000,
            "protocol": "native",
            "is_clickhouse": True,
            "status": "auth_required",
            "auth_required": True,
            "attempted_credentials": 0,
            "auth_attempts": [],
            "error": None,
            "show_databases": False,
            "show_tables": False,
            "show_columns": False,
            "table_columns_info": [],
            "table_dump_enabled": False,
            "table_dumps": [],
            "sql_command": None,
        }

    monkeypatch.setattr(clickhouse_stage, "_audit_clickhouse_host", fake_audit)

    emitted: list[str] = []
    clickhouse_stage.audit_clickhouse_targets(
        hosts=["127.0.0.1"],
        port=9000,
        timeout=1.0,
        retries=0,
        workers=1,
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
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        logger=None,
        append_output=False,
    )

    assert len(emitted) == 1
    assert "ClickHouse Database" in emitted[0]
    assert "(auth required:True)" in emitted[0]
    assert not any("authentication required" in line for line in emitted)


def test_resolve_ports_default_behavior() -> None:
    assert clickhouse_stage._resolve_ports("native", 9000, []) == [9000]
    assert clickhouse_stage._resolve_ports("auto", 9000, []) == [9000]
    assert clickhouse_stage._resolve_ports("http", 9000, []) == [8123]
    assert clickhouse_stage._resolve_ports("native", 19000, []) == [19000]
    assert clickhouse_stage._resolve_port_protocols("native", 9000, []) == [(9000, "native")]


def test_audit_clickhouse_host_with_port_fallback_stops_after_first_detect(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, str]] = []

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
            show_databases,
            show_tables,
            show_columns,
            table_targets,
            table_columns,
            dump_table_rows,
            execute_command,
            sql_command,
        )
        calls.append((port, protocol))
        if port == 9000:
            return {
                "timestamp": "2026-03-01T00:00:00Z",
                "host": "127.0.0.1",
                "port": port,
                "protocol": protocol,
                "is_clickhouse": True,
                "status": "auth_required",
                "auth_required": True,
                "error": None,
            }
        return {
            "timestamp": "2026-03-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": port,
            "protocol": protocol,
            "is_clickhouse": False,
            "status": "fail",
            "auth_required": None,
            "error": "connection failed",
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

    assert calls == [(9000, "native")]
    assert record["is_clickhouse"] is True
    assert record["port"] == 9000


def test_run_clickhouse_stage_rejects_show_columns_without_table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        port=9000,
        ports=None,
        protocol="native",
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        database="default",
        show_databases=False,
        show_tables=False,
        show_columns=True,
        tables=None,
        dump=False,
        columns=None,
        sql_cmd=None,
        sql_shell=False,
        output=None,
        output_format="txt",
        defcreds=False,
        log=None,
    )

    assert clickhouse_stage.run_clickhouse_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2


def test_run_clickhouse_stage_rejects_sql_shell_with_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_connect_module", lambda: object)
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        port=9000,
        ports=None,
        protocol="native",
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        database="default",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        tables=None,
        dump=False,
        columns=None,
        sql_cmd=None,
        sql_shell=True,
        output="out.txt",
        output_format="txt",
        defcreds=False,
        log=None,
    )

    assert clickhouse_stage.run_clickhouse_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2


def test_call_audit_clickhouse_host_with_stage_debug_adds_stage_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9000,
            "protocol": "native",
            "is_clickhouse": True,
            "status": "valid_credentials",
            "auth_required": True,
            "error": None,
        }

    monkeypatch.setattr(clickhouse_stage, "_audit_clickhouse_host", fake_audit)
    debug_lines: list[str] = []
    result = clickhouse_stage._call_audit_clickhouse_host_with_stage_debug(
        "127.0.0.1",
        9000,
        1.0,
        1,
        "default",
        "default",
        False,
        "default",
        "native",
        False,
        False,
        False,
        [],
        [],
        False,
        None,
        None,
        port_protocols=None,
        run_deep_checks=True,
        debug=True,
        debug_emit=debug_lines.append,
    )
    assert isinstance(result.get("stages"), list)
    assert result.get("stage_attempts") is not None
    assert any("stage_trace stage_name=detect_protocol" in line for line in debug_lines)


def test_run_clickhouse_stage_processes_all_ports_without_short_circuit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(clickhouse_stage, "_configure_clickhouse_loggers", lambda: None)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object())
    monkeypatch.setattr(clickhouse_stage, "collect_scan_ports", lambda _ports: [9000, 9001, 9002])
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda _targets: ["127.0.0.1"])
    monkeypatch.setattr(
        clickhouse_stage,
        "_resolve_port_protocols",
        lambda _proto, _port, _parsed: [(9000, "native"), (9001, "native"), (9002, "native")],
    )

    called_ports: list[int] = []

    def fake_audit_clickhouse_targets(*_args, **kwargs):  # type: ignore[no-untyped-def]
        called_ports.append(int(kwargs["port"]))
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (1, 0, 0, 0, 0, 0)

    monkeypatch.setattr(clickhouse_stage, "audit_clickhouse_targets", fake_audit_clickhouse_targets)

    progress_totals: list[int] = []
    progress_advances: list[int] = []

    class _FakeProgressBar:
        def __init__(self, _name: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            progress_totals.append(int(total))

        def advance(self, count: int = 1) -> None:
            progress_advances.append(int(count))

        def close(self) -> None:
            return

    monkeypatch.setattr(
        clickhouse_stage,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        port=9000,
        ports="9000,9001,9002",
        http=False,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        database="default",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        tables=None,
        columns=None,
        dump=False,
        execute=None,
        sql_cmd=None,
        os_shell=False,
        sql_shell=False,
        output=None,
        output_format="txt",
        log=None,
    )

    rc = clickhouse_stage.run_clickhouse_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert called_ports == [9000, 9001, 9002]
    assert progress_totals == [3]
    assert progress_advances == [1, 1, 1]


def test_run_clickhouse_stage_multi_port_verbose_uses_single_global_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(clickhouse_stage, "_configure_clickhouse_loggers", lambda: None)
    monkeypatch.setattr(clickhouse_stage, "_load_clickhouse_driver_client", lambda: object())
    monkeypatch.setattr(clickhouse_stage, "collect_scan_ports", lambda _ports: [9000, 9001, 9002])
    monkeypatch.setattr(clickhouse_stage, "collect_scan_targets", lambda _targets: ["127.0.0.1"])
    monkeypatch.setattr(
        clickhouse_stage,
        "_resolve_port_protocols",
        lambda _proto, _port, _parsed: [(9000, "native"), (9001, "native"), (9002, "native")],
    )

    show_progress_flags: list[bool] = []

    def fake_audit_clickhouse_targets(*_args, **kwargs):  # type: ignore[no-untyped-def]
        show_progress_flags.append(bool(kwargs["show_progress"]))
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (1, 0, 0, 1, 0, 0)

    monkeypatch.setattr(clickhouse_stage, "audit_clickhouse_targets", fake_audit_clickhouse_targets)

    progress_totals: list[int] = []
    progress_advances: list[int] = []

    class _FakeProgressBar:
        def __init__(self, _name: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            progress_totals.append(int(total))

        def advance(self, count: int = 1) -> None:
            progress_advances.append(int(count))

        def close(self) -> None:
            return

    monkeypatch.setattr(
        clickhouse_stage,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        username="default",
        password="default",
        defcreds=False,
        port=9000,
        ports="9000,9001,9002",
        http=False,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        database="default",
        show_databases=True,
        show_tables=False,
        show_columns=False,
        tables=None,
        columns=None,
        dump=False,
        execute=None,
        sql_cmd=None,
        os_shell=False,
        sql_shell=False,
        output=None,
        output_format="txt",
        log=None,
    )

    rc = clickhouse_stage.run_clickhouse_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert show_progress_flags == [False, False, False]
    assert progress_totals == [3]
    assert progress_advances == [1, 1, 1]


def test_audit_clickhouse_targets_emits_two_pass_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_stage_call(
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
        *,
        port_protocols: list[tuple[int, str]] | None,
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
            protocol,
            show_databases,
            show_tables,
            show_columns,
            table_targets,
            table_columns,
            dump_table_rows,
            execute_command,
            sql_command,
            port_protocols,
            debug,
            debug_emit,
        )
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 9000,
            "protocol": "native",
            "is_clickhouse": True,
            "status": "valid_credentials",
            "auth_required": True,
            "show_databases": bool(run_deep_checks),
            "database_names": ["default"] if run_deep_checks else None,
            "database_count": 1 if run_deep_checks else None,
            "auth_attempts": [],
            "table_columns_info": [],
            "table_dumps": [],
            "error": None,
            "debug_events": [],
            "debug_events_streamed": True,
            "stages": [],
            "stage_durations_ms": {},
            "stage_attempts": {},
            "stage_failed_at": None,
        }

    monkeypatch.setattr(clickhouse_stage, "_call_audit_clickhouse_host_with_stage_debug", fake_stage_call)
    debug_lines: list[str] = []
    emitted: list[str] = []
    totals = clickhouse_stage.audit_clickhouse_targets(
        hosts=["127.0.0.1"],
        port=9000,
        timeout=1.0,
        retries=0,
        workers=1,
        username="default",
        password="default",
        defcreds=False,
        database="default",
        protocol="native",
        show_databases=True,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        execute_command=None,
        sql_command=None,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        logger=None,
        append_output=False,
        debug_emit=debug_lines.append,
        show_progress=False,
    )
    assert totals == (1, 0, 0, 1, 0, 0)
    assert any("pass=1 detect start total=1" in line for line in debug_lines)
    assert any("stage2_gate=run reason=status=valid_credentials" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=1" in line for line in debug_lines)


def test_clickhouse_helper_predicates_and_close_client() -> None:
    assert clickhouse_stage._friendly_error_from_exception(TimeoutError("timed out")) == "connection timeout"
    assert "connection refused" in clickhouse_stage._friendly_error_from_exception(
        OSError("[Errno 111] Connection refused")
    )
    assert clickhouse_stage._is_timeout_error("request timeout") is True
    assert clickhouse_stage._is_connection_refused_error("connection refused by peer") is True
    assert clickhouse_stage._is_connection_timeout_fail_record({"status": "fail", "error": "timeout"}) is True
    assert (
        clickhouse_stage._is_connection_refused_fail_record({"status": "fail", "error": "connection refused"}) is True
    )

    assert clickhouse_stage._should_emit_status_line({"status": "open_no_auth"}, "txt") is True
    assert clickhouse_stage._should_emit_status_line({"status": "auth_required"}, "txt") is False
    assert (
        clickhouse_stage._should_emit_status_line(
            {"status": "auth_required", "attempted_credentials": 1, "auth_attempts": [{"ok": False}]},
            "txt",
        )
        is False
    )
    assert clickhouse_stage._should_emit_status_line({"status": "auth_required"}, "json") is True

    assert clickhouse_stage._is_auth_error("Code: 516. Authentication failed") is True
    assert clickhouse_stage._looks_like_clickhouse_error("DB::Exception: Code: 102") is True

    class _NativeClient:
        closed = False

        def disconnect(self) -> None:
            self.closed = True

    class _HttpClient:
        closed = False

        def close(self) -> None:
            self.closed = True

    native = _NativeClient()
    http = _HttpClient()
    clickhouse_stage._close_client("native", native)
    clickhouse_stage._close_client("http", http)
    assert native.closed is True
    assert http.closed is True


def test_clickhouse_normalization_and_query_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    assert clickhouse_stage._normalize_table_targets(["db.users,db.users", "db.audit"]) == ["db.users", "db.audit"]
    assert clickhouse_stage._split_table_name("users", "default") == ("default", "users")
    assert clickhouse_stage._split_table_name("app.users", "default") == ("app", "users")
    assert clickhouse_stage._split_table_name("bad-name", "default") == (None, None)

    rows_iter = iter(
        [
            ([["default"], [], ["analytics"]], None),
            ([["default", "users"], ["bad"], ["analytics", "events"]], None),
            ([["id"], ["email"]], None),
            ([["id"], ["email"], ["skip"]], None),
        ]
    )
    monkeypatch.setattr(clickhouse_stage, "_query_rows", lambda *_args, **_kwargs: next(rows_iter))

    session = _session()
    assert clickhouse_stage._query_database_names(session) == (["default", "analytics"], None)
    assert clickhouse_stage._query_readable_tables(session) == (["default.users", "analytics.events"], None)
    assert clickhouse_stage._query_table_columns(session, "default", "users", only_columns=None) == (
        ["id", "email"],
        None,
    )
    assert clickhouse_stage._query_table_columns(session, "default", "users", only_columns=["email"]) == (
        ["email"],
        None,
    )


def test_clickhouse_capability_and_exec_sql_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    assert clickhouse_stage._normalize_execute_command(" id; ") == "id"
    assert clickhouse_stage._quote_sql_literal("a'b\\c") == "'a\\'b\\\\c'"
    assert "executable(" in clickhouse_stage._build_os_exec_query("id")

    call_sql: list[str] = []

    def fake_query_rows(_session: object, sql: str):
        call_sql.append(sql)
        if sql.startswith("SELECT name FROM system.databases"):
            return [["default"]], None
        if sql.startswith("SHOW GRANTS"):
            return [["GRANT SELECT ON *.*"], ["GRANT ACCESS MANAGEMENT ON *.*"]], None
        if sql == "SELECT name FROM system.tables LIMIT 1":
            return [["users"]], None
        if "redposture_exec_probe" in sql:
            return [["ok"]], None
        if sql == "select 1":
            return [["1"], ["2"], ["3"]], None
        if sql == "SYSTEM FLUSH LOGS":
            return [["ok"]], None
        return [], "oops"

    monkeypatch.setattr(clickhouse_stage, "_query_rows", fake_query_rows)
    session = _session()
    read_cap, exec_cap, admin_cap, db_count, db_names, cap_error = clickhouse_stage._collect_capabilities(session)
    assert (read_cap, exec_cap, admin_cap, db_count, db_names, cap_error) == (
        True,
        True,
        True,
        1,
        ["default"],
        None,
    )

    sql_out, sql_err = clickhouse_stage._run_sql_query(session, "select 1", max_lines=2)
    assert sql_err is None
    assert sql_out[-1] == "<output truncated at 2 lines>"

    exec_out, exec_err = clickhouse_stage._run_execute_command(session, "SYSTEM FLUSH LOGS", max_lines=1)
    assert exec_err is None
    assert exec_out[-1] == "<output truncated at 1 lines>"

    empty_out, empty_err = clickhouse_stage._run_execute_command(session, "   ")
    assert empty_out == []
    assert empty_err == "empty command"

    # exercise operational session fallback to default DB
    connect_calls: list[str] = []

    def fake_connect_and_probe(
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
        connect_calls.append(database)
        if database == "analytics":
            return None, "unknown database analytics"
        return _session(database="default"), None

    monkeypatch.setattr(clickhouse_stage, "_connect_and_probe", fake_connect_and_probe)
    op_session, op_error = clickhouse_stage._open_operational_session(
        "native",
        "127.0.0.1",
        9000,
        1.0,
        "default",
        "",
        "analytics",
    )
    assert op_session is not None
    assert "connected to default" in str(op_error)
    assert connect_calls == ["analytics", "default"]


def test_render_colored_clickhouse_line_smoke() -> None:
    class _Painter:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, color: str, _stream: object) -> str:
            return f"<{color}>{text}</{color}>"

        def plain(self, line: str) -> None:
            self.lines.append(line)

    painter = _Painter()
    assert clickhouse_stage._render_colored_clickhouse_line(painter, "NOPE") is False
    rendered = clickhouse_stage._render_colored_clickhouse_line(
        painter,
        "CLICKHOUSE\t127.0.0.1\t9000\t [+] anonymous access (auth required:False) "
        "(read:true) (execute:false) (admin:unknown) (DBs:2)",
    )
    assert rendered is True
    assert painter.lines and "auth required:False" in painter.lines[0]
