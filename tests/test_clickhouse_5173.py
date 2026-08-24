from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.clickhouse import actions, stage


class _Client:
    def __init__(self) -> None:
        self.closed = False

    def disconnect(self) -> None:
        self.closed = True


class ServerException(Exception):
    pass


ServerException.__module__ = "clickhouse_driver.errors"


def _server_error(code: int, text: str = "server error") -> ServerException:
    error = ServerException(f"Code: {code}. {text}")
    error.code = code
    return error


def _session(protocol: str = "native") -> actions._ChSession:
    return actions._ChSession(protocol, _Client(), "default", "", "default")


def test_access_denied_is_limited_not_auth_rejected() -> None:
    limited = actions._classify_clickhouse_exception(_server_error(497, "ACCESS_DENIED"), "native")
    assert limited.confirms_service is True
    assert limited.access_limited is True
    assert limited.auth_required is None
    assert actions._is_auth_error(limited) is False

    for code in (192, 193, 194, 195, 516):
        rejected = actions._classify_clickhouse_exception(_server_error(code, "authentication failed"), "native")
        assert rejected.auth_required is True
        assert rejected.access_limited is False


def test_probe_keeps_session_for_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _Client()

    def execute(_query: str) -> None:
        raise _server_error(497, "ACCESS_DENIED")

    client.execute = execute
    monkeypatch.setattr(actions, "_open_clickhouse_client", lambda *_args, **_kwargs: client)
    result = actions._connect_and_probe("native", "127.0.0.1", 9000, 1, "default", "")
    assert result.kind == "access_limited"
    assert result.session is not None
    assert result.access_limited is True
    assert client.closed is False


def test_database_fallback_uses_only_code_81(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def code_81(*_args: Any, database: str = "default", **_kwargs: Any):
        calls.append(database)
        if database == "analytics":
            return actions._probe_result(
                None,
                actions._ChProbeError(
                    "localized database error",
                    kind="server_exception",
                    confirms_service=True,
                    code=81,
                ),
            )
        return actions._probe_result(_session())

    monkeypatch.setattr(actions, "_connect_and_probe", code_81)
    session, warning = actions._open_operational_session("native", "127.0.0.1", 9000, 1, "default", "", "analytics")
    assert session is not None
    assert calls == ["analytics", "default"]
    assert "connected to default" in str(warning)

    calls.clear()
    monkeypatch.setattr(
        actions,
        "_connect_and_probe",
        lambda *_args, **_kwargs: actions._probe_result(
            None,
            actions._ChProbeError(
                "unknown database in arbitrary text",
                kind="client_error",
                code=None,
            ),
        ),
    )
    session, _warning = actions._open_operational_session("native", "127.0.0.1", 9000, 1, "default", "", "analytics")
    assert session is None


def test_server_side_limits_are_n_plus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    def query(_session: Any, sql: str):
        queries.append(sql)
        return [], None

    monkeypatch.setattr(actions, "_query_rows", query)
    actions._query_database_names(_session(), 7)
    actions._query_visible_tables(_session(), 11)
    assert queries[0].endswith("LIMIT 8")
    assert queries[1].endswith("LIMIT 12")


def test_native_sql_stream_stops_after_501st_row_and_closes() -> None:
    class Stream:
        def __init__(self) -> None:
            self.closed = False

        def __iter__(self):
            return iter([(number,) for number in range(1000)])

        def close(self) -> None:
            self.closed = True

    stream = Stream()
    client = _Client()
    client.execute_iter = lambda _query: stream
    session = actions._ChSession("native", client, "default", "", "default")
    output, error = actions._run_sql_query(session, "SELECT number FROM numbers(1000)")
    assert error is None
    assert len(output) == 501
    assert output[-1] == "<output truncated at 500 lines>"
    assert stream.closed is True


def test_http_sql_stream_context_is_closed() -> None:
    class StreamContext:
        def __init__(self) -> None:
            self.closed = False

        def __enter__(self):
            return iter([(1,), (2,)])

        def __exit__(self, *_args: Any) -> None:
            self.closed = True

    context = StreamContext()
    client = _Client()
    client.query_rows_stream = lambda _query: context
    session = actions._ChSession("http", client, "default", "", "default")
    output, error = actions._run_sql_query(session, "SELECT 1")
    assert error is None
    assert output == ["[1]", "[2]"]
    assert context.closed is True


def test_http_client_receives_both_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    module = SimpleNamespace(get_client=lambda **kwargs: captured.update(kwargs) or _Client())
    monkeypatch.setattr(actions, "_load_clickhouse_connect_module", lambda: module)
    actions._open_clickhouse_client("http", "127.0.0.1", 8123, 4.25, "default", "", "default")
    assert captured["connect_timeout"] == 4.25
    assert captured["send_receive_timeout"] == 4.25


def test_check_grant_unsupported_is_cached_and_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    def query(_session: Any, sql: str):
        queries.append(sql)
        if sql.startswith("CHECK GRANT"):
            return None, "Code: 62. Syntax error"
        return [], None

    monkeypatch.setattr(actions, "_query_rows", query)
    session = _session()
    assert actions._check_table_read_access(session, "db", "one") == (True, None)
    assert actions._check_table_read_access(session, "db", "two") == (True, None)
    assert sum(query.startswith("CHECK GRANT") for query in queries) == 1
    assert sum("LIMIT 0" in query for query in queries) == 2


def test_stable_credential_schema_removes_legacy_fields() -> None:
    record = actions._normalize_clickhouse_record_schema(
        {
            "status": "valid_credentials",
            "is_clickhouse": True,
            "attempted_credentials": 1,
            "auth_attempts": [{"username": "user", "ok": True}],
        }
    )
    assert record["credential_attempt_count"] == 1
    assert record["credential_attempts"][0]["username"] == "user"
    assert "attempted_credentials" not in record
    assert "auth_attempts" not in record


def test_auto_port_matrix_and_http_alias() -> None:
    plain = parse_args(["clickhouse", "-t", "127.0.0.1", "--protocol", "auto"])
    assert stage.build_clickhouse_plan(plain).ports == (9000, 19000, 8123, 18123)
    tls = parse_args(["clickhouse", "-t", "127.0.0.1", "--protocol", "auto", "--tls"])
    assert stage.build_clickhouse_plan(tls).ports == (9440, 8443)
    alias = parse_args(["clickhouse", "-t", "127.0.0.1", "--http"])
    assert stage._raw_protocol(alias) == "http"
    assert actions._protocol_attempt_order("auto", 8123) == ("http", "native")
    assert actions._protocol_attempt_order("auto", 9000) == ("native", "http")


def test_retry_jitter_is_injectable_and_capped() -> None:
    assert actions._retry_delay(0, jitter=lambda _low, _high: 0.8) == pytest.approx(0.16)
    assert actions._retry_delay(0, jitter=lambda _low, _high: 1.2) == pytest.approx(0.24)
    assert actions._retry_delay(9, jitter=lambda _low, _high: 1.2) == 1.5


def test_partial_action_keeps_service_identity_and_sets_operation_failure() -> None:
    record = actions._normalize_clickhouse_record_schema(
        {
            "status": "open_no_auth",
            "is_clickhouse": True,
            "partial": True,
            "partial_reasons": ["columns db.table: failed"],
            "action_statuses": {"columns": "partial"},
            "requested_operation_failure": True,
        }
    )
    assert record["status"] == "open_no_auth"
    assert record["is_clickhouse"] is True
    assert record["requested_operation_failure"] is True


def test_limited_lifecycle_skips_background_audit_but_runs_requested_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limited_error = actions._ChProbeError(
        "Code: 497. ACCESS_DENIED",
        kind="access_limited",
        confirms_service=True,
        access_limited=True,
        code=497,
    )
    session = _session()
    monkeypatch.setattr(actions, "_connect_and_probe", lambda *_args, **_kwargs: (session, limited_error))
    state = actions.ClickHouseLifecycleState()
    args = SimpleNamespace(
        retries=0,
        timeout=1.0,
        tls=False,
        insecure=False,
        tls_ca=None,
        tls_cert=None,
        tls_key=None,
        tls_server_name=None,
        proxy=None,
    )
    credential = SimpleNamespace(username=None, password=None, source="anonymous")
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=args,
        host="127.0.0.1",
        port=9000,
        credential=credential,
    )
    options = {
        "database": "default",
        "protocol": "native",
        "show_databases": False,
        "show_tables": False,
        "show_columns": False,
        "table_targets": [],
        "table_columns": [],
        "dump_table_rows": False,
        "execute_command": None,
        "sql_command": None,
        "show_databases_limit": None,
        "show_tables_limit": None,
        "show_columns_limit": None,
        "dump_row_limit": None,
    }
    detected = actions.detect_clickhouse(ctx, options)
    assert detected["status"] == "anonymous_limited"
    assert detected["auth_status"] == "limited"

    monkeypatch.setattr(
        actions,
        "_collect_capabilities",
        lambda *_args, **_kwargs: pytest.fail("background capability audit must not run"),
    )
    queries: list[str] = []
    monkeypatch.setattr(actions, "_query_rows", lambda _session, query: queries.append(query) or ([], None))
    collected = actions.collect_clickhouse_data(ctx, detected, options)
    assert queries == []
    assert collected["action_statuses"]["databases"] == "not_requested"


def test_limited_credentials_are_valid_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    state = actions.ClickHouseLifecycleState(selected_protocol="native", auth_required=True)
    limited_session = actions._ChSession("native", _Client(), "reader", "secret", "default")
    monkeypatch.setattr(
        actions,
        "_open_operational_session",
        lambda *_args, **_kwargs: (limited_session, "Code: 497. ACCESS_DENIED"),
    )
    args = SimpleNamespace(retries=0, timeout=1.0, tls=False, insecure=False, proxy=None)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=args,
        host="127.0.0.1",
        port=9000,
        credential=SimpleNamespace(username="reader", password="secret", source="provided"),
    )
    record = actions.authenticate_clickhouse(
        ctx,
        {"host": "127.0.0.1", "port": 9000, "status": "auth_required", "is_clickhouse": True},
        {"protocol": "native", "database": "default"},
    )
    assert record["status"] == "valid_credentials"
    assert record["auth_status"] == "limited"
    assert record["provided_credentials_ok"] is True
