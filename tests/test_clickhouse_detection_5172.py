from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from clickhouse_connect.driver.exceptions import DatabaseError
from clickhouse_driver.errors import (
    NetworkError,
    ServerException,
    SocketTimeoutError,
    UnexpectedPacketFromServerError,
    UnknownPacketFromServerError,
)

from redposture_core.cli_args import parse_args
from redposture_core.modules.clickhouse import actions as clickhouse
from redposture_core.modules.clickhouse import stage as clickhouse_stage
from redposture_core.stage_runtime import AuditCommandRunner, AuditCredentialRun, AuditHookContext


class _Client:
    def disconnect(self) -> None:
        return None


def _session(protocol: str = "native") -> clickhouse._ChSession:
    return clickhouse._ChSession(protocol, _Client(), "default", "", "default")


def _ctx(
    state: clickhouse.ClickHouseLifecycleState,
    *,
    retries: int = 0,
    tls: bool = False,
) -> AuditHookContext:
    return AuditHookContext(
        args=SimpleNamespace(
            timeout=0.1,
            retries=retries,
            tls=tls,
            insecure=False,
            tls_ca=None,
            tls_cert=None,
            tls_key=None,
            tls_server_name=None,
            proxy=None,
        ),
        logger=None,
        host="127.0.0.1",
        port=9000,
        credential=AuditCredentialRun(),
        lifecycle_state=state,
    )


def _options(protocol: str = "native") -> dict[str, Any]:
    return {
        "database": "default",
        "protocol": protocol,
        "show_databases": False,
        "show_tables": False,
        "show_columns": False,
        "table_targets": [],
        "table_columns": [],
        "dump_table_rows": False,
        "dump_row_limit": None,
        "execute_command": None,
        "sql_command": None,
        "show_databases_limit": None,
        "show_tables_limit": None,
        "show_columns_limit": None,
    }


@pytest.mark.parametrize(
    ("exc", "kind", "confirmed", "retryable", "auth_required"),
    [
        (UnexpectedPacketFromServerError("unexpected packet"), "protocol_mismatch", False, False, None),
        (UnknownPacketFromServerError("unknown packet"), "protocol_mismatch", False, False, None),
        (SocketTimeoutError("127.0.0.1:9000"), "transport", False, True, None),
        (NetworkError("127.0.0.1:9000"), "transport", False, True, None),
        (ServerException("Authentication failed", code=516), "auth", True, False, True),
        (ServerException("Server-side query error", code=62), "server_exception", True, False, None),
    ],
)
def test_native_driver_exceptions_keep_detection_evidence(
    exc: BaseException,
    kind: str,
    confirmed: bool,
    retryable: bool,
    auth_required: bool | None,
) -> None:
    error = clickhouse._classify_clickhouse_exception(exc, "native")

    assert error.kind == kind
    assert error.confirms_service is confirmed
    assert error.retryable is retryable
    assert error.auth_required is auth_required


def test_http_requires_canonical_clickhouse_exception_marker() -> None:
    canonical = clickhouse._classify_clickhouse_exception(
        DatabaseError("Received ClickHouse exception, code: 516, server response: Authentication failed"),
        "http",
    )
    generic = clickhouse._classify_clickhouse_exception(
        DatabaseError("HTTP driver received HTTP status 404, server response: DB::Exception Code: 516"),
        "http",
    )

    assert canonical.confirms_service is True
    assert canonical.auth_required is True
    assert generic.kind == "not_clickhouse"
    assert generic.confirms_service is False
    for text in ("Code: 102", "Code: 209", "Code: 210", "DB::Exception: Code: 516"):
        assert clickhouse._looks_like_clickhouse_error(text) is False


def test_native_protocol_mismatch_falls_back_to_http_without_native_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    tls_modes: list[bool] = []

    def fake_probe(protocol: str, *_args: Any, **_kwargs: Any):
        calls.append(protocol)
        tls_modes.append(bool(_kwargs["tls_config"].enabled))
        if protocol == "native":
            return None, clickhouse._classify_clickhouse_exception(
                UnexpectedPacketFromServerError("wrong packet"), "native"
            )
        return _session("http"), None

    monkeypatch.setattr(clickhouse, "_connect_and_probe", fake_probe)
    record = clickhouse.detect_clickhouse(
        _ctx(clickhouse.ClickHouseLifecycleState(), retries=3, tls=True),
        _options(),
    )

    assert calls == ["native", "http"]
    assert tls_modes == [True, True]
    assert record["status"] == "open_no_auth"
    assert record["protocol"] == "http"
    assert record["is_clickhouse"] is True


def test_native_transport_retries_current_protocol_without_http_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_probe(protocol: str, *_args: Any, **_kwargs: Any):
        calls.append(protocol)
        return None, clickhouse._classify_clickhouse_exception(SocketTimeoutError("target"), protocol)

    monkeypatch.setattr(clickhouse, "_connect_and_probe", fake_probe)
    monkeypatch.setattr(clickhouse.time, "sleep", lambda _delay: None)
    record = clickhouse.detect_clickhouse(
        _ctx(clickhouse.ClickHouseLifecycleState(), retries=2),
        _options(),
    )

    assert calls == ["native", "native", "native"]
    assert record["status"] == "fail"
    assert record["is_clickhouse"] is False
    assert record["operational_failure"] is True
    assert record["detection_error_kind"] == "transport"


def test_http_only_mode_never_probes_native(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_probe(protocol: str, *_args: Any, **_kwargs: Any):
        calls.append(protocol)
        return None, clickhouse._ChProbeError("HTTP 404", kind="not_clickhouse")

    monkeypatch.setattr(clickhouse, "_connect_and_probe", fake_probe)
    record = clickhouse.detect_clickhouse(
        _ctx(clickhouse.ClickHouseLifecycleState()),
        _options("http"),
    )

    assert calls == ["http"]
    assert record["status"] == "not_clickhouse"


def test_legacy_and_lifecycle_paths_share_native_to_http_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_single_protocol(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        protocol = str(kwargs.get("protocol") or _args[8])
        calls.append(protocol)
        if protocol == "native":
            return {
                "host": "127.0.0.1",
                "port": 9000,
                "protocol": "native",
                "status": "not_clickhouse",
                "is_clickhouse": False,
                "detection_error_kind": "protocol_mismatch",
                "error": "Code: 102",
            }
        return {
            "host": "127.0.0.1",
            "port": 9000,
            "protocol": "http",
            "status": "auth_required",
            "is_clickhouse": True,
            "auth_required": True,
            "error": None,
        }

    monkeypatch.setattr(clickhouse, "_audit_clickhouse_host_on_protocol", fake_single_protocol)
    record = clickhouse._audit_clickhouse_host(
        host="127.0.0.1",
        port=9000,
        timeout=0.1,
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

    assert calls == ["native", "http"]
    assert record["status"] == "auth_required"
    assert record["protocol"] == "http"


def test_confirmed_server_error_does_not_enter_deep_stage_or_render_duplicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        clickhouse,
        "_connect_and_probe",
        lambda *_args, **_kwargs: (
            None,
            clickhouse._classify_clickhouse_exception(ServerException("Query error", code=62), "native"),
        ),
    )
    args = parse_args(["clickhouse", "-t", "127.0.0.1", "--port", "9000"])
    emitted: list[str] = []
    runner = AuditCommandRunner(
        args=args,
        spec=clickhouse_stage.build_clickhouse_spec(args),
        emit_line=emitted.append,
    )

    result = runner.run_plan(clickhouse_stage.build_clickhouse_plan(args))

    assert result.detected_count == 1
    assert len([line for line in emitted if "ClickHouse Database" in line]) == 1
    assert not any("connection failed" in line for line in emitted)


def test_unconfirmed_records_are_hidden_in_txt_and_retained_in_debug_and_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mismatch = clickhouse._ChProbeError("Code: 102. Unexpected packet", kind="protocol_mismatch")
    non_service = clickhouse._ChProbeError("HTTP status 404", kind="not_clickhouse")
    monkeypatch.setattr(
        clickhouse,
        "_connect_and_probe",
        lambda protocol, *_args, **_kwargs: (None, mismatch if protocol == "native" else non_service),
    )

    txt_args = parse_args(["clickhouse", "-t", "127.0.0.1", "--port", "9000"])
    txt_lines: list[str] = []
    AuditCommandRunner(
        args=txt_args,
        spec=clickhouse_stage.build_clickhouse_spec(txt_args),
        emit_line=txt_lines.append,
    ).run_plan(clickhouse_stage.build_clickhouse_plan(txt_args))
    assert txt_lines == ["[*] No CLICKHOUSE service detected on target"]

    debug_args = parse_args(["clickhouse", "-t", "127.0.0.1", "--port", "9000", "--debug"])
    debug_lines: list[str] = []
    AuditCommandRunner(
        args=debug_args,
        spec=clickhouse_stage.build_clickhouse_spec(debug_args),
        emit_line=debug_lines.append,
    ).run_plan(clickhouse_stage.build_clickhouse_plan(debug_args))
    assert any("not a ClickHouse service" in line for line in debug_lines)

    json_args = parse_args(["clickhouse", "-t", "127.0.0.1", "--port", "9000", "--format", "json"])
    json_lines: list[str] = []
    AuditCommandRunner(
        args=json_args,
        spec=clickhouse_stage.build_clickhouse_spec(json_args),
        emit_line=json_lines.append,
    ).run_plan(clickhouse_stage.build_clickhouse_plan(json_args))
    payload = json.loads(json_lines[0])
    assert payload["status"] == "not_clickhouse"
    assert payload["is_clickhouse"] is False
    assert payload["error"] == "HTTP status 404"


def test_all_transport_failures_emit_only_aggregate_inconclusive_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport_error = clickhouse._ChProbeError(
        "connection timeout: Code: 209",
        kind="transport",
        retryable=True,
    )
    monkeypatch.setattr(
        clickhouse,
        "_connect_and_probe",
        lambda *_args, **_kwargs: (None, transport_error),
    )
    args = parse_args(["clickhouse", "-t", "127.0.0.1", "--port", "9000"])
    emitted: list[str] = []

    AuditCommandRunner(
        args=args,
        spec=clickhouse_stage.build_clickhouse_spec(args),
        emit_line=emitted.append,
    ).run_plan(clickhouse_stage.build_clickhouse_plan(args))

    assert emitted == [
        "[!] CLICKHOUSE audit inconclusive: no service confirmed; 1/1 target unreachable or failed before detection"
    ]


def test_mixed_detected_and_transport_failure_has_no_aggregate_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_error = clickhouse._ChProbeError(
        "Code: 516. Authentication failed",
        kind="auth",
        confirms_service=True,
        auth_required=True,
    )
    transport_error = clickhouse._ChProbeError(
        "connection timeout: Code: 209",
        kind="transport",
        retryable=True,
    )

    def fake_probe(_protocol: str, host: str, *_args: Any, **_kwargs: Any):
        return None, auth_error if host == "127.0.0.1" else transport_error

    monkeypatch.setattr(clickhouse, "_connect_and_probe", fake_probe)
    args = parse_args(["clickhouse", "-t", "127.0.0.1,127.0.0.2", "--port", "9000"])
    emitted: list[str] = []

    result = AuditCommandRunner(
        args=args,
        spec=clickhouse_stage.build_clickhouse_spec(args),
        emit_line=emitted.append,
    ).run_plan(clickhouse_stage.build_clickhouse_plan(args))

    assert result.detected_count == 1
    assert len([line for line in emitted if "ClickHouse Database" in line]) == 1
    assert not any("audit inconclusive" in line for line in emitted)


def test_clickhouse_spec_disables_deep_checks_without_session() -> None:
    args = parse_args(["clickhouse", "-t", "127.0.0.1"])
    spec = clickhouse_stage.build_clickhouse_spec(args)

    assert spec.suppress_undetected_records_in_text is True
    assert spec.deep_gate is not None
