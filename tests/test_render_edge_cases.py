"""Render-layer edge-case unit tests across modules.

Covers status-fallback paths, missing/empty record fields, JSON-vs-txt switching,
unknown-status defaults, and color-rendering edge cases. Each test targets one
narrow branch in the per-module `_format_record` / `_format_detect_record`
helpers that historically only ran via integration paths.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import redposture_core.stage_clickhouse as clickhouse_stage
import redposture_core.stage_consul as consul_stage
import redposture_core.stage_elastic as elastic_stage
import redposture_core.stage_etcd as etcd_stage
import redposture_core.stage_gitlab as gitlab_stage
import redposture_core.stage_grafana as grafana_stage
import redposture_core.stage_grpc as grpc_stage

# ---------------------------------------------------------------------------
# clickhouse._format_record — every status branch
# ---------------------------------------------------------------------------


def _ch_record(**kw: Any) -> dict[str, Any]:
    base = {"target": "127.0.0.1", "port": 9000, "status": kw.pop("status", "fail")}
    base.update(kw)
    return base


def test_clickhouse_format_record_json_drops_credential_fields() -> None:
    rec = _ch_record(
        status="valid_credentials",
        provided_password="secret",
        effective_password="secret",
        auth_attempts=[{"username": "x"}],
        effective_username="default",
    )
    out = clickhouse_stage._format_record(rec, "json")
    payload = json.loads(out)
    assert "provided_password" not in payload
    assert "effective_password" not in payload
    assert "auth_attempts" not in payload
    assert payload["status"] == "valid_credentials"
    assert payload["effective_username"] == "default"


def test_clickhouse_open_no_auth_uses_detect_marker_only() -> None:
    record = _ch_record(
        status="open_no_auth",
        host="127.0.0.1",
        is_clickhouse=True,
        auth_required=False,
    )
    assert clickhouse_stage._format_record(record, "txt") == ""
    detect_line = clickhouse_stage._format_detect_record(record, "txt")
    assert "[*] ClickHouse Database" in detect_line
    assert "(auth required:False)" in detect_line


def test_clickhouse_format_record_weak_default_creds_uses_effective_user() -> None:
    out = clickhouse_stage._format_record(
        _ch_record(status="weak_default_creds", effective_username="root", effective_password="root"),
        "txt",
    )
    assert "root:root" in out
    assert "[+]" in out


def test_clickhouse_format_record_invalid_creds_anonymous() -> None:
    out = clickhouse_stage._format_record(_ch_record(status="invalid_credentials_anonymous"), "txt")
    assert "[-]" in out
    assert "credentials invalid" in out
    assert "anonymous access" in out


def test_clickhouse_format_record_auth_required_with_attempts_marks_invalid() -> None:
    out = clickhouse_stage._format_record(
        _ch_record(status="auth_required", attempted_credentials=3),
        "txt",
    )
    assert "credentials invalid" in out


def test_clickhouse_format_record_auth_required_no_attempts_is_plain() -> None:
    out = clickhouse_stage._format_record(_ch_record(status="auth_required"), "txt")
    assert "credentials invalid" not in out
    assert "authentication required" in out


def test_clickhouse_format_record_fail_with_error_shows_err_suffix() -> None:
    out = clickhouse_stage._format_record(
        _ch_record(status="fail", error="connection refused"),
        "txt",
    )
    assert "[!]" in out
    assert "connection failed" in out
    assert "err=connection refused" in out


def test_clickhouse_format_record_fail_without_error_omits_err_suffix() -> None:
    out = clickhouse_stage._format_record(_ch_record(status="fail"), "txt")
    assert "err=" not in out
    assert "connection failed" in out


def test_clickhouse_format_record_unknown_status_falls_back_to_fail_marker() -> None:
    out = clickhouse_stage._format_record(_ch_record(status="some_new_state"), "txt")
    assert "[!]" in out


def test_clickhouse_format_record_status_default_when_missing() -> None:
    rec = {"target": "127.0.0.1", "port": 9000}
    out = clickhouse_stage._format_record(rec, "txt")
    # Missing status defaults to 'fail' per the str(record.get('status') or 'fail') idiom.
    assert "[!]" in out


# ---------------------------------------------------------------------------
# elastic — JSON shape + detect record
# ---------------------------------------------------------------------------


def test_elastic_format_detect_record_json_normalizes_to_detect_shape() -> None:
    # _format_detect_record transforms input record into a detect-payload shape
    # (type/service/port/detected/auth_required/version) rather than passing it through.
    rec = {"target": "127.0.0.1", "port": 9200, "status": "open_no_auth", "version": "8.10"}
    payload = json.loads(elastic_stage._format_detect_record(rec, "json"))
    assert payload["type"] == "detect"
    assert payload["service"] == "elastic"
    assert payload["port"] == 9200


def test_elastic_format_record_fail_marker_with_error() -> None:
    rec = {"target": "127.0.0.1", "port": 9200, "status": "fail", "error": "tls: unknown ca"}
    out = elastic_stage._format_record(rec, "txt")
    assert "[!]" in out or "[-]" in out
    # error text should be referenced
    assert "tls" in out.lower() or "unknown ca" in out.lower() or "fail" in out.lower()


# ---------------------------------------------------------------------------
# etcd — _format_record edge branches
# ---------------------------------------------------------------------------


def test_etcd_format_detect_record_json_shape() -> None:
    # Detect-payload has its own normalized shape (type/service/port/detected/...).
    rec = {"target": "127.0.0.1", "port": 2379, "status": "open_no_auth"}
    payload = json.loads(etcd_stage._format_detect_record(rec, "json"))
    assert payload["type"] == "detect"
    assert payload["service"] == "etcd"
    assert payload["port"] == 2379


def test_etcd_format_record_unknown_status_does_not_raise() -> None:
    rec = {"target": "127.0.0.1", "port": 2379, "status": "novel_state"}
    out = etcd_stage._format_record(rec, "txt")
    # Some marker must be present even for unknown states.
    assert any(marker in out for marker in ("[+]", "[-]", "[!]", "[*]"))


# ---------------------------------------------------------------------------
# gitlab — _format_record branch coverage
# ---------------------------------------------------------------------------


def test_gitlab_format_record_json_round_trip() -> None:
    rec = {"target": "127.0.0.1", "port": 80, "status": "open_no_auth", "version": "16.0"}
    out = gitlab_stage._format_record(rec, "json")
    assert json.loads(out)["version"] == "16.0"


def test_gitlab_format_record_fail_emits_marker() -> None:
    out = gitlab_stage._format_record(
        {"target": "127.0.0.1", "port": 80, "status": "fail", "error": "boom"},
        "txt",
    )
    assert "[!]" in out or "[-]" in out


# ---------------------------------------------------------------------------
# grafana — auth attempt + detect helpers
# ---------------------------------------------------------------------------


def test_grafana_format_detect_record_uses_indeterminate_marker() -> None:
    # Detect-stage output for grafana reports auth_required:unknown when the field
    # isn't set, with the [*] indeterminate marker.
    rec = {"target": "127.0.0.1", "port": 3000, "status": "open_no_auth"}
    out = grafana_stage._format_detect_record(rec, "txt")
    assert "[*]" in out
    assert "Grafana Service" in out


def test_grafana_format_record_json_serializable() -> None:
    rec = {"target": "127.0.0.1", "port": 3000, "status": "valid_credentials"}
    out = grafana_stage._format_record(rec, "json")
    payload = json.loads(out)
    assert payload["status"] == "valid_credentials"


# ---------------------------------------------------------------------------
# consul — _render_colored fallthrough
# ---------------------------------------------------------------------------


class _RecordingConsole:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, content: Any, *args: Any, **kwargs: Any) -> None:
        self.lines.append(str(content))


def test_consul_render_colored_line_handles_blank_input() -> None:
    console = _RecordingConsole()
    # blank input is a no-op; should not crash and should return False (no handled markers).
    handled = consul_stage._render_colored_consul_line(console, "")
    assert handled is False


def test_consul_render_colored_line_pass_through_unrecognized_text() -> None:
    console = _RecordingConsole()
    handled = consul_stage._render_colored_consul_line(console, "totally unrelated text")
    assert handled is False


# ---------------------------------------------------------------------------
# grpc renderer edge cases
# ---------------------------------------------------------------------------


def test_grpc_format_record_json_includes_status_and_target() -> None:
    rec = {"target": "127.0.0.1", "port": 50051, "status": "not_grpc"}
    payload = json.loads(grpc_stage._format_record(rec, "json"))
    assert payload["status"] == "not_grpc"
    assert payload["target"] == "127.0.0.1"


def test_grpc_format_record_unknown_status_does_not_crash() -> None:
    rec = {"target": "127.0.0.1", "port": 50051, "status": "very_new_state"}
    out = grpc_stage._format_record(rec, "txt")
    assert isinstance(out, str)
    assert len(out) > 0


# ---------------------------------------------------------------------------
# JSON-format invariants: every module's _format_record must round-trip JSON
# without exception for a minimal valid record. Catches future serialization
# regressions (e.g. inserting a non-serializable object into the payload).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stage_module,port,status",
    [
        (clickhouse_stage, 9000, "open_no_auth"),
        (elastic_stage, 9200, "open_no_auth"),
        (etcd_stage, 2379, "open_no_auth"),
        (gitlab_stage, 80, "open_no_auth"),
        (grafana_stage, 3000, "open_no_auth"),
        (grpc_stage, 50051, "not_grpc"),
    ],
)
def test_format_record_json_is_valid_json(stage_module: Any, port: int, status: str) -> None:
    rec = {"target": "127.0.0.1", "port": port, "status": status}
    rendered = stage_module._format_record(rec, "json")
    # Must parse without exception.
    payload = json.loads(rendered)
    assert payload["target"] == "127.0.0.1"
    assert payload["port"] == port
    assert payload["status"] == status
