from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from redposture_core import stage_etcd as etcd
from redposture_core.audit_models import AuditRecord
from redposture_core.stage_etcd import (
    _audit_etcd_host,
    _body_indicates_auth_required,
    _call_audit_etcd_host_with_stage_debug,
    _count_v2_keys,
    _count_v2_nodes,
    _count_v3_keys,
    _dump_v2_all_from_body,
    _format_credential_attempts_records,
    _format_detect_record,
    _format_keys_detail_records,
    _format_record,
    _friendly_error_text,
    _is_suppressed_fail_record,
    _join_api_versions,
    _major_version,
    _normalize_etcd_key,
)
from tests.stage_runtime_helpers import patch_module_host_stage_for_test, run_module_targets_for_test


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

    def plain(self, message: str, color: str | None = None) -> None:
        _ = color
        self.messages.append(("plain", message))

    def _paint(self, text: str, _color: str, _stream: object) -> str:
        return text

    def render_tagged_payload_line(self, line: str, tag: str, payload_color: str | None = None) -> bool:
        _ = (line, tag, payload_color)
        return False


def _etcd_args(**overrides: object) -> argparse.Namespace:
    data: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "retries": 0,
        "ports": None,
        "port": 2379,
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "output": None,
        "output_format": "txt",
        "workers": 1,
        "show_keys": False,
        "dump": False,
        "key": None,
    }
    data.update(overrides)
    return argparse.Namespace(**data)


def test_etcd_default_credentials_are_exact_and_explicit_overlap_is_deduplicated() -> None:
    assert etcd._ETCD_DEFAULT_CREDS == (
        ("admin", "admin"),
        ("admin", "changeme"),
        ("admin", "etcd"),
        ("admin", "password"),
        ("etcd", "etcd"),
        ("etcd", "password"),
        ("root", "admin"),
        ("root", "etcd"),
        ("root", "password"),
        ("root", "root"),
        ("root", "rootpass"),
        ("service", "service"),
        ("user", "password"),
        ("user", "user"),
    )
    assert etcd._build_etcd_credential_candidates("root", "root", True) == [
        ("root", "root", "provided"),
        ("admin", "admin", "default"),
        ("admin", "changeme", "default"),
        ("admin", "etcd", "default"),
        ("admin", "password", "default"),
        ("etcd", "etcd", "default"),
        ("etcd", "password", "default"),
        ("root", "admin", "default"),
        ("root", "etcd", "default"),
        ("root", "password", "default"),
        ("root", "rootpass", "default"),
        ("service", "service", "default"),
        ("user", "password", "default"),
        ("user", "user", "default"),
    ]


def _etcd_host_record(
    kwargs: dict[str, object],
    *,
    status: str,
    detected: bool,
    error: str | None = None,
) -> AuditRecord:
    return AuditRecord(
        host=str(kwargs["host"]),
        port=int(kwargs["port"]),
        service="etcd",
        module="etcd",
        status=status,
        auth_required=status == "auth_required",
        extra={
            "is_etcd": detected,
            "api_versions": "v3" if detected else None,
            "error": error,
            "show_keys": bool(kwargs.get("show_keys")),
            "dump_keys": bool(kwargs.get("dump_keys")),
            "query_key": kwargs.get("query_key"),
        },
    )


def test_friendly_error_text_maps_common_network_errors() -> None:
    assert "connection refused" in _friendly_error_text("[Errno 111] Connection refused")
    assert _friendly_error_text("timed out") == "connection timeout"
    assert _friendly_error_text("nodename nor servname provided") == "dns lookup failed"


def test_body_indicates_auth_required_detects_known_messages() -> None:
    assert _body_indicates_auth_required("etcdserver: authentication failed") is True
    assert _body_indicates_auth_required("permission denied") is True
    assert _body_indicates_auth_required("ok") is False


def test_major_version_parsing() -> None:
    assert _major_version("3.5.11") == 3
    assert _major_version("2") == 2
    assert _major_version("v3") is None
    assert _major_version("") is None


def test_count_v2_nodes_recursively_counts_leaf_keys() -> None:
    node = {
        "dir": True,
        "nodes": [
            {"key": "/a", "value": "1"},
            {"dir": True, "nodes": [{"key": "/b", "value": "2"}]},
        ],
    }
    assert _count_v2_nodes(node) == 2


def test_count_v2_keys_and_v3_keys_helpers() -> None:
    assert _count_v2_keys('{"node": {"key":"/a","value":"1"}}') == 1
    assert _count_v2_keys("not-json") is None

    assert _count_v3_keys('{"count": 7}') == 7
    assert _count_v3_keys('{"count": "8"}') == 8
    assert _count_v3_keys("{}") == 0
    assert _count_v3_keys('{"count": "x"}') is None
    assert etcd._parse_v3_key_count("{}") == (0, None)
    malformed_count, malformed_error = etcd._parse_v3_key_count('{"count": "x"}')
    assert malformed_count is None
    assert "invalid count" in str(malformed_error)
    assert etcd._parse_v3_key_count("not-json") == (None, "count response returned invalid JSON")


def test_join_api_versions_formats_expected_values() -> None:
    assert _join_api_versions(v2_supported=True, v3_supported=True) == "v2,v3"
    assert _join_api_versions(v2_supported=True, v3_supported=False) == "v2"
    assert _join_api_versions(v2_supported=False, v3_supported=False) == "-"


def test_normalize_etcd_key_adds_leading_slash() -> None:
    assert _normalize_etcd_key("a/b") == "/a/b"
    assert _normalize_etcd_key("/a/b") == "/a/b"
    assert _normalize_etcd_key("  ") is None


def test_dump_v2_all_from_body_returns_sorted_pairs() -> None:
    body = '{"node":{"dir":true,"nodes":[{"key":"/b","value":"2"},{"key":"/a","value":"1"}]}}'
    assert _dump_v2_all_from_body(body) == [
        {"key": "/a", "value": "1", "error": None},
        {"key": "/b", "value": "2", "error": None},
    ]


def test_format_record_for_main_statuses() -> None:
    base = {"host": "127.0.0.1", "port": 2379}

    anonymous_record = {**base, "status": "open_no_auth", "key_count": 3}
    assert _format_record(anonymous_record, "txt") == ""
    anonymous_json = json.loads(_format_record(anonymous_record, "json"))
    assert anonymous_json["status"] == "open_no_auth"
    assert anonymous_json["key_count"] == 3

    line_auth = _format_record({**base, "status": "auth_required"}, "txt")
    assert "[-] authentication required" in line_auth

    line_unknown = _format_record({**base, "status": "unknown_auth", "error": "weird"}, "txt")
    assert "[!] auth status unknown" in line_unknown
    assert "err=weird" in line_unknown

    line_fail = _format_record({**base, "status": "fail", "error": "connection timeout"}, "txt")
    assert "[!] connection failed" in line_fail
    assert "err=connection timeout" in line_fail


def test_format_detect_record_shows_auth_required_flag() -> None:
    line = _format_detect_record(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 2379,
            "is_etcd": True,
            "api_versions": "v3",
            "auth_required": True,
            "server_version": "3.5.0",
        },
        "txt",
    )
    assert "[*] etcd Database" in line
    assert "(auth required:True)" in line


def test_format_keys_detail_records_builds_text_sections() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 2379,
        "show_keys": True,
        "dump_keys": True,
        "query_key": "/a",
        "query_key_value": "/a:1",
        "keys": ["/b", "/a"],
        "key_values": ["/a:1", "/b:2"],
        "key_count": 2,
    }
    lines = _format_keys_detail_records(record, "txt")
    assert any("[*] Show Keys" in line for line in lines)
    assert any("[*] Dump Key /a" in line for line in lines)
    assert any("[*] Dump Keys" in line for line in lines)


def test_is_suppressed_fail_record_for_any_fail_status() -> None:
    assert _is_suppressed_fail_record({"status": "fail", "error": "connection timeout"}) is True
    assert _is_suppressed_fail_record({"status": "fail", "error": "connection refused (service)"}) is True
    assert _is_suppressed_fail_record({"status": "fail", "error": "dns lookup failed"}) is True
    assert _is_suppressed_fail_record({"status": "auth_required", "error": "dns lookup failed"}) is False


def test_audit_etcd_host_open_v2_collects_keys_and_query(monkeypatch) -> None:
    def fake_http_json_request(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, str]:
        _ = (host, port, method, timeout, payload)
        if path == "/version":
            return 200, '{"etcdserver":"2.3.8"}'
        if path == "/v2/keys?recursive=true":
            return 200, '{"node":{"dir":true,"nodes":[{"key":"/b","value":"2"},{"key":"/a","value":"1"}]}}'
        if path == "/v2/keys/a":
            return 200, '{"node":{"key":"/a","value":"1"}}'
        raise AssertionError(path)

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", fake_http_json_request)

    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=True,
        dump_keys=True,
        query_key="/a",
    )

    assert record["status"] == "open_no_auth"
    assert record["api_versions"] == "v2"
    assert record["key_count"] == 2
    assert record["keys"] == ["/a", "/b"]
    assert record["key_values"] == ["/a:1", "/b:2"]
    assert record["query_key_value"] == "/a:1"


def test_audit_etcd_host_v3_auth_required_and_unknown_auth(monkeypatch) -> None:
    auth_required_calls: list[str] = []

    def fake_auth_required(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, str]:
        _ = (host, port, method, timeout, payload)
        auth_required_calls.append(path)
        if path == "/version":
            return 200, '{"etcdserver":"3.5.11"}'
        if path == "/v2/keys?recursive=true":
            return 404, ""
        if path == "/v3/auth/status":
            return 200, '{"enabled": true}'
        raise AssertionError(path)

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", fake_auth_required)
    auth_record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )
    assert auth_record["status"] == "auth_required"
    assert auth_record["api_versions"] == "v3"
    assert auth_record["auth_required"] is True
    assert "/v3/auth/status" in auth_required_calls

    def fake_unknown(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, str]:
        _ = (host, port, method, timeout, payload)
        if path == "/version":
            return 200, '{"etcdserver":"3.5.11"}'
        if path == "/v2/keys?recursive=true":
            return 404, ""
        if path == "/v3/auth/status":
            return 500, "oops"
        if path == "/v3/kv/range":
            return 500, "oops"
        raise AssertionError(path)

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", fake_unknown)
    unknown_record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )
    assert unknown_record["status"] == "unknown_auth"
    assert unknown_record["auth_required"] is None
    assert "/v3/kv/range returned status 500" in str(unknown_record["error"])


def test_audit_etcd_host_v3_range_probe_uses_valid_all_range_payload(monkeypatch) -> None:
    seen_payloads: list[dict[str, object] | None] = []

    def fake_request(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, str]:
        _ = (host, port, method, timeout)
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14"}'
        if path == "/v2/keys?recursive=true":
            return 404, ""
        if path == "/v3/auth/status":
            return 500, "auth status disabled by gateway"
        if path == "/v3/kv/range":
            seen_payloads.append(payload)
            if payload == {"key": "AA==", "range_end": "AA==", "count_only": True}:
                return 200, '{"count":"8"}'
            return 400, '{"error":"etcdserver: key is not provided"}'
        raise AssertionError(path)

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", fake_request)
    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )

    assert seen_payloads == [{"key": "AA==", "range_end": "AA==", "count_only": True}]
    assert record["status"] == "open_no_auth"
    assert record["auth_required"] is False
    assert record["key_count"] == 8


def test_audit_etcd_mixed_api_open_access_wins_over_auth_required(monkeypatch) -> None:
    def fake_request(_host, _port, _method, path, _timeout, *, payload=None):
        _ = payload
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14"}'
        if path == "/v2/keys?recursive=true":
            return 200, '{"node":{"dir":true,"nodes":[]}}'
        if path == "/v3/auth/status":
            return 200, '{"enabled":true}'
        raise AssertionError(path)

    monkeypatch.setattr(etcd, "_http_json_request", fake_request)
    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )

    assert record["status"] == "open_no_auth"
    assert record["auth_required"] is False
    assert record["api_auth_required"] == {"v2": False, "v3": True}
    assert record["key_count"] == 0
    assert record["key_count_state"] == "known"


def test_audit_etcd_malformed_v3_count_is_explicitly_unknown(monkeypatch) -> None:
    def fake_request(_host, _port, _method, path, _timeout, *, payload=None):
        _ = payload
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14"}'
        if path == "/v2/keys?recursive=true":
            return 404, ""
        if path == "/v3/auth/status":
            return 200, '{"enabled":false}'
        if path == "/v3/kv/range":
            return 200, '{"count":[]}'
        raise AssertionError(path)

    monkeypatch.setattr(etcd, "_http_json_request", fake_request)
    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )

    assert record["status"] == "open_no_auth"
    assert record["key_count"] is None
    assert record["key_count_state"] == "unknown"
    assert "invalid count" in str(record["key_count_error"])
    assert _format_record(record, "txt") == ""
    assert "count response returned invalid count" in json.loads(_format_record(record, "json"))["key_count_error"]


def test_audit_etcd_authenticated_reads_propagate_token_and_render_selected_default(monkeypatch) -> None:
    token_calls: list[tuple[dict[str, object], str | None]] = []

    def fake_request(_host, _port, _method, path, _timeout, *, payload=None, auth_token=None):
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14"}'
        if path == "/v2/keys?recursive=true":
            return 404, ""
        if path == "/v3/auth/status":
            return 200, '{"enabled":true}'
        if path == "/v3/kv/range":
            assert isinstance(payload, dict)
            token_calls.append((payload, auth_token))
            if payload.get("count_only"):
                return 200, "{}"
            if payload.get("key") == etcd._b64_encode_text("/wanted"):
                return 200, '{"kvs":[]}'
            return 200, '{"kvs":[],"more":false}'
        raise AssertionError(path)

    auth_attempts: list[tuple[str, str]] = []

    def fake_auth(_host, _port, _timeout, username, password):
        auth_attempts.append((username, password))
        if (username, password) == ("admin", "admin"):
            raise OSError("candidate transport failure")
        if (username, password) == ("admin", "changeme"):
            return "token-123", None
        if (username, password) == ("root", "etcd"):
            return "token-later", None
        return None, "authentication failed"

    monkeypatch.setattr(etcd, "_http_json_request", fake_request)
    monkeypatch.setattr(etcd, "_etcd_v3_authenticate", fake_auth)
    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=True,
        dump_keys=True,
        query_key="/wanted",
        defcreds=True,
        dump_batch=10,
        dump_delay=0,
    )

    assert auth_attempts == list(etcd._ETCD_DEFAULT_CREDS)
    assert record["status"] == "weak_default_creds"
    assert record["key_count"] == 0
    assert record["key_count_state"] == "known"
    assert record["effective_username"] == "admin"
    assert record["effective_password"] == "changeme"
    assert "candidate transport failure" in str(record["credential_attempts"][0]["error"])
    assert len(token_calls) == 3
    assert all(token == "token-123" for _payload, token in token_calls)
    assert _format_record(record, "txt") == ""
    rendered = _format_credential_attempts_records(record, "txt")
    assert len(rendered) == len(etcd._ETCD_DEFAULT_CREDS)
    selected_line = next(line for line in rendered if "[+] admin:changeme" in line)
    later_success_line = next(line for line in rendered if "[+] root:etcd" in line)
    assert selected_line.endswith("[+] admin:changeme (keys:0)")
    assert later_success_line.endswith("[+] root:etcd")


def test_audit_etcd_defcreds_full_failure_renders_each_pair_once(monkeypatch) -> None:
    def fake_request(_host, _port, _method, path, _timeout, *, payload=None, auth_token=None):
        _ = (payload, auth_token)
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14"}'
        if path == "/v2/keys?recursive=true":
            return 404, ""
        if path == "/v3/auth/status":
            return 200, '{"enabled":true}'
        raise AssertionError(path)

    attempted: list[tuple[str, str]] = []

    def fake_auth(_host, _port, _timeout, username, password):
        attempted.append((username, password))
        return None, "authentication failed"

    monkeypatch.setattr(etcd, "_http_json_request", fake_request)
    monkeypatch.setattr(etcd, "_etcd_v3_authenticate", fake_auth)
    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
        defcreds=True,
    )

    assert attempted == list(etcd._ETCD_DEFAULT_CREDS)
    assert record["status"] == "auth_required"
    assert len(record["credential_attempts"]) == len(etcd._ETCD_DEFAULT_CREDS)
    assert _format_record(record, "txt") == ""
    lines = _format_credential_attempts_records(record, "txt")
    assert len(lines) == len(etcd._ETCD_DEFAULT_CREDS)
    assert all(" [-] " in line for line in lines)


def test_audit_etcd_without_defcreds_stops_after_first_success(monkeypatch) -> None:
    def fake_request(_host, _port, _method, path, _timeout, *, payload=None, auth_token=None):
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14"}'
        if path == "/v2/keys?recursive=true":
            return 404, ""
        if path == "/v3/auth/status":
            return 200, '{"enabled":true}'
        if path == "/v3/kv/range":
            assert auth_token == "token-first"
            return 200, '{"count":"0"}'
        raise AssertionError(path)

    attempted: list[tuple[str, str]] = []

    def fake_auth(_host, _port, _timeout, username, password):
        attempted.append((username, password))
        return ("token-first" if username == "first" else "token-second"), None

    monkeypatch.setattr(etcd, "_http_json_request", fake_request)
    monkeypatch.setattr(etcd, "_etcd_v3_authenticate", fake_auth)
    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
        credential_candidates=[
            {"username": "first", "password": "one", "source": "file"},
            {"username": "second", "password": "two", "source": "file"},
        ],
    )

    assert attempted == [("first", "one")]
    assert record["status"] == "valid_credentials"
    assert record["effective_username"] == "first"
    assert record["effective_password"] == "one"


def test_audit_etcd_host_marks_non_etcd_and_retries_failures(monkeypatch) -> None:
    def fake_not_etcd(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, str]:
        _ = (host, port, method, timeout, payload)
        if path == "/version":
            return 404, ""
        if path == "/v2/keys?recursive=true":
            return 404, ""
        raise AssertionError(path)

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", fake_not_etcd)
    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )
    assert record["status"] == "fail"
    assert record["is_etcd"] is False
    assert record["error"] == "service is not etcd"

    attempts = {"count": 0}

    def fake_fail(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, str]:
        _ = (host, port, method, path, timeout, payload)
        attempts["count"] += 1
        raise TimeoutError("timed out")

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", fake_fail)
    monkeypatch.setattr("redposture_core.stage_etcd._retry_delay", lambda _attempt: 0.0)
    failed_record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=1,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )
    assert attempts["count"] == 2
    assert failed_record["status"] == "fail"
    assert failed_record["error"] == "connection timeout"


def test_audit_etcd_targets_emits_detect_status_and_key_lines(monkeypatch) -> None:
    def fake_audit(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        show_keys: bool,
        dump_keys: bool,
        query_key: str | None,
        dump_batch: int = 10000,
        dump_delay: int = 20,
    ) -> dict[str, object]:
        _ = (host, port, timeout, retries, show_keys, dump_keys, query_key, dump_batch, dump_delay)
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 2379,
            "is_etcd": True,
            "status": "open_no_auth",
            "api_versions": "v2",
            "server_version": "2.3.8",
            "auth_required": False,
            "key_count": 2,
            "show_keys": True,
            "dump_keys": True,
            "query_key": "/a",
            "keys": ["/a", "/b"],
            "key_values": ["/a:1", "/b:2"],
            "query_key_value": "/a:1",
            "elapsed_ms": 5,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.stage_etcd._audit_etcd_host", fake_audit)

    lines: list[str] = []
    total, open_no_auth, auth_required, failed = run_module_targets_for_test(
        "etcd",
        hosts=["127.0.0.1"],
        port=2379,
        timeout=1.0,
        retries=0,
        workers=1,
        show_keys=True,
        dump_keys=True,
        query_key="/a",
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_connection_refused_status_lines=False,
    )

    assert (total, open_no_auth, auth_required, failed) == (1, 1, 0, 0)
    detect_line = next(line for line in lines if "[*] etcd Database" in line)
    assert "(auth required:False)" in detect_line
    assert not any("[+] anonymous access" in line for line in lines)
    assert any("[*] Show Keys" in line for line in lines)
    assert any("[*] Dump Keys" in line for line in lines)


def test_call_audit_etcd_host_with_stage_debug_adds_stage_telemetry(monkeypatch) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 2379,
            "is_etcd": True,
            "status": "open_no_auth",
            "auth_required": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.stage_etcd._audit_etcd_host", fake_audit)
    debug_lines: list[str] = []
    result = _call_audit_etcd_host_with_stage_debug(
        "127.0.0.1",
        2379,
        1.0,
        1,
        False,
        False,
        None,
        run_deep_checks=True,
        debug=True,
        debug_emit=debug_lines.append,
    )
    assert isinstance(result.get("stages"), list)
    assert result.get("stage_attempts") is not None
    assert any("stage_trace stage_name=detect_protocol" in line for line in debug_lines)


def test_audit_etcd_targets_emits_two_pass_debug_markers(monkeypatch) -> None:
    def fake_stage_call(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        show_keys: bool,
        dump_keys: bool,
        query_key: str | None,
        *,
        run_deep_checks: bool,
        debug: bool,
        debug_emit,
    ) -> dict[str, object]:
        _ = (port, timeout, retries, show_keys, dump_keys, query_key, debug, debug_emit)
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 2379,
            "is_etcd": True,
            "status": "open_no_auth",
            "auth_required": False,
            "show_keys": bool(run_deep_checks),
            "dump_keys": False,
            "query_key": None,
            "keys": ["/a"] if run_deep_checks else None,
            "key_values": None,
            "query_key_value": None,
            "api_versions": "v3",
            "server_version": "3.5.0",
            "key_count": 1,
            "error": None,
            "debug_events": [],
            "debug_events_streamed": True,
            "stages": [],
            "stage_durations_ms": {},
            "stage_attempts": {},
            "stage_failed_at": None,
        }

    monkeypatch.setattr("redposture_core.stage_etcd._call_audit_etcd_host_with_stage_debug", fake_stage_call)
    debug_lines: list[str] = []
    emitted: list[str] = []
    totals = run_module_targets_for_test(
        "etcd",
        hosts=["127.0.0.1"],
        port=2379,
        timeout=1.0,
        retries=0,
        workers=1,
        show_keys=True,
        dump_keys=False,
        query_key=None,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        debug_emit=debug_lines.append,
        show_progress=False,
    )
    assert totals == (1, 1, 0, 0)
    assert any("pass=1 detect start total=1" in line for line in debug_lines)
    assert any("stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=1" in line for line in debug_lines)


def test_dump_v2_and_v3_helpers_cover_error_and_success_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_http_v2(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, str]:
        _ = (host, port, method, timeout, payload)
        if path.endswith("/missing"):
            return 404, ""
        if path.endswith("/broken"):
            return 500, ""
        if path.endswith("/invalid-json"):
            return 200, "not-json"
        if path.endswith("/invalid-node"):
            return 200, '{"node": "bad"}'
        if path.endswith("/dir"):
            return 200, '{"node": {"dir": true}}'
        return 200, '{"node": {"key": "/ok", "value": "1"}}'

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", fake_http_v2)
    assert etcd._dump_v2_key("127.0.0.1", 2379, "/missing", 1.0) == (
        {"key": "/missing", "value": "<not found>", "error": None},
        None,
    )
    assert etcd._dump_v2_key("127.0.0.1", 2379, "/broken", 1.0) == (None, "/v2/keys/broken returned status 500")
    assert etcd._dump_v2_key("127.0.0.1", 2379, "/invalid-json", 1.0) == (
        None,
        "/v2/keys/invalid-json returned invalid JSON",
    )
    assert etcd._dump_v2_key("127.0.0.1", 2379, "/invalid-node", 1.0) == (
        None,
        "/v2/keys/invalid-node returned invalid node",
    )
    assert etcd._dump_v2_key("127.0.0.1", 2379, "/dir", 1.0) == (
        {"key": "/dir", "value": "<dir>", "error": None},
        None,
    )
    assert etcd._dump_v2_key("127.0.0.1", 2379, "/ok", 1.0) == (
        {"key": "/ok", "value": "1", "error": None},
        None,
    )

    monkeypatch.setattr(
        "redposture_core.stage_etcd._http_json_request",
        lambda *_args, **_kwargs: (200, '{"kvs":[{"key":"L2E=","value":"MQ=="}]}'),
    )
    assert etcd._dump_v3_all("127.0.0.1", 2379, 1.0) == (
        [{"key": "/a", "value": "1", "error": None}],
        None,
    )
    assert etcd._dump_v3_key("127.0.0.1", 2379, "/key", 1.0) == (
        {"key": "/a", "value": "1", "error": None},
        None,
    )

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", lambda *_args, **_kwargs: (401, ""))
    assert etcd._dump_v3_all("127.0.0.1", 2379, 1.0) == (None, "authentication required")
    assert etcd._dump_v3_key("127.0.0.1", 2379, "/key", 1.0) == (None, "authentication required")

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", lambda *_args, **_kwargs: (500, ""))
    assert etcd._dump_v3_all("127.0.0.1", 2379, 1.0) == (None, "/v3/kv/range returned status 500")
    assert etcd._dump_v3_key("127.0.0.1", 2379, "/key", 1.0) == (None, "/v3/kv/range returned status 500")

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", lambda *_args, **_kwargs: (200, "not-json"))
    assert etcd._dump_v3_all("127.0.0.1", 2379, 1.0) == (None, "/v3/kv/range returned invalid JSON")
    assert etcd._dump_v3_key("127.0.0.1", 2379, "/key", 1.0) == (None, "/v3/kv/range returned invalid JSON")

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", lambda *_args, **_kwargs: (200, '{"kvs":"x"}'))
    assert etcd._dump_v3_all("127.0.0.1", 2379, 1.0) == ([], None)
    assert etcd._dump_v3_key("127.0.0.1", 2379, "/key", 1.0) == (
        {"key": "/key", "value": "<not found>", "error": None},
        None,
    )

    monkeypatch.setattr(
        "redposture_core.stage_etcd._http_json_request", lambda *_args, **_kwargs: (200, '{"kvs":["x"]}')
    )
    assert etcd._dump_v3_key("127.0.0.1", 2379, "/key", 1.0) == (
        {"key": "/key", "value": "<not found>", "error": None},
        None,
    )


def test_dump_v3_all_uses_valid_all_range_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    seen_payloads: list[dict[str, object] | None] = []

    def fake_request(*_args: object, **kwargs: object) -> tuple[int, str]:
        payload = kwargs.get("payload")
        assert isinstance(payload, dict)
        seen_payloads.append(payload)
        return 200, '{"kvs":[]}'

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", fake_request)
    assert etcd._dump_v3_all("127.0.0.1", 2379, 1.0, limit=2) == ([], None)
    assert seen_payloads == [{"key": "AA==", "range_end": "AA==", "limit": 2}]


def test_format_keys_detail_records_json_and_merge_stage_records() -> None:
    record = {
        "timestamp": "2026-03-27T00:00:00Z",
        "host": "127.0.0.1",
        "port": 2379,
        "show_keys": True,
        "dump_keys": True,
        "query_key": "/a",
        "query_key_value": "/a:1",
        "keys": ["/b", "/a"],
        "key_values": ["/a:1", "/b:2"],
        "key_count": 2,
    }
    payloads = [json.loads(line) for line in _format_keys_detail_records(record, "json")]
    assert {item["type"] for item in payloads} == {"keys_list", "key_dump", "keys_dump"}

    merged = etcd._merge_stage2_record(
        {
            "status": "open_no_auth",
            "debug_events": ["a"],
            "debug_events_streamed": False,
            "stages": [{"stage_name": "detect_protocol"}],
            "stage_durations_ms": {"detect_protocol": 1},
            "stage_attempts": {"detect_protocol": 2},
            "stage_failed_at": None,
        },
        {
            "status": "open_no_auth",
            "debug_events": ["b"],
            "debug_events_streamed": True,
            "stages": [{"stage_name": "data"}],
            "stage_durations_ms": {"data": 3},
            "stage_attempts": {"data": 2},
            "stage_failed_at": "data",
        },
    )
    assert merged["debug_events"] == ["a", "b"]
    assert merged["debug_events_streamed"] is True
    assert merged["stage_failed_at"] == "data"
    assert merged["stage_durations_ms"] == {"detect_protocol": 1, "data": 3}


def test_render_colored_etcd_line_returns_expected_flags() -> None:
    class _Painter:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, color: str, _stream: object) -> str:
            return f"<{color}>{text}</{color}>"

        def plain(self, line: str) -> None:
            self.lines.append(line)

    console = _Painter()
    assert etcd._render_colored_etcd_line(console, "NOPE") is False
    assert etcd._render_colored_etcd_line(console, "ETCD\t127.0.0.1\t2379\t [*] etcd Database (auth required:True)")
    assert console.lines
    assert "auth required:True" in console.lines[0]


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"timeout": 0}, "--timeout must be > 0"),
        ({"retries": -1}, "--retries must be >= 0"),
        ({"ports": "bad"}, "failed to parse --port"),
        ({"targets": None, "hosts": None}, "etcd requires -t/--targets"),
    ],
)
def test_run_etcd_stage_validation_paths(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], expected: str
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(etcd, "Console", _ConsoleCapture)
    rc = etcd.run_etcd_stage(_etcd_args(**overrides), logger=object())
    assert rc == 2
    assert any(expected in msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "error")


def test_run_etcd_stage_accepts_https_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(etcd, "Console", _ConsoleCapture)
    rc = etcd.run_etcd_stage(_etcd_args(targets="https://127.0.0.1:2379"), logger=object())
    assert rc == 1
    assert not any(
        "etcd accepts only http:// URL targets for -t/--targets" in msg
        for level, msg in _ConsoleCapture.instances[-1].messages
        if level == "error"
    )


def test_run_etcd_stage_debug_flow_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(etcd, "Console", _ConsoleCapture)
    monkeypatch.setattr(etcd, "collect_scan_ports", lambda *_args, **_kwargs: [2379, 22379])
    monkeypatch.setattr(
        etcd,
        "collect_scan_target_specs",
        lambda _targets: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        etcd,
        "build_scan_execution_groups",
        lambda _specs, _ports, include_scheme_in_key=False: [
            SimpleNamespace(hosts=["127.0.0.1"], port=2379),
            SimpleNamespace(hosts=["127.0.0.1"], port=22379),
        ],
    )

    calls: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        calls.append(dict(kwargs))
        return _etcd_host_record(kwargs, status="fail", detected=False, error="connection refused")

    patch_module_host_stage_for_test(monkeypatch, "etcd", fake_audit_targets)
    rc = etcd.run_etcd_stage(_etcd_args(debug=True), logger=object())
    assert rc == 1
    assert len(calls) == 2
    assert [call["port"] for call in calls] == [2379, 22379]
    assert all(call["run_deep_checks"] is False for call in calls)
    assert all(call["debug"] is True and callable(call["debug_emit"]) for call in calls)
    infos = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "info"]
    assert any("etcd audit started:" in msg for msg in infos)


def test_run_etcd_stage_verbose_multi_group_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(etcd, "Console", _ConsoleCapture)
    monkeypatch.setattr(etcd, "collect_scan_ports", lambda *_args, **_kwargs: [2379, 22379])
    monkeypatch.setattr(
        etcd,
        "collect_scan_target_specs",
        lambda _targets: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        etcd,
        "build_scan_execution_groups",
        lambda _specs, _ports, include_scheme_in_key=False: [
            SimpleNamespace(hosts=["127.0.0.1"], port=2379),
            SimpleNamespace(hosts=["127.0.0.1"], port=22379),
        ],
    )

    calls: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        calls.append(dict(kwargs))
        return _etcd_host_record(kwargs, status="fail", detected=False, error="connection refused")

    patch_module_host_stage_for_test(monkeypatch, "etcd", fake_audit_targets)

    progress_totals: list[int] = []
    progress_advances: list[int] = []

    class _FakeProgressBar:
        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            progress_totals.append(int(total))

        def advance(self, amount: int = 1) -> None:
            progress_advances.append(int(amount))

        def close(self) -> None:
            return

    monkeypatch.setattr(
        "redposture_core.stage_runtime.start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    rc = etcd.run_etcd_stage(_etcd_args(show_keys=True), logger=object())
    assert rc == 1
    assert len(calls) == 2
    assert [call["port"] for call in calls] == [2379, 22379]
    assert all(call["run_deep_checks"] is False for call in calls)
    assert progress_totals == [2]
    assert progress_advances == [1, 1]


def test_run_etcd_stage_suppresses_unreachable_summary_without_debug(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(etcd, "Console", _ConsoleCapture)
    monkeypatch.setattr(etcd, "collect_scan_ports", lambda *_args, **_kwargs: [2379])
    monkeypatch.setattr(
        etcd,
        "collect_scan_target_specs",
        lambda _targets: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        etcd,
        "build_scan_execution_groups",
        lambda _specs, _ports, include_scheme_in_key=False: [SimpleNamespace(hosts=["127.0.0.1"], port=2379)],
    )
    patch_module_host_stage_for_test(
        monkeypatch,
        "etcd",
        lambda **kwargs: _etcd_host_record(
            kwargs,
            status="fail",
            detected=False,
            error="connection refused",
        ),
    )
    rc = etcd.run_etcd_stage(_etcd_args(), logger=object())
    assert rc == 1
    warns = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert not any("all etcd targets are unreachable" in msg for msg in warns)


def test_next_key_b64_appends_null_byte() -> None:
    # Continuation key is "<last key>\x00" so the next range starts strictly after it.
    nxt = etcd._next_key_b64(etcd._b64_encode_text("/b"))
    assert etcd._b64_decode_text(nxt) == "/b\x00"


def test_stream_dump_v3_all_pages_through_ranges_with_continuation(monkeypatch) -> None:
    b64 = etcd._b64_encode_text
    page1 = json.dumps(
        {"kvs": [{"key": b64("/a"), "value": b64("1")}, {"key": b64("/b"), "value": b64("2")}], "more": True}
    )
    page2 = json.dumps({"kvs": [{"key": b64("/c"), "value": b64("3")}], "more": False})
    seen_keys: list[object] = []

    def fake_request(host, port, method, path, timeout, *, payload=None):
        _ = (host, port, method, timeout)
        assert path == "/v3/kv/range"
        assert payload is not None
        assert payload["range_end"] == etcd._ETCD_V3_ALL_RANGE_KEY_B64
        assert payload["limit"] == 2
        seen_keys.append(payload["key"])
        return (200, page1) if payload["key"] == etcd._ETCD_V3_ALL_RANGE_KEY_B64 else (200, page2)

    monkeypatch.setattr(etcd, "_http_json_request", fake_request)
    sleeps: list[float] = []
    monkeypatch.setattr(etcd.time, "sleep", lambda s: sleeps.append(s))

    entries, err = etcd._stream_dump_v3_all("127.0.0.1", 2379, 1.0, batch=2, delay_ms=20)

    assert err is None
    assert [entry["key"] for entry in entries] == ["/a", "/b", "/c"]
    assert [entry["value"] for entry in entries] == ["1", "2", "3"]
    # Page 2 continues from the key immediately after the last one returned in page 1.
    assert seen_keys[0] == etcd._ETCD_V3_ALL_RANGE_KEY_B64
    assert seen_keys[1] == etcd._next_key_b64(b64("/b"))
    assert sleeps == [0.02]  # one pause between the two pages


def test_stream_dump_v3_all_respects_total_limit(monkeypatch) -> None:
    b64 = etcd._b64_encode_text
    calls = {"n": 0}

    def fake_request(host, port, method, path, timeout, *, payload=None):
        _ = (host, port, method, timeout, path)
        calls["n"] += 1
        assert payload["limit"] == 3  # min(batch=10, remaining=3)
        kvs = [{"key": b64(f"/k{i}"), "value": b64(str(i))} for i in range(3)]
        return 200, json.dumps({"kvs": kvs, "more": True})

    monkeypatch.setattr(etcd, "_http_json_request", fake_request)
    monkeypatch.setattr(etcd.time, "sleep", lambda _s: None)

    entries, err = etcd._stream_dump_v3_all("h", 2379, 1.0, batch=10, delay_ms=0, limit=3)

    assert err is None
    assert [entry["key"] for entry in entries] == ["/k0", "/k1", "/k2"]
    assert calls["n"] == 1  # stops once the cap is reached, no extra page


def test_stream_dump_v3_all_zero_delay_does_not_sleep(monkeypatch) -> None:
    b64 = etcd._b64_encode_text
    calls = {"n": 0}

    def fake_request(host, port, method, path, timeout, *, payload=None):
        _ = (host, port, method, timeout, path, payload)
        calls["n"] += 1
        if calls["n"] == 1:
            return 200, json.dumps({"kvs": [{"key": b64("/a"), "value": b64("1")}], "more": True})
        return 200, json.dumps({"kvs": [{"key": b64("/b"), "value": b64("2")}], "more": False})

    monkeypatch.setattr(etcd, "_http_json_request", fake_request)
    sleeps: list[float] = []
    monkeypatch.setattr(etcd.time, "sleep", lambda s: sleeps.append(s))

    entries, err = etcd._stream_dump_v3_all("h", 2379, 1.0, batch=1, delay_ms=0)

    assert err is None
    assert [entry["key"] for entry in entries] == ["/a", "/b"]
    assert sleeps == []  # delay_ms=0 disables inter-page pauses


def test_stream_dump_v3_all_reports_auth_required(monkeypatch) -> None:
    monkeypatch.setattr(etcd, "_http_json_request", lambda *_a, **_k: (401, ""))
    monkeypatch.setattr(etcd.time, "sleep", lambda _s: None)

    entries, err = etcd._stream_dump_v3_all("h", 2379, 1.0, batch=10, delay_ms=0)

    assert entries is None
    assert err == "authentication required"


def test_audit_etcd_host_v3_dump_streams_paged_ranges(monkeypatch) -> None:
    b64 = etcd._b64_encode_text

    def fake_request(host, port, method, path, timeout, *, payload=None):
        _ = (host, port, method, timeout)
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14"}'
        if path == "/v2/keys?recursive=true":
            return 404, ""
        if path == "/v3/auth/status":
            return 500, "auth status disabled by gateway"
        if path == "/v3/kv/range":
            assert payload is not None
            if payload.get("count_only"):
                return 200, '{"count":"3"}'
            if payload["key"] == etcd._ETCD_V3_ALL_RANGE_KEY_B64:
                return 200, json.dumps(
                    {
                        "kvs": [{"key": b64("/a"), "value": b64("1")}, {"key": b64("/b"), "value": b64("2")}],
                        "more": True,
                    }
                )
            return 200, json.dumps({"kvs": [{"key": b64("/c"), "value": b64("3")}], "more": False})
        raise AssertionError(path)

    monkeypatch.setattr("redposture_core.stage_etcd._http_json_request", fake_request)
    monkeypatch.setattr(etcd.time, "sleep", lambda _s: None)

    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=True,
        dump_keys=True,
        query_key=None,
        dump_batch=2,
        dump_delay=0,
    )

    assert record["status"] == "open_no_auth"
    assert record["auth_required"] is False
    # Streamed across two range pages; key names derived from the dumped entries.
    assert record["key_values"] == ["/a:1", "/b:2", "/c:3"]
    assert record["keys"] == ["/a", "/b", "/c"]


def test_etcd_rejects_login_html_and_falls_back_to_v3beta_gateway(monkeypatch) -> None:
    original_http_json_request = etcd._http_json_request
    monkeypatch.setattr(etcd, "_http_json_request", lambda *_args, **_kwargs: (200, "<html>login</html>"))
    record = _audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )
    assert record["is_etcd"] is False
    monkeypatch.setattr(etcd, "_http_json_request", original_http_json_request)

    calls: list[str] = []

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def request(self, _method, url, **_kwargs):
            calls.append(url)
            if "/v3/auth/status" in url:
                return SimpleNamespace(status=404, text="{}", error=None)
            return SimpleNamespace(status=200, text='{"enabled":false}', error=None)

    etcd._ETCD_V3_PREFIX_CACHE.clear()
    monkeypatch.setattr(etcd, "resolve_http_scheme", lambda *_args, **_kwargs: "http")
    monkeypatch.setattr(etcd, "HttpApiClient", _Client)

    assert etcd._http_json_request("etcd.local", 2379, "POST", "/v3/auth/status", 1.0) == (
        200,
        '{"enabled":false}',
    )
    assert calls == [
        "http://etcd.local:2379/v3/auth/status",
        "http://etcd.local:2379/v3beta/auth/status",
    ]
    calls.clear()
    etcd._http_json_request("etcd.local", 2379, "POST", "/v3/kv/range", 1.0, payload={})
    assert calls == ["http://etcd.local:2379/v3beta/kv/range"]
