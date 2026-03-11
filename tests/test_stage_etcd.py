from __future__ import annotations

from redposture_core.stage_etcd import (
    _body_indicates_auth_required,
    _count_v2_keys,
    _count_v2_nodes,
    _count_v3_keys,
    _dump_v2_all_from_body,
    _format_detect_record,
    _format_keys_detail_records,
    _format_record,
    _friendly_error_text,
    _is_suppressed_fail_record,
    _join_api_versions,
    _major_version,
    _normalize_etcd_key,
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
    assert _count_v3_keys('{"count": "x"}') is None


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
    assert _dump_v2_all_from_body(body) == ["/a:1", "/b:2"]


def test_format_record_for_main_statuses() -> None:
    base = {"host": "127.0.0.1", "port": 2379}

    line_open = _format_record({**base, "status": "open_no_auth", "key_count": 3}, "txt")
    assert "[+] anonymous access (keys:3)" in line_open

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


def test_is_suppressed_fail_record_for_timeout_and_refused() -> None:
    assert _is_suppressed_fail_record({"status": "fail", "error": "connection timeout"}) is True
    assert _is_suppressed_fail_record({"status": "fail", "error": "connection refused (service)"}) is True
    assert _is_suppressed_fail_record({"status": "fail", "error": "dns lookup failed"}) is False
