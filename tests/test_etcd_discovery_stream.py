"""etcd discovery pages must shrink without advancing the continuation key."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
from types import SimpleNamespace
from unittest.mock import patch

from redposture_core.discovery_spool import SpoolingRecords
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.etcd import actions as etcd


def encoded(text):
    return base64.b64encode(text.encode()).decode()


def test_etcd_v3_shrinks_oversized_page_without_advancing_cursor(monkeypatch):
    calls = []

    def get(_host, _port, _method, _path, _timeout, *, payload, **kwargs):
        calls.append(dict(payload))
        if payload["limit"] > 1:
            raise urllib.error.URLError("HTTP response exceeds limit")
        if payload["key"] == "AA==":
            return 200, json.dumps(
                {"kvs": [{"key": encoded("a/password"), "value": encoded("qa-first-secret")}], "more": True}
            )
        return 200, json.dumps(
            {"kvs": [{"key": encoded("z/password"), "value": encoded("qa-last-secret")}], "more": False}
        )

    monkeypatch.setattr(etcd, "_http_json_request", get)
    values, error = etcd._stream_dump_v3_all(
        "qa", 2379, 1, batch=4, delay_ms=0, discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 5, 4096)
    )
    assert error is None
    assert [item["key"] for item in values] == ["a/password", "z/password"]
    assert [call["limit"] for call in calls] == [4, 2, 1, 1]
    assert [call["key"] for call in calls[:3]] == ["AA=="] * 3


def test_etcd_v3_source_catalog_spills_to_disk_when_discovering(monkeypatch):
    monkeypatch.setattr(
        etcd,
        "_http_json_request",
        lambda *a, **kw: (
            200,
            json.dumps(
                {
                    "kvs": [
                        {"key": encoded(f"app-{index}/password"), "value": encoded(f"qa-{index}-" + "n" * 400000)}
                        for index in range(3)
                    ],
                    "more": False,
                }
            ),
        ),
    )
    values, error = etcd._stream_dump_v3_all(
        "qa", 2379, 1, batch=4, delay_ms=0, discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 5, 4000000)
    )
    assert error is None
    assert isinstance(values, SpoolingRecords)
    assert len(values) == 3
    for index, item in enumerate(values):
        value = item["value"]
        assert isinstance(value, DiskBackedText)
        expected = f"qa-{index}-" + "n" * 400000
        assert value.byte_length == len(expected)
        assert value.digest == hashlib.sha256(expected.encode()).hexdigest()


def test_etcd_v3_emits_before_next_page_and_does_not_duplicate_catalogs(monkeypatch):
    from types import SimpleNamespace

    emitted = []
    pages = []

    def get(_host, _port, _method, path, _timeout, *, payload=None, **kwargs):
        if path == "/version":
            return 200, '{"etcdserver":"3.5.16","etcdcluster":"3.5.0"}'
        if path.startswith("/v2/keys"):
            return 404, "{}"
        if path == "/v3/auth/status":
            return 200, '{"enabled":false}'
        if path == "/v3/kv/range":
            if payload.get("count_only"):
                return 200, '{"count":"2"}'
            pages.append(payload["key"])
            if len(pages) == 1:
                return 200, json.dumps(
                    {"kvs": [{"key": encoded("a/password"), "value": encoded("qa-first-secret")}], "more": True}
                )
            assert emitted, "completed first-page secret must be live before the next request"
            return 200, json.dumps(
                {"kvs": [{"key": encoded("z/password"), "value": encoded("qa-last-secret")}], "more": False}
            )
        raise AssertionError(path)

    monkeypatch.setattr(etcd, "_http_json_request", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover=True, discover_time=30),
        host="qa",
        port=2379,
        discovery_started_at=time.monotonic(),
        live_emit=emitted.append,
    )
    report = etcd._audit_etcd_host("qa", 2379, 1, 0, False, True, None, discover=True, discover_ctx=ctx)
    assert report["content_discovery"]["status"] == "complete"
    assert [item["value"] for item in report["content_discovery"]["findings"]] == ["qa-first-secret", "qa-last-secret"]
    assert isinstance(report["key_value_entries"], SpoolingRecords)
    assert report["key_values"] is None


def test_etcd_v3_empty_page_with_more_is_not_complete(monkeypatch):
    monkeypatch.setattr(etcd, "_http_json_request", lambda *a, **kw: (200, '{"kvs":[],"more":true}'))
    values, error = etcd._stream_dump_v3_all(
        "qa", 2379, 1, batch=4, delay_ms=0, discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 5, 4096)
    )
    assert error == "pagination_stalled"


def test_etcd_v3_final_repeated_page_is_partial_even_without_more(monkeypatch):
    replies = iter(
        [
            {"kvs": [{"key": encoded("a/password"), "value": encoded("qa-first-secret")}], "more": True},
            {"kvs": [{"key": encoded("a/password"), "value": encoded("qa-first-secret")}], "more": False},
        ]
    )
    monkeypatch.setattr(etcd, "_http_json_request", lambda *a, **kw: (200, json.dumps(next(replies))))
    values, error = etcd._stream_dump_v3_all(
        "qa", 2379, 1, batch=1, delay_ms=0, discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 5, 4096)
    )
    assert error == "pagination_stalled"
    assert len(values) == 1


def test_etcd_spooled_txt_keeps_keys_next_to_dump_and_full_values(tmp_path):
    from pathlib import Path

    entries = SpoolingRecords()
    value = "qa-full-λ-" + "n" * 1200000
    entries.append({"key": "a/password", "value": value}, sort_key="a/password")
    entries.append({"key": "z/password", "value": "qa-last-secret"}, sort_key="z/password")
    record = {
        "host": "qa",
        "port": 2379,
        "key_value_entries": entries,
        "show_keys": True,
        "dump_keys": True,
        "show_keys_limit": 1,
        "key_count": 2,
        "keys": ["a/password", "z/password"],
    }
    path = etcd._spool_keys_details(record, dump_values=True)
    try:
        output = Path(path).read_text()
        assert output.index("a/password\n") < output.index("a/password:" + value)
        assert "[*] Dump Keys" in output and "z/password:qa-last-secret" in output
        assert "\x1b" not in output and "SpoolingRecords" not in output
    finally:
        Path(path).unlink(missing_ok=True)


def test_etcd_v3_retries_readonly_page_timeout_with_smaller_batch(monkeypatch):
    limits = []

    def get(*args, payload, **kwargs):
        limits.append(payload["limit"])
        if payload["limit"] > 1:
            raise urllib.error.URLError("timed out")
        return 200, json.dumps(
            {"kvs": [{"key": encoded("password"), "value": encoded("qa-real-secret")}], "more": False}
        )

    monkeypatch.setattr(etcd, "_http_json_request", get)
    values, error = etcd._stream_dump_v3_all(
        "qa", 2379, 1, batch=4, delay_ms=0, discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 5, 4096)
    )
    assert error is None and len(values) == 1
    assert limits == [4, 2, 1]


def test_etcd_v2_midbody_disconnect_keeps_only_complete_leaves():
    first = json.dumps({"key": "/a/password", "value": "qa-first-secret"}, separators=(",", ":")).encode()
    second = json.dumps({"key": "/z/password", "value": "qa-unfinished-secret"}, separators=(",", ":")).encode()
    body = b'{"action":"get","node":{"key":"/","dir":true,"nodes":[' + first + b"," + second[:30]

    class BrokenPool:
        def __init__(self, **_kwargs):
            pass

        def request_stream(self, _method, _url, **kwargs):
            kwargs["on_response"](200, {})
            for chunk in (body[:23], body[23:]):
                kwargs["on_chunk"](chunk)
            return SimpleNamespace(status=200, error="connection_reset", truncated=True)

        def close(self):
            pass

    with patch.object(etcd, "HttpSessionPool", BrokenPool):
        status, retained, error, received = etcd._stream_v2_tree(
            "127.0.0.1", 2379, 3, "/v2/keys?recursive=true", deadline=time.monotonic() + 3
        )

    assert status == 200
    assert error == "connection_reset"
    assert received == len(body)
    assert retained is not None
    assert [node["key"] for node in etcd._iter_v2_leaves(retained["node"])] == ["/a/password"]


def test_etcd_v3_midbody_disconnect_keeps_only_complete_kvs():
    first = json.dumps(
        {"key": encoded("a/password"), "value": encoded("qa-first-secret")}, separators=(",", ":")
    ).encode()
    second = json.dumps(
        {"key": encoded("z/password"), "value": encoded("qa-unfinished-secret")}, separators=(",", ":")
    ).encode()
    body = b'{"kvs":[' + first + b"," + second[:20]

    class BrokenPool:
        def __init__(self, **_kwargs):
            pass

        def request_stream(self, _method, _url, **kwargs):
            kwargs["on_response"](200, {})
            for chunk in (body[:19], body[19:]):
                kwargs["on_chunk"](chunk)
            return SimpleNamespace(status=200, error="connection_reset", truncated=True)

        def close(self):
            pass

    with patch.object(etcd, "HttpSessionPool", BrokenPool):
        status, retained, error, received = etcd._stream_v3_page(
            "127.0.0.1", 2379, 3, {"key": "AA=="}, auth_token=None, deadline=time.monotonic() + 3
        )

    assert status == 200
    assert error == "connection_reset"
    assert received == len(body)
    assert retained is not None
    assert [(item["key"], item["value"]) for item in retained["kvs"]] == [
        (encoded("a/password"), encoded("qa-first-secret"))
    ]


def test_etcd_v2_interrupted_probe_reports_partial_and_received_bytes(monkeypatch):
    def get(_host, _port, _method, path, _timeout, **_kwargs):
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14","etcdcluster":"3.5.0"}'
        if path.startswith("/v2/keys"):
            raise urllib.error.URLError("HTTP response exceeds limit")
        if path in {"/v3/auth/status", "/v3/kv/range"}:
            return 404, "{}"
        raise AssertionError(path)

    monkeypatch.setattr(etcd, "_http_json_request", get)
    monkeypatch.setattr(
        etcd,
        "_stream_v2_tree",
        lambda *_args, **_kwargs: (
            200,
            {"node": {"key": "/", "dir": True, "nodes": [{"key": "/a/password", "value": "qa-first-secret"}]}},
            "connection_reset",
            123,
        ),
    )
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover=True, discover_time=30),
        host="qa",
        port=2379,
        discovery_started_at=time.monotonic(),
    )
    record = etcd._audit_etcd_host("qa", 2379, 1, 0, False, True, None, discover=True, discover_ctx=ctx)
    discovery = record["content_discovery"]
    assert discovery["status"] == "partial"
    assert discovery["bytes_read"] == 123
    assert any("connection_reset" in reason for reason in discovery["partial_reasons"])
    assert [item["value"] for item in discovery["findings"]] == ["qa-first-secret"]


def test_etcd_discovery_starts_with_small_sample_before_large_batch(monkeypatch):
    requested = []

    def get(*args, payload, **kwargs):
        requested.append(payload["limit"])
        return 200, json.dumps(
            {"kvs": [{"key": encoded("password"), "value": encoded("qa-real-secret")}], "more": False}
        )

    monkeypatch.setattr(etcd, "_http_json_request", get)
    values, error = etcd._stream_dump_v3_all(
        "qa",
        2379,
        1,
        batch=10000,
        delay_ms=0,
        discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 5, 4000000),
    )
    assert error is None and len(values) == 1
    assert requested == [16]


def test_authenticated_etcd_without_keyspace_permission_is_unavailable(monkeypatch):
    from types import SimpleNamespace

    def get(_host, _port, _method, path, _timeout, **kwargs):
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14","etcdcluster":"3.5.0"}'
        if path.startswith("/v2/"):
            return 404, "{}"
        if path == "/v3/auth/status":
            return 200, '{"enabled":true}'
        if path == "/v3/kv/range":
            return 403, '{"error":"permission denied"}'
        raise AssertionError(path)

    monkeypatch.setattr(etcd, "_http_json_request", get)
    monkeypatch.setattr(etcd, "_etcd_v3_authenticate", lambda *a, **kw: ("qa-valid-token", None))
    monkeypatch.setattr(etcd, "_etcd_v2_authenticate", lambda *a, **kw: (False, "unsupported"))
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover=True, discover_time=30),
        host="qa",
        port=2379,
        discovery_started_at=time.monotonic(),
    )
    record = etcd._audit_etcd_host(
        "qa", 2379, 1, 0, False, True, None, username="qa", password="valid", discover=True, discover_ctx=ctx
    )
    assert record["provided_credentials_ok"] is True
    assert record["content_discovery"]["status"] == "unavailable"
    assert not record["content_discovery"]["findings"]
    assert record["api_has_access"]["v3"] is False
