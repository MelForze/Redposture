"""A single oversized etcd range row must still be discoverable."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
from types import SimpleNamespace
from typing import Any

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.etcd import actions as etcd
from redposture_core.storage_discovery import DiscoveryCollector


def test_single_oversized_v3_row_falls_back_to_stream_without_byte_budget(monkeypatch: Any) -> None:
    secret = "qa-streamed-etcd-password"
    key = base64.b64encode(b"app/password").decode()
    value = base64.b64encode(secret.encode()).decode()
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30),
        discovery_started_at=time.monotonic(),
        host="qa",
        port=2379,
        live_emit=lambda *_args: None,
    )
    collector = DiscoveryCollector("etcd", ctx, {"status": "open_no_auth"})
    calls: list[dict[str, Any]] = []

    def buffered(*_args: Any, payload: dict[str, Any], **_kwargs: Any) -> tuple[int, str]:
        calls.append(payload)
        raise urllib.error.URLError("HTTP response exceeds limit")

    def streamed(*_args: Any, **_kwargs: Any) -> tuple[int, dict[str, Any], None, int]:
        return 200, {"kvs": [{"key": key, "value": value}], "more": False}, None, 20_000_000

    monkeypatch.setattr(etcd, "_http_json_request", buffered)
    monkeypatch.setattr(etcd, "_stream_v3_page", streamed, raising=False)
    entries, error = etcd._stream_dump_v3_all(
        "qa",
        2379,
        1,
        batch=1,
        delay_ms=0,
        discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 30, 300_000_000, collector),
    )
    assert error is None
    assert [entry["key"] for entry in entries] == ["app/password"]
    assert [finding["value"] for finding in collector.result()["findings"]] == [secret]
    assert collector.bytes_read == 20_000_000
    assert len(calls) == 1


def test_streamed_v3_page_decodes_large_base64_value_in_chunks(monkeypatch: Any) -> None:
    secret = "qa-etcd-large-" + "A" * 1_200_000
    raw = json.dumps(
        {
            "kvs": [
                {
                    "key": base64.b64encode(b"qa/password").decode(),
                    "value": base64.b64encode(secret.encode()).decode(),
                }
            ],
            "more": False,
        }
    ).encode()

    class Pool:
        def request_stream(self, _method: str, _url: str, **kwargs: Any) -> Any:
            kwargs["on_response"](200, {})
            for offset in range(0, len(raw), 8191):
                kwargs["on_chunk"](raw[offset : offset + 8191])
            return SimpleNamespace(status=200, error=None, truncated=False)

    monkeypatch.setattr(
        etcd._ETCD_HTTP_LOCAL,
        "state",
        etcd._EtcdHttpLifecycle(pool=Pool(), scheme="http", host="127.0.0.1", port=2379),
        raising=False,
    )
    status, payload, error, count = etcd._stream_v3_page(
        "127.0.0.1",
        2379,
        2.0,
        {"key": "AA==", "range_end": "AA==", "limit": 1},
        auth_token=None,
        deadline=time.monotonic() + 10,
    )
    assert status == 200 and error is None and count == len(raw)
    assert payload is not None
    encoded = payload["kvs"][0]["value"]
    assert isinstance(encoded, DiskBackedText)
    decoded = etcd._b64_decode_discovery_value(encoded)
    assert isinstance(decoded, DiskBackedText)
    assert decoded.byte_length == len(secret)
    assert decoded.digest == hashlib.sha256(secret.encode()).hexdigest()
    assert "".join(decoded.iter_text_chunks()) == secret


def test_buffered_v3_page_spools_large_decoded_value_before_catalog_copy() -> None:
    """Buffered sub-4-MB pages must not retain every decoded value as str."""
    secret = "qa-etcd-buffered-" + "Ab0" * 166_667
    encoded = base64.b64encode(secret.encode()).decode()
    decoded = etcd._b64_decode_discovery_value(encoded)
    assert isinstance(decoded, DiskBackedText)
    assert decoded.byte_length == len(secret)
    assert decoded.digest == hashlib.sha256(secret.encode()).hexdigest()
    assert "".join(decoded.iter_text_chunks()) == secret
    decoded.close()


def test_selected_v3_key_uses_stream_after_buffered_limit(monkeypatch: Any) -> None:
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30),
        discovery_started_at=time.monotonic(),
        host="qa",
        port=2379,
        live_emit=lambda *_args: None,
    )
    collector = DiscoveryCollector("etcd", ctx, {"status": "open_no_auth"})
    monkeypatch.setattr(
        etcd,
        "_http_json_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(urllib.error.URLError("HTTP response exceeds limit")),
    )
    monkeypatch.setattr(
        etcd,
        "_stream_v3_page",
        lambda *_args, **_kwargs: (
            200,
            {
                "kvs": [
                    {
                        "key": base64.b64encode(b"/qa/password").decode(),
                        "value": base64.b64encode(b"qa-selected-secret").decode(),
                    }
                ]
            },
            None,
            20_000_000,
        ),
    )
    entry, error = etcd._dump_v3_key(
        "qa",
        2379,
        "/qa/password",
        1.0,
        discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 30, 300_000_000, collector),
    )
    assert error is None
    assert entry == {"key": "/qa/password", "value": "qa-selected-secret", "error": None}
    assert [item["value"] for item in collector.result()["findings"]] == ["qa-selected-secret"]


def test_oversized_v2_tree_is_streamed_before_v3_fallback(monkeypatch: Any) -> None:
    def buffered(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: Any) -> tuple[int, str]:
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14","etcdcluster":"3.5.0"}'
        if path == "/v2/keys?recursive=true":
            raise urllib.error.URLError("HTTP response exceeds limit")
        if path == "/v3/auth/status":
            return 200, '{"enabled":false}'
        if path == "/v3/kv/range":
            return 200, '{"kvs":[],"count":"0"}'
        raise AssertionError(path)

    monkeypatch.setattr(etcd, "_http_json_request", buffered)
    monkeypatch.setattr(
        etcd,
        "_stream_v2_tree",
        lambda *_args, **_kwargs: (
            200,
            {"node": {"key": "/", "dir": True, "nodes": [{"key": "/app/password", "value": "qa-v2-secret-value"}]}},
            None,
            20_000_000,
        ),
        raising=False,
    )
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30),
        discovery_started_at=time.monotonic(),
        host="qa",
        port=2379,
        live_emit=lambda *_args: None,
    )
    record = etcd._audit_etcd_host(
        "qa",
        2379,
        1.0,
        0,
        False,
        True,
        None,
        discover=True,
        discover_ctx=ctx,
    )
    discovery = record["content_discovery"]
    assert discovery["status"] == "complete"
    assert [item["value"] for item in discovery["findings"]] == ["qa-v2-secret-value"]
    assert record["api_has_access"]["v2"] is True


def test_large_v2_tree_does_not_hide_confirmed_etcd_during_detect(monkeypatch: Any) -> None:
    def buffered(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: Any) -> tuple[int, str]:
        if path == "/version":
            return 200, '{"etcdserver":"3.5.14","etcdcluster":"3.5.0"}'
        if path == "/v2/keys?recursive=true":
            raise urllib.error.URLError("HTTP response exceeds limit")
        if path == "/v3/auth/status":
            return 200, '{"enabled":false}'
        if path == "/v3/kv/range":
            return 200, '{"count":"0"}'
        raise AssertionError(path)

    monkeypatch.setattr(etcd, "_http_json_request", buffered)
    record = etcd._audit_etcd_host("qa", 2379, 1.0, 0, False, False, None)
    assert record["is_etcd"] is True
    assert record["status"] == "open_no_auth"
    assert record["server_version"] == "3.5.14"


def test_selected_v2_key_streams_and_reports_full_value(monkeypatch: Any) -> None:
    secret = "qa-v2-password-" + "A" * 1_200_000
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30),
        discovery_started_at=time.monotonic(),
        host="qa",
        port=2379,
        live_emit=lambda *_args: None,
    )
    collector = DiscoveryCollector("etcd", ctx, {"status": "open_no_auth"})
    value = DiskBackedText()
    value.append_text(secret)
    value.finish()
    monkeypatch.setattr(
        etcd,
        "_http_json_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(urllib.error.URLError("HTTP response exceeds limit")),
    )
    monkeypatch.setattr(
        etcd,
        "_stream_v2_tree",
        lambda *_args, **_kwargs: (
            200,
            {"node": {"key": "/qa/password", "value": value}},
            None,
            len(secret),
        ),
    )
    entry, error = etcd._dump_v2_key(
        "qa",
        2379,
        "/qa/password",
        1.0,
        discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 30, 300_000_000, collector),
    )
    assert error is None
    assert entry is not None and isinstance(entry["value"], DiskBackedText)
    assert entry["value"].digest == hashlib.sha256(secret.encode()).hexdigest()
    findings = collector.result()["findings"]
    assert len(findings) == 1
    assert findings[0]["value"].digest == hashlib.sha256(secret.encode()).hexdigest()


def test_selected_v2_discovery_does_not_read_other_keys(monkeypatch: Any) -> None:
    paths: list[str] = []

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: Any) -> tuple[int, str]:
        paths.append(path)
        if path == "/version":
            return 200, '{"etcdserver":"2.3.8"}'
        if path == "/v2/keys/qa/password":
            return 200, '{"node":{"key":"/qa/password","value":"qa-selected-secret"}}'
        raise AssertionError(f"unexpected broad read: {path}")

    monkeypatch.setattr(etcd, "_http_json_request", request)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30),
        discovery_started_at=time.monotonic(),
        host="qa",
        port=2379,
        live_emit=lambda *_args: None,
    )
    record = etcd._audit_etcd_host(
        "qa",
        2379,
        1.0,
        0,
        False,
        False,
        "/qa/password",
        discover=True,
        discover_ctx=ctx,
    )
    assert paths == ["/version", "/v2/keys/qa/password", "/v2/keys/qa/password"]
    assert record["content_discovery"]["status"] == "complete"
    assert [item["value"] for item in record["content_discovery"]["findings"]] == ["qa-selected-secret"]
