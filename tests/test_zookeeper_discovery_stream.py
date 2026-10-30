from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from redposture_core.discovery_bytes import SpoolBytes
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.zookeeper import actions
from redposture_core.modules.zookeeper.discovery import discover_znodes


def test_discover_traverses_past_legacy_2000_znode_limit_and_preserves_large_value() -> None:
    secret = "qa-" + "S" * 1_000_000
    raw = ('{"password":"' + secret + '"}').encode()
    names = [f"node-{index:04d}" for index in range(2_001)]

    class Client:
        def get_data_discovery(self, path: str, *, deadline: float | None = None) -> Any:
            if path == "/node-2000":
                spool = SpoolBytes()
                spool.write(raw)
                return spool, 0, {"data_length": len(raw), "num_children": 0}
            return b"", 0, {"data_length": 0, "num_children": 0}

        def read_children_discovery(self, path: str, callback: Any, *, deadline: float | None = None) -> Any:
            if path == "/":
                for name in names:
                    callback(name)
                return 0, {"data_length": 0, "num_children": len(names)}
            return 0, {"data_length": 0, "num_children": 0}

    ctx = SimpleNamespace(
        args=SimpleNamespace(
            discover=True, discover_time=30, dump=True, _discover_implicit_dump=True, show_znodes=False
        ),
        discovery_started_at=time.monotonic(),
        live_emit=lambda *_args: None,
    )
    result = discover_znodes(ctx, {"status": "open_no_auth"}, Client(), {"query_znode": None, "dump_limit": None})
    report = result["content_discovery"]
    assert report["status"] == "complete"
    assert result["znode_count"] == 2_001
    matching = [
        item
        for item in report["findings"]
        if hashlib.sha256(
            "".join(item["value"].iter_text_chunks()).encode()
            if isinstance(item["value"], DiskBackedText)
            else str(item["value"]).encode()
        ).hexdigest()
        == hashlib.sha256(secret.encode()).hexdigest()
    ]
    assert len(matching) == 1
    assert "node-2000" in matching[0]["object_path"]


def test_lifecycle_routes_implicit_discovery_around_legacy_byte_and_node_caps(monkeypatch: Any) -> None:
    class Client:
        def get_data_discovery(self, path: str, *, deadline: float | None = None) -> Any:
            return b'{"password":"qa-secret-value"}' if path == "/" else b"", 0, None

        def read_children_discovery(self, path: str, callback: Any, *, deadline: float | None = None) -> Any:
            return 0, None

    client = Client()
    state = actions.ZooKeeperLifecycleState(anonymous_client=client)
    monkeypatch.setattr(actions, "_refresh_zookeeper_lifecycle_client", lambda *_a, **_k: (client, None))
    ctx = SimpleNamespace(
        lifecycle_state=state,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        host="127.0.0.1",
        port=2181,
        args=SimpleNamespace(discover=True, discover_time=30, dump=True, _discover_implicit_dump=True),
        discovery_started_at=time.monotonic(),
        live_emit=lambda *_args: None,
        debug_emit=None,
    )
    result = actions.collect_zookeeper_data(
        ctx,
        {"module": "zookeeper", "status": "open_no_auth"},
        {"show_znodes": False, "dump": True, "query_znode": None, "max_znodes": 1, "dump_limit": None},
    )
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["value"] == "qa-secret-value" for item in result["content_discovery"]["findings"])


def test_explicit_discovery_dump_streams_full_json_and_txt() -> None:
    secret = "unicode-λ-" + "X" * 1_000_000

    class Client:
        def get_data_discovery(self, path: str, *, deadline: float | None = None) -> Any:
            return ('{"password":"' + secret + '"}').encode(), 0, None

        def read_children_discovery(self, path: str, callback: Any, *, deadline: float | None = None) -> Any:
            return 0, None

    for fmt in ("txt", "json"):
        ctx = SimpleNamespace(
            args=SimpleNamespace(
                discover=True, discover_time=30, dump=True, _discover_implicit_dump=False, output_format=fmt
            ),
            discovery_started_at=time.monotonic(),
            host="127.0.0.1",
            port=2181,
            live_emit=lambda *_args: None,
            live_discovery_value=lambda *_args, **_kwargs: None,
        )
        result = discover_znodes(
            ctx,
            {"status": "open_no_auth", "module": "zookeeper"},
            Client(),
            {"query_znode": None, "dump": True, "show_znodes": False},
        )
        stream = result["_stream_lines_file"]
        raw = Path(stream).read_text(encoding="utf-8")
        Path(stream).unlink()
        if fmt == "json":
            record = json.loads(raw)
            assert record["type"] == "znodes_dump"
            assert record["znode_values"] == ["/:" + '{"password":"' + secret + '"}']
        else:
            assert secret in raw and "DiskBackedText" not in raw
        assert "\x1b[" not in raw


def test_discovery_keeps_completed_finding_after_later_transport_failure() -> None:
    class Client:
        sock: object | None = object()

        def get_data_discovery(self, path: str, *, deadline: float | None = None) -> Any:
            if path == "/a":
                return b'{"password":"first-secret-value"}', 0, None
            if path == "/b":
                self.sock = None
                raise ConnectionError("unexpected EOF")
            return b"", 0, None

        def read_children_discovery(self, path: str, callback: Any, *, deadline: float | None = None) -> Any:
            if path == "/":
                callback("a")
                callback("b")
            return 0, None

    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, _discover_implicit_dump=True),
        discovery_started_at=time.monotonic(),
        host="127.0.0.1",
        port=2181,
        live_emit=lambda *_args: None,
    )
    result = discover_znodes(ctx, {"module": "zookeeper", "status": "open_no_auth"}, Client(), {})
    report = result["content_discovery"]
    assert report["status"] == "partial"
    assert any(item["value"] == "first-secret-value" for item in report["findings"])
    assert any("unexpected EOF" in reason for reason in report["partial_reasons"])


def test_discovery_does_not_call_long_benign_text_a_secret() -> None:
    class Client:
        def get_data_discovery(self, path: str, *, deadline: float | None = None) -> Any:
            spool = SpoolBytes()
            spool.write(b"x" * 1_000_000)
            return spool, 0, None

        def read_children_discovery(self, path: str, callback: Any, *, deadline: float | None = None) -> Any:
            return 0, None

    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, _discover_implicit_dump=True),
        discovery_started_at=time.monotonic(),
        host="127.0.0.1",
        port=2181,
        live_emit=lambda *_args: None,
    )
    result = discover_znodes(ctx, {"module": "zookeeper", "status": "open_no_auth"}, Client(), {})
    report = result["content_discovery"]
    assert report["status"] == "complete"
    assert report["findings"] == []


def test_selected_binary_znode_is_dumped_as_base64_without_scanning_or_children() -> None:
    class Client:
        def get_data_discovery(self, path: str, *, deadline: float | None = None) -> Any:
            assert path == "/binary"
            spool = SpoolBytes()
            spool.write(b"\xff\x00secret")
            return spool, 0, None

        def read_children_discovery(self, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("selected znode must not traverse children")

    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, _discover_implicit_dump=False, output_format="json"),
        discovery_started_at=time.monotonic(),
        host="127.0.0.1",
        port=2181,
        live_emit=lambda *_args: None,
    )
    result = discover_znodes(
        ctx,
        {"module": "zookeeper", "status": "open_no_auth"},
        Client(),
        {"query_znode": "/binary", "dump": True, "show_znodes": True},
    )
    assert result["content_discovery"]["status"] == "complete"
    assert result["content_discovery"]["findings"] == []
    assert result["znode_count"] is None
    stream = Path(result["_stream_lines_file"])
    rows = [json.loads(line) for line in stream.read_text().splitlines()]
    stream.unlink()
    assert rows[0]["znodes"] == ["/binary"]
    assert rows[1]["znode_values"] == ["/binary:<base64:" + base64.b64encode(b"\xff\x00secret").decode() + ">"]


def test_zookeeper_discovery_preserves_finding_when_later_child_denies_access() -> None:
    class Client:
        def get_data_discovery(self, path: str, *, deadline: float | None = None) -> Any:
            if path == "/secret":
                return b'{"password":"first-secret-value"}', 0, None
            if path == "/denied":
                return None, -102, None
            return None, 0, None

        def read_children_discovery(self, path: str, callback: Any, *, deadline: float | None = None) -> Any:
            if path == "/":
                callback("secret")
                callback("denied")
                return 0, None
            if path == "/denied":
                return -102, None
            return 0, None

    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, _discover_implicit_dump=False, output_format="txt"),
        discovery_started_at=time.monotonic(),
        host="127.0.0.1",
        port=2181,
        live_emit=lambda *_args: None,
    )
    result = discover_znodes(
        ctx,
        {"module": "zookeeper", "status": "open_no_auth"},
        Client(),
        {"dump": True, "show_znodes": True},
    )
    report = result["content_discovery"]
    assert report["status"] == "partial"
    assert any(item["value"] == "first-secret-value" for item in report["findings"])
    assert any("access_denied" in reason for reason in report["partial_reasons"])
    stream = Path(result["_stream_lines_file"])
    raw = stream.read_text()
    stream.unlink()
    assert "<Access Denied>" in raw and "first-secret-value" in raw
    assert "\x1b[" not in raw
