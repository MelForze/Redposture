"""Redis discovery reads complete frames without allocating their advertised size."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.redis.discovery import RESPStreamReader


class ReadSocket:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.position = 0
        self.requests: list[int] = []

    def recv(self, size: int) -> bytes:
        self.requests.append(size)
        data = self.payload[self.position : self.position + size]
        self.position += len(data)
        return data

    def gettimeout(self) -> float:
        return 1.0

    def settimeout(self, timeout: float) -> None:
        assert timeout > 0

    def sendall(self, data: bytes) -> None:
        pass

    def close(self) -> None:
        pass


def bulk(data: bytes) -> bytes:
    return f"${len(data)}\r\n".encode() + data + b"\r\n"


@pytest.mark.parametrize("payload", [("λ🔑" * 20_000 + "tail").encode(), b"\xff\x00" * 30_000])
def test_large_resp_bulk_preserves_full_text_or_binary_without_large_recv(payload: bytes) -> None:
    sock = ReadSocket(bulk(payload))
    reader = RESPStreamReader(sock, deadline=time.monotonic() + 10, portion=31)
    kind, raw = reader.read()
    assert kind == "bulk"
    with raw:
        value = raw.text()
        assert isinstance(value, DiskBackedText)
        expected = "base64:" + base64.b64encode(payload).decode() if b"\xff" in payload else payload.decode()
        assert value.digest == hashlib.sha256(expected.encode()).hexdigest()
        assert "".join(value.iter_text_chunks()) == expected
        value.close()
    assert max(sock.requests) <= 31
    assert sock.position == len(sock.payload)


def test_resp_array_is_consumed_lazily_and_next_frame_remains_readable() -> None:
    sock = ReadSocket(b"*2\r\n" + bulk(b"a") + bulk(b"b") + b"+OK\r\n")
    reader = RESPStreamReader(sock, deadline=time.monotonic() + 10, portion=32)
    kind, values = reader.read()
    assert kind == "array" and sock.position == 4
    assert list(values) == [("bulk", b"a"), ("bulk", b"b")]
    assert reader.read() == ("simple", b"OK")


@pytest.mark.parametrize("ending", [b"", b"\r", b"xx"])
def test_incomplete_large_bulk_is_never_returned_as_a_value(ending: bytes) -> None:
    sock = ReadSocket(b"$1024\r\n" + b"q" * 1024 + ending)
    reader = RESPStreamReader(sock, deadline=time.monotonic() + 10, portion=32)
    with pytest.raises((ConnectionError, ValueError), match="EOF|bulk"):
        reader.read()


def test_resp_deadline_is_checked_between_bulk_portions() -> None:
    reader = RESPStreamReader(ReadSocket(bulk(b"x" * 1024)), deadline=time.monotonic() - 1, portion=32)
    with pytest.raises(TimeoutError, match="discover_time"):
        reader.read()


def test_discovery_keeps_full_large_value_and_emits_before_next_scan() -> None:
    from redposture_core.modules.redis import actions, discovery

    expected = "long-" + "aB3q" * 300_000 + "λ-tail"
    client, server = socket.socketpair()
    client.settimeout(3)
    seen: list[bytes] = []
    emissions: list[object] = []
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            with server:
                while True:
                    _kind, args = actions._read_resp(server)
                    seen.append(args[0])
                    if args[0] == b"SCAN":
                        if args[1] == b"0":
                            server.sendall(b"*2\r\n$1\r\n1\r\n*1\r\n" + bulk(b"api_token"))
                        else:
                            assert emissions, "finding did not arrive before the next page"
                            server.sendall(b"*2\r\n$1\r\n0\r\n*0\r\n")
                    elif args[0] == b"TYPE":
                        server.sendall(b"+string\r\n")
                    elif args[0] == b"GET":
                        server.sendall(bulk(expected.encode()))
                    else:
                        raise AssertionError(args)
        except (ConnectionError, OSError):
            pass
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    context = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, format="json"),
        host="qa",
        port=6379,
        discovery_started_at=time.monotonic(),
        live_discovery_value=lambda *a, **kw: emissions.append(kw["value"]),
        live_emit=None,
    )
    try:
        result = discovery.discover_redis(context, {"status": "open_no_auth"}, client)
        report = result["content_discovery"]
        assert report["status"] == "complete", report["partial_reasons"]
        findings = list(report["findings"])
        assert len(findings) == 1
        value = findings[0]["value"]
        assert value.digest == hashlib.sha256(expected.encode()).hexdigest()
        assert "key_value_entries.api_token" in findings[0]["object_path"]
        assert result["key_value_entries"] is None and result["key_values"] is None
        assert seen == [b"SCAN", b"TYPE", b"GET", b"SCAN"]
    finally:
        client.close()
        thread.join(4)
    assert not thread.is_alive()
    assert not errors


def test_redis_data_hook_uses_streaming_discovery_without_legacy_dump(monkeypatch) -> None:
    from redposture_core.audit_models import AuditRecord
    from redposture_core.modules.redis import actions, discovery

    state = actions.RedisAuditLifecycleState(
        host="qa",
        port=6379,
        timeout=1,
        retries=0,
        debug=False,
        debug_emit=None,
        started=time.monotonic(),
        sock=object(),
        status="open_no_auth",
        is_redis=True,
    )
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover=True, dump=True, _discover_implicit_dump=True), lifecycle_state=state
    )
    monkeypatch.setattr(actions, "_count_redis_keys", lambda sock: (500, None))
    called: list[object] = []

    def stream(context, prior, sock):
        called.append(sock)
        return {
            "content_discovery": {"status": "complete", "findings": []},
            "key_values": None,
            "key_value_entries": None,
        }

    monkeypatch.setattr(discovery, "discover_redis", stream)
    monkeypatch.setattr(
        actions, "_stream_dump_redis_keys", lambda *a, **kw: pytest.fail("legacy dump retained the values")
    )
    result = actions.redis_data_hook(
        ctx, AuditRecord.from_mapping({"host": "qa", "port": 6379, "status": "open_no_auth"}, module="redis")
    )
    assert called == [state.sock]
    assert result.extra["content_discovery"]["status"] == "complete"
    assert result.extra["key_values"] is None


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_explicit_dump_and_discover_preserve_large_value_without_repr(output_format) -> None:
    from redposture_core.modules.redis.discovery import discover_redis

    expected = "exact-" + "r" * 100_000 + "λ-tail"
    sock = ReadSocket(b"*2\r\n$1\r\n0\r\n*1\r\n" + bulk(b"api_token") + b"+string\r\n" + bulk(expected.encode()))
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, output_format=output_format, dump=True, _discover_implicit_dump=False),
        host="qa",
        port=6379,
        live_emit=None,
        discovery_started_at=time.monotonic(),
    )
    result = discover_redis(ctx, {"status": "open_no_auth"}, sock)
    entry = result["key_value_entries"][0]
    assert entry["value"].digest == hashlib.sha256(expected.encode()).hexdigest()
    saved = "".join(iter_json_chunks(result["key_value_entries"]))
    assert expected in saved and "DiskBackedText object" not in saved
    if output_format == "txt":
        assert result["_redis_streamed_details"] is True
        path = Path(result["_stream_lines_file"])
        try:
            text = path.read_text()
            assert "Dump Keys" in text and f"api_token:{expected}" in text
            assert "\x1b[" not in text and " object at " not in text
        finally:
            path.unlink()
    else:
        assert "_stream_lines_file" not in result


def test_runtime_stream_file_bounds_each_read_of_a_long_value(tmp_path, monkeypatch, capsys) -> None:
    import builtins

    from redposture_core.stage_runtime import LineOutputSink

    source = tmp_path / "source.txt"
    target = tmp_path / "saved.txt"
    expected = "full-" + "q" * 200_000 + "λ-tail"
    source.write_text(f"REDIS\tqa\t6379\tapi_token:{expected}\n")
    original_open = builtins.open

    class BoundedReader:
        def __init__(self):
            self.reader = original_open(source, encoding="utf-8")

        def __iter__(self):
            raise AssertionError("whole-line iteration allocated the entire Redis value")

        def readline(self, size=-1):
            assert 0 < size <= 65_536
            return self.reader.readline(size)

        def close(self):
            self.reader.close()

    monkeypatch.setattr(
        builtins,
        "open",
        lambda path, *a, **kw: BoundedReader() if str(path) == str(source) else original_open(path, *a, **kw),
    )
    sink = LineOutputSink(str(target), lambda line: print(line))
    try:
        assert sink.emit_stream_file(str(source)) == 1
    finally:
        sink.close()
    assert expected in capsys.readouterr().out
    assert expected in target.read_text()


def context(**args):
    return SimpleNamespace(
        args=SimpleNamespace(discover_time=30, format="json", **args),
        host="qa",
        port=6379,
        live_emit=None,
        discovery_started_at=time.monotonic(),
    )


def test_manual_dump_limit_does_not_stop_secret_discovery() -> None:
    from redposture_core.modules.redis.discovery import discover_redis

    page = b"*2\r\n$1\r\n0\r\n*3\r\n" + bulk(b"a") + bulk(b"b") + bulk(b"api_token")
    sock = ReadSocket(
        page
        + b"+string\r\n"
        + bulk(b"one")
        + b"+string\r\n"
        + bulk(b"two")
        + b"+string\r\n"
        + bulk(b"last-token-value")
    )
    result = discover_redis(context(dump=2, show_keys=1), {"status": "open_no_auth"}, sock)
    assert len(result["key_value_entries"]) == 2
    assert list(result["keys"]) == ["a"]
    assert result["content_discovery"]["status"] == "complete"
    assert any(finding["value"] == "last-token-value" for finding in result["content_discovery"]["findings"])


def test_all_key_values_denied_are_unavailable_not_complete() -> None:
    from redposture_core.modules.redis.discovery import discover_redis

    page = b"*2\r\n$1\r\n0\r\n*1\r\n" + bulk(b"secret")
    result = discover_redis(context(), {"status": "open_no_auth"}, ReadSocket(page + b"-NOPERM TYPE denied\r\n"))
    assert result["content_discovery"]["status"] == "unavailable"
    assert result["content_discovery"]["findings"] == []


def test_corrupt_later_value_keeps_completed_findings() -> None:
    from redposture_core.modules.redis.discovery import discover_redis

    page = b"*2\r\n$1\r\n0\r\n*2\r\n" + bulk(b"first_token") + bulk(b"second_token")
    sock = ReadSocket(page + b"+string\r\n" + bulk(b"first-real-value") + b"+string\r\n$100000\r\npartial")
    result = discover_redis(context(), {"status": "open_no_auth"}, sock)
    assert result["content_discovery"]["status"] == "partial"
    assert [item["value"] for item in result["content_discovery"]["findings"]] == ["first-real-value"]


def test_repeated_scan_cursor_is_partial_without_repeating_the_first_finding() -> None:
    from redposture_core.modules.redis.discovery import discover_redis

    page = b"*2\r\n" + bulk(b"1") + b"*1\r\n" + bulk(b"api_token")
    wire = ReadSocket(page + b"+string\r\n" + bulk(b"first-real-value") + page)
    report = discover_redis(context(), {"status": "open_no_auth"}, wire)["content_discovery"]
    assert report["status"] == "partial"
    assert any("repeated_scan_cursor" in reason for reason in report["partial_reasons"])
    assert [item["value"] for item in report["findings"]] == ["first-real-value"]


@pytest.mark.parametrize("key", ["config", "api_token"])
def test_large_redis_json_is_scanned_as_fields_not_as_one_secret(key) -> None:
    from redposture_core.modules.redis.discovery import discover_redis

    payload = json.dumps(
        {"notes": "ordinary daily report " * 60_000, "credentials": {"password": "late-real-password"}}
    ).encode()
    page = b"*2\r\n$1\r\n0\r\n*1\r\n" + bulk(key.encode())
    result = discover_redis(context(), {"status": "open_no_auth"}, ReadSocket(page + b"+string\r\n" + bulk(payload)))
    report = result["content_discovery"]
    assert report["status"] == "complete", report["partial_reasons"]
    found = list(report["findings"])
    assert len(found) == 1
    assert found[0]["value"] == "late-real-password"
    assert found[0]["object_path"].endswith("credentials.password")


def resp(value):
    if isinstance(value, list):
        return f"*{len(value)}\r\n".encode() + b"".join(resp(item) for item in value)
    if isinstance(value, int):
        return f":{value}\r\n".encode()
    return bulk(value)


def test_redis_zset_scans_members_and_never_interprets_scores_as_passwords():
    from redposture_core.modules.redis.discovery import discover_redis

    token = b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    wire = ReadSocket(resp([b"0", [b"sample"]]) + b"+zset\r\n" + resp([token, b"1", b"password", b"123456"]))
    report = discover_redis(context(), {"status": "open_no_auth"}, wire)["content_discovery"]
    assert report["status"] == "complete"
    assert [item["value"] for item in report["findings"]] == [token.decode()]


def test_redis_stream_reads_entry_values_instead_of_just_length():
    from redposture_core.modules.redis.discovery import discover_redis

    wire = ReadSocket(
        resp([b"0", [b"events"]]) + b"+stream\r\n" + resp([[b"1-0", [b"password", b"qa-stream-secret"]]]) + resp([])
    )
    ctx = context()
    positions = []
    ctx.live_emit = lambda line: positions.append(wire.position)
    report = discover_redis(ctx, {"status": "open_no_auth"}, wire)["content_discovery"]
    assert report["status"] == "complete", report["partial_reasons"]
    assert [item["value"] for item in report["findings"]] == ["qa-stream-secret"]
    assert positions[0] < len(wire.payload)


def test_redis_stream_repeated_id_is_partial_and_keeps_previous_secret():
    from redposture_core.modules.redis.discovery import discover_redis

    first = resp([[b"1-0", [b"password", b"qa-first-secret"]]])
    wire = ReadSocket(resp([b"0", [b"events"]]) + b"+stream\r\n" + first + first)
    report = discover_redis(context(), {"status": "open_no_auth"}, wire)["content_discovery"]
    assert report["status"] == "partial"
    assert any("pagination stalled" in reason for reason in report["partial_reasons"])
    assert [item["value"] for item in report["findings"]] == ["qa-first-secret"]


def test_redis_stream_truncated_later_entry_keeps_completed_values():
    from redposture_core.modules.redis.discovery import discover_redis

    first = resp([[b"1-0", [b"password", b"qa-first-secret"]]])
    wire = ReadSocket(
        resp([b"0", [b"events"]])
        + b"+stream\r\n"
        + first
        + b"*1\r\n*2\r\n"
        + bulk(b"2-0")
        + b"*2\r\n"
        + bulk(b"password")
        + b"$100000\r\nincomplete"
    )
    report = discover_redis(context(), {"status": "open_no_auth"}, wire)["content_discovery"]
    assert report["status"] == "partial"
    assert [item["value"] for item in report["findings"]] == ["qa-first-secret"]
