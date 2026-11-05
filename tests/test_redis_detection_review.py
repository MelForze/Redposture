"""Pure in-memory wire corpora for both Redis detection continuations."""

from __future__ import annotations

import asyncio
import socket
import time
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients.async_retained_socket import _BASE_REGISTRY, RetainedSocketIO, run_native
from redposture_core.modules.redis import actions


class Wire:
    def __init__(self, data: bytes, *, send_error: bool = False, fragment_size: int | None = None):
        self.data = bytearray(data)
        self.sent: list[bytes] = []
        self.send_error = send_error
        self.fragment_size = fragment_size

    def recv(self, count: int) -> bytes:
        if self.fragment_size is not None:
            count = min(count, self.fragment_size)
        value = bytes(self.data[:count])
        del self.data[:count]
        return value

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))
        if self.send_error:
            self.send_error = False
            raise BrokenPipeError("server sent DENIED and closed before PING")

    def settimeout(self, _timeout):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


def detect(data: bytes, route: str, monkeypatch, **wire_options):
    wire = Wire(data, **wire_options)
    state = actions.RedisAuditLifecycleState("qa", 6379, 1, 0, False, None, time.monotonic())
    ctx = SimpleNamespace(lifecycle_state=state)
    if route in {"sync", "legacy"}:
        monkeypatch.setattr(actions, "_open_redis_socket", lambda *_args, **_kwargs: wire)
        if route == "legacy":
            return actions._audit_redis_host("qa", 6379, 1, 0, None, None, False, False, False, None), wire
        return actions.redis_detect_hook(ctx).to_dict(), wire

    class MemoryIO(RetainedSocketIO):
        async def open(self, address: tuple[str, int], timeout: float | None = None, **options: Any) -> socket.socket:
            # A local unconnected Unix FD supplies socket method identities;
            # every read/write is intercepted, no listener/connection is made.
            sock = socket.socket(socket.AF_UNIX)
            self.sockets[sock] = timeout
            return sock

        async def recv(self, sock: socket.socket, count: int, *options: Any) -> bytes:
            return wire.recv(count)

        async def sendall(self, sock: socket.socket, data: bytes, *options: Any) -> None:
            wire.sendall(data)

    async def run():
        io = MemoryIO()
        try:
            result = await run_native(
                actions._redis_detect_hook_detect_steps(ctx),
                None,
                {**_BASE_REGISTRY, **actions._ASYNC_RETAINED_STEPS},
                io,
            )
            return result.to_dict()
        finally:
            io.close()

    return asyncio.run(run()), wire


INFO = b"redis_version:7.4.0\r\n"
BULK_INFO = b"$" + str(len(INFO)).encode() + b"\r\n" + INFO + b"\r\n"


@pytest.mark.parametrize("route", ["sync", "native"])
@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        (b"+PONG\r\n" + BULK_INFO, True),
        (b"+PONG\r\n", True),  # INFO EOF must not erase the proven PONG.
        (b"-NOAUTH Authentication required.\r\n", True),
        (b"-NOPERM this user has no permissions to run PING\r\n", True),
        (b"-LOADING Redis is loading the dataset in memory\r\n", True),
        (b"-BUSY Redis is busy running a script\r\n", True),
        (b"-ERR PING disabled\r\n" + BULK_INFO, True),
        (b"-ERR some unrelated service\r\n", False),
        (b"+OK\r\n", False),
        (b":1\r\n", False),
        (b"$4\r\nPONG\r\n", False),
        (b"HTTP/1.1 200 OK\r\n", False),
        (b"$4\r\nPONGxx", False),
    ],
)
def test_redis_detection_review_known_answers(monkeypatch, route, wire, expected):
    record, _transport = detect(wire, route, monkeypatch)
    assert record["is_redis"] is expected


@pytest.mark.parametrize("route", ["sync", "native", "legacy"])
@pytest.mark.parametrize("send_error", [False, True])
@pytest.mark.parametrize("fragment_size", [None, 1, 3])
def test_protected_mode_denial_before_eof_still_identifies_redis(monkeypatch, route, send_error, fragment_size):
    # Redis sends this branded DENIED response and closes a non-loopback
    # connection in protected mode. INFO cannot provide a second fingerprint.
    record, wire = detect(
        b"-DENIED Redis is running in protected mode\r\n",
        route,
        monkeypatch,
        send_error=send_error,
        fragment_size=fragment_size,
    )
    assert len(wire.sent) == 1  # No INFO/AUTH after the conclusive denial.
    assert record["is_redis"] is True
    assert record["auth_required"] is None  # protected-mode access != password proof
    assert record["protected_mode"] is True and record["access_denied"] is True
    assert record["credential_verification_status"] == "unavailable"


@pytest.mark.parametrize("route", ["sync", "native", "legacy"])
@pytest.mark.parametrize(
    "wire",
    [
        b"-DENIED OtherDB is running in protected mode\r\n",
        b"-DENIED Redis is running in protected mode-ish\r\n",
        b"-ERR Redis is running in protected mode\r\n",
        b"+DENIED Redis is running in protected mode\r\n",
        b"-DENIED Redis is running in protected mode\r",
    ],
)
def test_lookalike_or_incomplete_protected_denial_is_not_redis(monkeypatch, route, wire):
    record, _wire = detect(wire, route, monkeypatch)
    assert record["is_redis"] is False


@pytest.mark.parametrize("output_format", ["txt", "json"])
@pytest.mark.parametrize("credentials", ["none", "provided", "defaults"])
def test_protected_mode_runtime_keeps_detection_without_auth_or_data(tmp_path, output_format, credentials):
    import json
    import socketserver
    import threading

    from redposture_core.cli_args import parse_args
    from redposture_core.modules.redis import stage
    from redposture_core.stage_runtime import AuditCommandRunner

    calls = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            calls.append(self.request.recv(1024))
            self.request.sendall(b"-DENIED Redis is running in protected mode because protected mode is enabled.\r\n")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    path = tmp_path / ("redis." + output_format)
    argv = [
        "redis",
        "-t",
        f"127.0.0.1:{server.server_address[1]}",
        "--timeout",
        "1",
        "-r",
        "0",
        "--no-color",
        "-f",
        output_format,
        "-o",
        str(path),
        "--dump",
        "--discover",
    ]
    if credentials == "provided":
        argv.extend(["-u", "default", "-p", "correct"])
    if credentials == "defaults":
        argv.append("--defcreds")
    args = parse_args(argv)
    stage._prepare_redis_credential_runs(args)
    try:
        result = AuditCommandRunner(args=args, spec=stage.build_redis_spec(args), emit_line=lambda line: None).run_plan(
            stage.build_redis_plan(args)
        )
        assert result.detected_count == result.record_count == 1
        record = result.records[0]
        assert record["is_redis"] is True and record["protected_mode"] is True
        assert record["auth_required"] is None
        assert record["credential_verification_status"] == "unavailable"
        assert not record.get("attempted_credentials")
        assert record.get("key_values") is None
        # RedisInsight UI detection also probes HTTP/TLS on the same target.
        # Only RESP traffic must stop after the conclusive protected-mode PING.
        assert [data for data in calls if data.startswith(b"*")] == [actions._encode_resp_array(["PING"])]
        assert not any(b"AUTH" in data or b"INFO" in data or b"SCAN" in data for data in calls)
        text = path.read_text()
        assert "\x1b" not in text
        if output_format == "json":
            assert json.loads(text)["protected_mode"] is True
        else:
            assert "Redis Database" in text and "Protected Mode (access:denied)" in text
            assert "[-]" not in text and "Connection Failed" not in text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


def test_protected_mode_output_uses_airflow_denial_palette(capsys):
    from redposture_core.console import Console
    from tests.test_stage_color_renderers import _assert_parentheses_are_not_colored, _contains_paint, _RecordingConsole

    record = {"host": "qa", "port": 6379, "is_redis": True, "status": "unknown_auth", "protected_mode": True}
    line = actions._format_record(record, "txt")
    console = _RecordingConsole()
    assert actions._render_colored_redis_line(console, line)
    assert _contains_paint(console.paint_calls, "Protected Mode", "white")
    assert _contains_paint(console.paint_calls, "(access:denied)", "bright_green")
    _assert_parentheses_are_not_colored(console.paint_calls)
    assert actions._render_colored_redis_line(Console(no_color=True), line)
    assert "\x1b" not in capsys.readouterr().out
