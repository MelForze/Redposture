"""Kubernetes exec websocket state handling without a live cluster."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from redposture_core.modules.kubeapi import actions as kube


def frame(opcode: int, payload: bytes = b"", *, final: bool = True) -> bytes:
    header = bytes([(0x80 if final else 0) | opcode])
    return (
        header + (bytes([len(payload)]) if len(payload) < 126 else b"\x7e" + len(payload).to_bytes(2, "big")) + payload
    )


class Socket:
    def __init__(self, frames: bytes = b"", handshake: str = "valid", timeout: bool = False) -> None:
        self.frames = frames
        self.handshake = handshake
        self.timeout = timeout
        self.buffer = b""
        self.sent: list[bytes] = []
        self.closed = False

    def settimeout(self, value: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        if data.startswith(b"GET "):
            key = next(
                line.split(": ", 1)[1] for line in data.decode().split("\r\n") if line.startswith("Sec-WebSocket-Key:")
            )
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            if self.handshake == "invalid_accept":
                accept = "wrong"
            upgrade = "not-websocket" if self.handshake == "invalid_upgrade" else "websocket"
            if self.handshake == "denied":
                self.buffer = b"HTTP/1.1 403 Forbidden\r\n\r\nForbidden"
            elif self.handshake == "oversized":
                self.buffer = b"HTTP/1.1 101 OK\r\nHeader: " + b"x" * 65537
            elif self.handshake == "eof":
                self.buffer = b""
            else:
                self.buffer = (
                    f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: {upgrade}\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode() + self.frames

    def recv(self, count: int) -> bytes:
        if not self.buffer and self.timeout:
            raise TimeoutError("read timeout")
        chunk, self.buffer = self.buffer[:count], self.buffer[count:]
        return chunk

    def close(self) -> None:
        self.closed = True


def execute(monkeypatch: pytest.MonkeyPatch, sock: Socket, retries: int = 0) -> dict[str, Any]:
    monkeypatch.setattr(kube.socket, "create_connection", lambda *args, **kwargs: sock)
    return kube._kube_exec_ws(
        "qa",
        6443,
        "team/a",
        "pod a",
        "printf qa",
        0.1,
        use_https=False,
        insecure=False,
        ca_file=None,
        token="verified",
        retries=retries,
    )


def test_kube_fragmented_stdout_ping_and_terminal_status(monkeypatch: pytest.MonkeyPatch) -> None:
    status = b"\x03" + json.dumps({"status": "Success"}).encode()
    sock = Socket(
        frame(2, b"\x01hel", final=False)
        + frame(9, b"ping")
        + frame(10, b"pong")
        + frame(0, b"lo")
        + frame(2, b"\x02diagnostic")
        + frame(2, status)
        + frame(8)
    )
    result = execute(monkeypatch, sock)
    assert result["ok"] is True and result["exit_code"] == 0
    assert result["stdout"] == "hello" and result["stderr"] == "diagnostic" and result["error"] is None
    assert sock.closed and len(sock.sent) == 3
    assert sock.sent[1][0] == 0x8A and sock.sent[2][0] == 0x88
    request = sock.sent[0].decode()
    assert "/namespaces/team%2Fa/pods/pod%20a/exec?" in request and "Authorization: Bearer verified" in request


@pytest.mark.parametrize(
    "mode,error",
    [
        ("unexpected", "unexpected websocket continuation frame"),
        ("interleaved", "interleaved websocket fragmented messages"),
        ("incomplete", "exec websocket closed with an incomplete fragmented message"),
        ("closed", "exec websocket closed before terminal status"),
        ("timeout", "exec websocket timed out before terminal status"),
    ],
)
def test_kube_stream_requires_terminal_status_and_valid_fragment_order(
    monkeypatch: pytest.MonkeyPatch, mode: str, error: str
) -> None:
    packets = {
        "unexpected": frame(0, b"orphan"),
        "interleaved": frame(2, b"\x01partial", final=False) + frame(2, b"\x01other"),
        "incomplete": frame(2, b"\x01partial", final=False) + frame(8),
        "closed": frame(8),
        "timeout": b"",
    }
    sock = Socket(packets[mode], timeout=mode == "timeout")
    result = execute(monkeypatch, sock)
    assert result["ok"] is False and result["exit_code"] is None and result["error"] == error
    assert sock.closed


@pytest.mark.parametrize(
    "handshake,error",
    [
        ("invalid_accept", "invalid server accept"),
        ("invalid_upgrade", "invalid upgrade headers"),
        ("denied", "Forbidden"),
        ("oversized", "headers too large"),
        ("eof", "unexpected EOF"),
    ],
)
def test_kube_handshake_fault_never_claims_execution(
    monkeypatch: pytest.MonkeyPatch, handshake: str, error: str
) -> None:
    sock = Socket(handshake=handshake)
    result = execute(monkeypatch, sock, retries=3)
    assert result["ok"] is False and error in result["error"] and sock.closed
    assert len([data for data in sock.sent if data.startswith(b"GET ")]) == 1


def test_kube_binary_capture_and_text_capture_use_shared_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kube, "DEFAULT_CAPTURE_BYTES", 4)
    sock = Socket(
        frame(2, b"\x01\x00\x01\x02\x03\x04\x05")
        + frame(2, b"\x02abcdef")
        + frame(2, b'\x03{"status":"Success"}')
        + frame(8)
    )
    result = execute(monkeypatch, sock)
    assert result["ok"] is True and result["stdout"] == "[binary 6 B]" and result["stderr"] == "abcd"
    assert result["stdout_base64"] == base64.b64encode(b"\x00\x01\x02\x03").decode()
    assert result["stderr_base64"] == base64.b64encode(b"abcd").decode()
    assert result["stdout_total"] == result["stderr_total"] == 6
    assert result["stdout_truncated"] is result["stderr_truncated"] is True


def test_kube_setup_failure_retries_before_upgrade_only(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    sock = Socket(frame(2, b'\x03{"status":"Success"}') + frame(8))

    def connect(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        if len(calls) == 1:
            raise OSError("connection reset")
        return sock

    monkeypatch.setattr(kube.socket, "create_connection", connect)
    monkeypatch.setattr(kube.time, "sleep", lambda delay: None)
    result = kube._kube_exec_ws(
        "qa", 6443, "default", "pod", "true", 0.1, use_https=False, insecure=False, ca_file=None, retries=2
    )
    assert result["ok"] is True and len(calls) == 2 and sock.closed
