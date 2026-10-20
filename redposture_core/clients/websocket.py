"""Bounded JSON WebSocket streams over the existing target HTTP transport."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Any
from urllib.parse import urlsplit

from .http_session import HttpSessionPool


class WebSocket:
    """One non-replayed stream; pool shutdown interrupts its active socket."""

    def __init__(self, pool: HttpSessionPool, url: str, *, headers: dict[str, str], timeout: float, max_bytes: int):
        self.pool, self.url, self.headers = pool, url, headers
        self.deadline = time.monotonic() + timeout
        self.max_bytes = max_bytes
        self.received = 0
        self.frames = 0
        self.buffer = bytearray()
        self.connection: Any = None
        self.sock: Any = None
        self._socket_ref: Any = None
        parsed = urlsplit(url)
        self.key = (parsed.scheme, str(parsed.hostname), parsed.port or (443 if parsed.scheme == "https" else 80))

    def _timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("execution stream deadline reached")
        return remaining

    def __enter__(self) -> WebSocket:
        parsed = urlsplit(self.url)
        try:
            # Reuse TLS, mTLS, SOCKS/HTTP proxy and pool cancellation behavior.
            self.connection = self.pool._new_connection(self.key, self._timeout())
            if self.connection.sock is None:
                self.connection.connect()
            self.sock = self.connection.sock
            # Keep the descriptor alive while pool.close() calls shutdown and
            # closes HTTPConnection. On macOS closing a descriptor underneath
            # a concurrent select()/recv can leave that reader asleep until
            # timeout. A file reference defers the actual descriptor close.
            self._socket_ref = self.sock.makefile("rb", buffering=0)
            with self.pool._lock:
                if self.pool._closed:
                    raise RuntimeError("HTTP session pool is closed")
                self.pool._active_sockets.add(self.sock)
            key = base64.b64encode(os.urandom(16)).decode()
            headers = {
                "Host": parsed.netloc,
                "Origin": f"{parsed.scheme}://{parsed.netloc}",
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": key,
                **self.headers,
            }
            path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
            request = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
            self.sock.settimeout(self._timeout())
            self.sock.sendall(request.encode())
            while b"\r\n\r\n" not in self.buffer:
                if len(self.buffer) > 65536:
                    raise ConnectionError("WebSocket handshake header limit")
                self.sock.settimeout(self._timeout())
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ConnectionError("WebSocket handshake EOF")
                self.buffer.extend(chunk)
            raw, rest = bytes(self.buffer).split(b"\r\n\r\n", 1)
            self.buffer = bytearray(rest)
            rows = raw.decode("latin1").split("\r\n")
            if len(rows[0].split()) < 2 or rows[0].split()[1] != "101":
                raise ConnectionError(f"WebSocket handshake HTTP {rows[0].split()[1:2]}")
            response = {k.strip().lower(): v.strip() for row in rows[1:] if ":" in row for k, v in [row.split(":", 1)]}
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            if (
                response.get("sec-websocket-accept") != accept
                or response.get("upgrade", "").lower() != "websocket"
                or "upgrade" not in response.get("connection", "").lower()
            ):
                raise ConnectionError("invalid WebSocket upgrade")
            return self
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        try:
            with self.pool._lock:
                self.pool._active_sockets.discard(self.sock)
            if self.connection is not None:
                self.pool._release(self.key, self.connection, False)
                self.connection = None
        finally:
            if self._socket_ref is not None:
                self._socket_ref.close()
                self._socket_ref = None

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _read(self, size: int) -> bytes:
        while len(self.buffer) < size:
            self.sock.settimeout(self._timeout())
            chunk = self.sock.recv(min(65536, size - len(self.buffer)))
            if not chunk:
                raise ConnectionError("execution stream closed before completion")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def _send(self, opcode: int, body: bytes) -> None:
        if len(body) > self.max_bytes:
            raise ValueError("execution request exceeds stream byte limit")
        mask = os.urandom(4)
        length = len(body)
        prefix = bytes([0x80 | opcode])
        prefix += (
            bytes([0x80 | length])
            if length < 126
            else b"\xfe" + length.to_bytes(2, "big")
            if length < 65536
            else b"\xff" + length.to_bytes(8, "big")
        )
        self.sock.settimeout(self._timeout())
        self.sock.sendall(prefix + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(body)))

    def send_json(self, value: Any) -> None:
        self._send(1, json.dumps(value).encode())

    def recv_json(self) -> Any:
        message = bytearray()
        started = False
        while True:
            self.frames += 1
            if self.frames > 10000:
                raise ValueError("execution stream frame limit")
            a, b = self._read(2)
            opcode, fin = a & 15, bool(a & 128)
            if a & 112 or b & 128:
                raise ValueError("unsupported WebSocket frame flags")
            length = b & 127
            if length == 126:
                length = int.from_bytes(self._read(2), "big")
            elif length == 127:
                length = int.from_bytes(self._read(8), "big")
            if self.received + length > self.max_bytes:
                raise ValueError("execution stream byte limit reached")
            self.received += length
            if opcode >= 8 and (not fin or length > 125):
                raise ValueError("invalid WebSocket control frame")
            body = self._read(length)
            if opcode == 8:
                raise ConnectionError("execution stream closed before completion")
            if opcode == 9:
                self._send(10, body)
                continue
            if opcode == 10:
                continue
            if opcode not in {0, 1} or (opcode == 0 and not started) or (opcode == 1 and started):
                raise ValueError("unexpected WebSocket message type")
            started = True
            message.extend(body)
            if fin:
                return json.loads(message.decode("utf-8"))
