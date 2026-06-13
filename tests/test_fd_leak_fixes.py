from __future__ import annotations

import ssl
from pathlib import Path

import pytest

import redposture_core.clients.grpc as grpc
from redposture_core.stage_runtime import LineOutputSink


class _FakeSock:
    def __init__(self, alpn: str | None = "h2") -> None:
        self.closed = False
        self.timeout: float | None = None
        self._alpn = alpn

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def selected_alpn_protocol(self) -> str | None:
        return self._alpn

    def close(self) -> None:
        self.closed = True


class _Ctx:
    def __init__(self, wrapped: _FakeSock | None, *, wrap_raises: bool = False) -> None:
        self.check_hostname = True
        self.verify_mode: object = None
        self._wrapped = wrapped
        self._wrap_raises = wrap_raises

    def set_alpn_protocols(self, _protocols: list[str]) -> None:
        pass

    def wrap_socket(self, _sock: object, server_hostname: str | None = None) -> _FakeSock:
        if self._wrap_raises:
            raise ssl.SSLError("tls handshake failed")
        assert self._wrapped is not None
        return self._wrapped


def test_open_grpc_socket_closes_base_on_wrap_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    base = _FakeSock()
    monkeypatch.setattr(grpc.socket, "create_connection", lambda *_a, **_k: base)
    monkeypatch.setattr(grpc.ssl, "create_default_context", lambda: _Ctx(None, wrap_raises=True))
    with pytest.raises(ssl.SSLError):
        grpc._open_grpc_socket("h", 443, 2.0, use_tls=True)
    assert base.closed is True  # base socket must be closed on handshake failure


def test_open_grpc_socket_closes_wrapped_on_alpn_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    base = _FakeSock()
    wrapped = _FakeSock(alpn="http/1.1")  # not h2 -> must raise and close wrapped
    monkeypatch.setattr(grpc.socket, "create_connection", lambda *_a, **_k: base)
    monkeypatch.setattr(grpc.ssl, "create_default_context", lambda: _Ctx(wrapped))
    with pytest.raises(OSError):
        grpc._open_grpc_socket("h", 443, 2.0, use_tls=True)
    assert wrapped.closed is True


def test_open_http_socket_closes_base_on_wrap_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    base = _FakeSock()
    monkeypatch.setattr(grpc.socket, "create_connection", lambda *_a, **_k: base)
    monkeypatch.setattr(grpc.ssl, "create_default_context", lambda: _Ctx(None, wrap_raises=True))
    with pytest.raises(ssl.SSLError):
        grpc._open_http_socket("h", 443, 2.0, use_tls=True)
    assert base.closed is True


def test_line_output_sink_reuses_one_handle_and_flushes(tmp_path: Path) -> None:
    path = tmp_path / "out.txt"
    sink = LineOutputSink(str(path), print)
    sink.emit_many(["a"])
    handle = sink._handle
    assert handle is not None
    sink.emit_many(["b"])
    assert sink._handle is handle  # reused, not re-opened per record
    assert path.read_text() == "a\nb\n"  # flushed and visible before close
    sink.close()
    assert sink._handle is None
