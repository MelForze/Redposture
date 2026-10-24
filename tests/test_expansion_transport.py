"""Fault and ownership contracts for pooled and manually tunneled HTTP."""

from __future__ import annotations

import http.client
import io
import socket
import ssl
import urllib.request
from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core.clients import http_api as api
from redposture_core.clients import http_session as session
from redposture_core.network_proxy import ProxyConfig


def _proxy(scheme: str = "https") -> ProxyConfig:
    return ProxyConfig(scheme, "proxy", 8443, None, None, f"{scheme}://proxy:8443")


@pytest.mark.parametrize(
    ("raw", "status", "body", "truncated", "method"),
    [
        (
            b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\ndata",
            201,
            b"data",
            False,
            "GET",
        ),
        (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nopaque", 101, b"opaq", True, "GET"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", 200, b"", False, "HEAD"),
        (b"HTTP/1.1 204 No Content\r\nContent-Length: 50\r\n\r\nignored", 204, b"", False, "GET"),
        (b"HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\n\r\nignored", 304, b"", False, "GET"),
        (b"HTTP/1.1 200 OK\r\nIgnored invalid line\r\nContent-Length: 2\r\n\r\nokEXTRA", 200, b"ok", False, "GET"),
    ],
)
def test_manual_http_parser_distinguishes_informational_and_bodyless_responses(
    raw: bytes, status: int, body: bytes, truncated: bool, method: str
) -> None:
    parsed_status, _, parsed_body, parsed_truncated = api._parse_http_response_bytes_detailed(
        raw, response_cap=4, method=method
    )
    assert (parsed_status, parsed_body, parsed_truncated) == (status, body, truncated)


@pytest.mark.parametrize("raw", [b"HTTP/1.1 100 Continue\r\n\r\n", b"HTTP/1.1 200 OK\r\n", b"not-http\r\n\r\n"])
def test_manual_http_parser_rejects_missing_final_response(raw: bytes) -> None:
    with pytest.raises(OSError, match="HTTP"):
        api._parse_http_response_bytes_detailed(raw, response_cap=100)


@pytest.mark.parametrize("value", ["-1", "not-a-number"])
def test_manual_http_parser_rejects_invalid_content_length(value: str) -> None:
    with pytest.raises(ValueError):
        api._parse_http_response_bytes_detailed(
            f"HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\nx".encode(), response_cap=100
        )


def test_manual_http_parser_retains_cap_limited_body_and_marks_truncated() -> None:
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\npartial"
    assert api._parse_http_response_bytes_detailed(raw, response_cap=4, truncated=True)[2:] == (b"part", True)
    with pytest.raises(ConnectionError, match="incomplete HTTP response body"):
        api._parse_http_response_bytes_detailed(raw, response_cap=100)


@pytest.mark.parametrize("body", [b"garbage", b"z\r\ninvalid", b"2\r\nok\r\nz\r\ninvalid"])
def test_partial_chunk_decoder_keeps_only_complete_preceding_chunks(body: bytes) -> None:
    assert api._decode_chunked_body(body, allow_partial=True) == (b"ok" if body.startswith(b"2") else b"")


@pytest.mark.parametrize("body", [b"1\r\na0\r\n\r\n", b"1\r\na\r\n0\r\n", b"1\r\na\r\n0\r\nX-Trailer: value"])
def test_complete_chunk_decoder_rejects_missing_crlf_or_trailer_terminator(body: bytes) -> None:
    with pytest.raises(ValueError, match="malformed chunked body"):
        api._decode_chunked_body(body)


class _Response:
    def __init__(self, body: bytes, *, length: int | None = 0, close_error: bool = False, will_close: bool = False):
        self.body, self.length = body, length
        self.status, self.will_close = 200, will_close
        self.close = Mock(side_effect=OSError("close failed") if close_error else None)

    def read(self, size: int) -> bytes:
        return self.body[:size]

    def getheaders(self) -> list[tuple[str, str]]:
        return [("X-Test", "present")]


def _connection(response: _Response) -> Mock:
    connection = Mock(spec=["sock", "timeout", "request", "getresponse", "close"])
    connection.sock = Mock(spec=["settimeout", "shutdown"])
    connection.getresponse.return_value = response
    return connection


@pytest.mark.parametrize(
    ("body", "remaining", "cap", "close_error", "will_close", "ok", "idle"),
    [
        (b"ok", 0, 2, False, False, True, True),
        (b"partial", 40, 100, False, False, False, False),
        (b"too long", 0, 2, False, False, True, False),
        (b"ok", 0, 2, True, False, True, False),
        (b"ok", 0, 2, False, True, True, False),
    ],
)
def test_pool_reuses_only_complete_cleanly_closed_responses(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    remaining: int,
    cap: int,
    close_error: bool,
    will_close: bool,
    ok: bool,
    idle: bool,
) -> None:
    response = _Response(body, length=remaining, close_error=close_error, will_close=will_close)
    connection = _connection(response)
    monkeypatch.setattr(session.http.client, "HTTPConnection", Mock(return_value=connection))
    pool = session.HttpSessionPool(timeout=1)
    result = pool.request_once("GET", "http://target/a?b=1", response_size_cap=cap)
    assert (result.error is None) is ok
    assert result.status == (200 if ok else 0)
    assert result.body == (body[:cap] if ok else b"")
    assert result.truncated is (len(body) > cap)
    assert bool(pool._idle.get(("http", "target", 80))) is idle
    assert pool._active_sockets == set()
    response.close.assert_called_once()
    connection.request.assert_called_once_with("GET", "/a?b=1", body=None, headers={"Connection": "keep-alive"})
    if not idle:
        connection.close.assert_called_once()
    pool.close()


def test_pool_idle_capacity_closes_overflow_and_snapshots_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    one, two = _connection(_Response(b"a")), _connection(_Response(b"b"))
    factory = Mock(side_effect=[one, two])
    monkeypatch.setattr(session.http.client, "HTTPConnection", factory)
    pool = session.HttpSessionPool(timeout=1, max_idle_per_origin=1)
    origin = ("http", "target", 80)
    first, _ = pool._acquire(origin, 1)
    second, _ = pool._acquire(origin, 1)
    pool._release(origin, first, True)
    two.close.side_effect = OSError("close failed")
    pool._release(origin, second, True)
    assert pool._idle[origin] == [one]
    two.close.assert_called_once()
    stats = pool.stats()
    stats["connections"] = 99
    assert pool.stats()["connections"] == 2
    acquired, reused = pool._acquire(origin, 3)
    assert acquired is one and reused is True
    one.sock.settimeout.assert_called_once_with(3)
    assert one.timeout == 3
    pool.close()
    pool._release(origin, first, True)


@pytest.mark.parametrize("kind", ["stale", "timeout", "invalid", "cancelled"])
def test_pool_retry_policy_distinguishes_transient_failures_and_cancellation(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    pool = session.HttpSessionPool(timeout=1, retries=1)
    error: Exception = (
        http.client.ResponseNotReady("stale")
        if kind == "stale"
        else TimeoutError("timed out")
        if kind == "timeout"
        else ValueError("bad header")
    )
    calls = []

    def request(*args: Any, **kwargs: Any):
        calls.append(kwargs)
        if len(calls) > 1:
            return api.HttpResponse(200, b"ok", {}), None, False
        if kind == "cancelled":
            pool.close()
        return api.HttpResponse(0, b"", {}, error=str(error)), error, True

    monkeypatch.setattr(pool, "_request_once", request)
    monkeypatch.setattr(session.time, "sleep", Mock())
    result = pool.request("GET", "http://target/")
    should_retry = kind in {"stale", "timeout"}
    assert len(calls) == (2 if should_retry else 1)
    assert pool.stats()["retries"] == int(should_retry)
    assert result.status == (200 if should_retry else 0)


@pytest.mark.parametrize("proxy_scheme", ["http", "https"])
def test_pool_builds_target_tls_over_selected_proxy_transport(
    monkeypatch: pytest.MonkeyPatch, proxy_scheme: str
) -> None:
    outer, wrapped = Mock(), Mock()
    context = Mock()
    context.wrap_socket.return_value = wrapped
    opener = Mock(return_value=outer)
    monkeypatch.setattr(session, "open_connection_via_proxy", opener)
    layer = Mock(return_value=wrapped)
    monkeypatch.setattr(session, "_LayeredTlsSocket", layer)
    connection = Mock()
    monkeypatch.setattr(session.http.client, "HTTPConnection", Mock(return_value=connection))
    pool = session.HttpSessionPool(timeout=1, proxy=_proxy(proxy_scheme))
    monkeypatch.setattr(pool, "_target_context", Mock(return_value=context))
    assert pool._new_connection(("https", "target", 443), 2) is connection
    assert connection.sock is wrapped
    opener.assert_called_once_with(pool.proxy, ("target", 443), timeout=2)
    if proxy_scheme == "https":
        layer.assert_called_once_with(outer, context, "target")
        context.wrap_socket.assert_not_called()
    else:
        context.wrap_socket.assert_called_once_with(outer, server_hostname="target")
    pool.close()


@pytest.mark.parametrize("error", [TimeoutError("proxy timed out"), ConnectionRefusedError("proxy connection refused")])
def test_pool_normalizes_connection_acquisition_errors_like_request_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr(session, "open_connection_via_proxy", Mock(side_effect=error))
    pool = session.HttpSessionPool(timeout=1, proxy=_proxy())
    result = pool.request("GET", "https://target/", retries=0)
    assert result.status == 0 and result.error and "proxy" in result.error
    assert pool._connections == set()


@pytest.mark.parametrize("error", [TimeoutError("proxy timed out"), ConnectionRefusedError("proxy connection refused")])
def test_pool_single_hop_normalizes_proxy_connection_acquisition_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr(session, "open_connection_via_proxy", Mock(side_effect=error))
    pool = session.HttpSessionPool(timeout=1, proxy=_proxy())
    result = pool.request_once("GET", "https://target/")
    assert result.status == 0 and result.error and "proxy" in result.error
    assert pool._connections == set()


class _TlsContext:
    def __init__(self, tls: Mock):
        self.tls = tls
        self.incoming: ssl.MemoryBIO | None = None
        self.outgoing: ssl.MemoryBIO | None = None

    def wrap_bio(self, incoming: ssl.MemoryBIO, outgoing: ssl.MemoryBIO, **_kwargs: Any):
        self.incoming, self.outgoing = incoming, outgoing
        outgoing.write(b"TLS hello")
        return self.tls


def test_layered_tls_makes_progress_across_read_write_demands_and_partial_writes() -> None:
    tls = Mock()
    tls.do_handshake.side_effect = [ssl.SSLWantWriteError(), ssl.SSLWantReadError(), None]
    tls.write.side_effect = [ssl.SSLWantReadError(), ssl.SSLWantWriteError(), 2, 2]
    tls.read.side_effect = [ssl.SSLWantWriteError(), ssl.SSLWantReadError(), b"ok", ssl.SSLZeroReturnError()]
    context = _TlsContext(tls)
    outer = Mock()
    outer.recv.side_effect = [b"handshake", b"write", b"read"]
    layered = session._LayeredTlsSocket(outer, context, "target")
    layered.sendall(b"abcd")
    assert [bytes(call.args[0]) for call in tls.write.call_args_list][-2:] == [b"abcd", b"cd"]
    assert layered.recv(2) == b"ok" and layered.recv(2) == b""
    outer.sendall.assert_called_once_with(b"TLS hello")
    layered.settimeout(2)
    layered.shutdown(socket.SHUT_RDWR)
    outer.settimeout.assert_called_once_with(2)
    outer.shutdown.assert_called_once_with(socket.SHUT_RDWR)
    outer.close.side_effect = OSError("closed")
    layered.close()
    layered.close()
    outer.close.assert_called_once()
    with pytest.raises(ValueError, match="read makefiles only"):
        layered.makefile("w")


def test_layered_tls_eof_is_fed_to_ssl_and_readinto_limits_bytes() -> None:
    tls = Mock()
    tls.do_handshake.side_effect = [ssl.SSLWantReadError(), None]
    tls.read.side_effect = [b"ab", b""]
    context = _TlsContext(tls)
    outer = Mock()
    outer.recv.return_value = b""
    layered = session._LayeredTlsSocket(outer, context, "target")
    assert context.incoming and context.incoming.eof
    with layered.makefile("rb", buffering=1) as reader:
        assert reader.read() == b"ab"


@pytest.mark.parametrize("phase", ["handshake", "write", "read_eof", "cap"])
def test_manual_nested_tls_exchange_handles_bidirectional_progress_and_bounds(phase: str) -> None:
    tls = Mock()
    tls.do_handshake.side_effect = [ssl.SSLWantWriteError(), None] if phase == "handshake" else [None]
    tls.write.side_effect = [ssl.SSLWantReadError(), 4] if phase == "write" else [4]
    tls.read.side_effect = (
        [ssl.SSLEOFError()] if phase == "read_eof" else [b"x" * 65537] if phase == "cap" else [b"ok", b""]
    )
    context = _TlsContext(tls)
    outer = Mock()
    outer.recv.return_value = b"peer response"
    result, truncated = api._tls_over_tls_exchange(
        outer, context, server_hostname="target", request_payload=b"data", response_cap=0
    )
    assert result == (b"" if phase == "read_eof" else b"x" * 65537 if phase == "cap" else b"ok")
    assert truncated is (phase == "cap")
    if phase == "write":
        outer.recv.assert_called_once()


def test_manual_https_proxy_always_closes_tunnel_after_parse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    outer = Mock()
    outer.close.side_effect = OSError("already closed")
    monkeypatch.setattr(api, "open_connection_via_proxy", Mock(return_value=outer))
    monkeypatch.setattr(api, "_tls_over_tls_exchange", Mock(return_value=(b"invalid", False)))
    client = api.HttpApiClient(api.HttpClientConfig(proxy=_proxy(), ssl_context=Mock()))
    response = client._send_https_target_via_https_proxy(
        urllib.request.Request("https://target/"), body=None, timeout=1
    )
    assert response.status == 0 and response.error and "incomplete HTTP response" in response.error
    outer.close.assert_called_once()


def test_http_error_body_read_failure_is_normalized_and_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    error = urllib.error.HTTPError("https://target/", 403, "Forbidden", {}, io.BytesIO(b"x"))
    monkeypatch.setattr(error, "read", Mock(side_effect=ConnectionResetError("body reset")))
    close = Mock()
    monkeypatch.setattr(error, "close", close)
    monkeypatch.setattr(api, "_open_http_request", Mock(side_effect=error))
    response = api.HttpApiClient().get("https://target/")
    assert response.status == 0 and response.error == "body reset"
    close.assert_called_once()
