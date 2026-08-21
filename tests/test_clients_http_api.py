from __future__ import annotations

import ssl
import urllib.error
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients.http_api import (
    HttpApiClient,
    HttpClientConfig,
    HttpResponse,
    _decode_chunked_body,
    _flush_tls_outgoing,
    _parse_http_response_bytes,
    _tls_over_tls_exchange,
    build_http_target_url,
    http_target_context,
    normalize_http_error,
)


class _FakeResponse:
    status = 200

    def __init__(
        self,
        body: bytes = b'{"ok":true}',
        headers: dict[str, str] | None = None,
        *,
        final_url: str | None = None,
    ) -> None:
        self._body = body
        self.headers = headers or {"Content-Type": "application/json"}
        self.final_url = final_url

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def close(self) -> None:
        return None

    def read(self, _size: int = -1) -> bytes:
        return self._body

    def getcode(self) -> int:
        return int(self.status)

    def geturl(self) -> str | None:
        return self.final_url


class _FakeOpener:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.requests: list[Any] = []

    def open(self, req: Any, timeout: float) -> Any:
        self.requests.append((req, timeout))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def test_http_api_client_get_success(monkeypatch) -> None:
    opener = _FakeOpener(_FakeResponse(b'{"status":"ok"}', {"X-Test": "1"}))
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    client = HttpApiClient(HttpClientConfig(timeout=2.5))
    response = client.get("http://127.0.0.1:8080/api", headers={"Accept": "application/json"})

    assert response.status == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Test"] == "1"
    assert response.truncated is False
    req, timeout = opener.requests[0]
    assert req.full_url == "http://127.0.0.1:8080/api"
    assert req.get_method() == "GET"
    assert timeout == 2.5
    assert req.get_header("Accept") == "application/json"


def test_http_api_client_records_redirect_and_rejects_cross_origin(monkeypatch) -> None:
    source = "https://service.local/api/health"
    same_origin = "https://service.local/login"
    monkeypatch.setattr(
        "redposture_core.clients.http_api.urllib.request.urlopen",
        _FakeOpener(_FakeResponse(b"login", final_url=same_origin)).open,
    )

    response = HttpApiClient().get(source)

    assert response.error is None
    assert response.request_url == source
    assert response.final_url == same_origin
    assert response.redirect_history == (source,)
    assert response.redirected is True

    cross_origin = "https://login.other.local/sign-in"
    monkeypatch.setattr(
        "redposture_core.clients.http_api.urllib.request.urlopen",
        _FakeOpener(_FakeResponse(b"login", final_url=cross_origin)).open,
    )
    response = HttpApiClient().get(source)

    assert response.status == 200
    assert response.final_url == cross_origin
    assert response.error == f"cross-origin redirect blocked: {source} -> {cross_origin}"


def test_http_target_context_preserves_https_ipv6_and_reverse_proxy_base_path() -> None:
    target = SimpleNamespace(scheme="https", path="/proxy/api/v4/version")

    with http_target_context(target, api_prefixes=("/api/v4",)):
        url = build_http_target_url("2001:db8::10", 8443, "/api/v4/user", default_scheme="http")

    assert url == "https://[2001:db8::10]:8443/proxy/api/v4/user"


def test_http_api_client_post_json_and_response_cap(monkeypatch) -> None:
    opener = _FakeOpener(_FakeResponse(b"abcdef"))
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    client = HttpApiClient(HttpClientConfig(response_size_cap=3))
    response = client.post("http://127.0.0.1:8080/api", json_body={"a": 1})

    assert response.body == b"abc"
    assert response.truncated is True
    req, _timeout = opener.requests[0]
    assert req.data == b'{"a":1}'
    assert req.get_header("Content-type") == "application/json"


def test_http_api_client_http_error_is_response(monkeypatch) -> None:
    error = urllib.error.HTTPError(
        "http://127.0.0.1/api",
        403,
        "Forbidden",
        {"Content-Type": "text/plain"},
        _FakeResponse(b"denied"),
    )
    opener = _FakeOpener(error)
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    response = HttpApiClient().get("http://127.0.0.1/api")

    assert response.status == 403
    assert response.body == b"denied"
    assert response.error is None
    assert response.truncated is False


def test_http_api_client_http_error_reports_response_cap_truncation(monkeypatch) -> None:
    error = urllib.error.HTTPError(
        "http://127.0.0.1/api",
        403,
        "Forbidden",
        {"Content-Type": "text/plain"},
        _FakeResponse(b"denied"),
    )
    opener = _FakeOpener(error)
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    response = HttpApiClient(HttpClientConfig(response_size_cap=3)).get("http://127.0.0.1/api")

    assert response.status == 403
    assert response.body == b"den"
    assert response.truncated is True


def test_http_response_truncated_defaults_false_for_compatible_construction() -> None:
    response = HttpResponse(status=200, body=b"ok", headers={})

    assert response.truncated is False


def test_http_api_client_transport_error_is_normalized(monkeypatch) -> None:
    opener = _FakeOpener(urllib.error.URLError("[Errno 111] Connection refused"))
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    response = HttpApiClient(HttpClientConfig(retries=1, backoff=0)).get("http://127.0.0.1/api")

    assert response.status == 0
    assert "Connection refused" in str(response.error)
    assert normalize_http_error(urllib.error.URLError("timed out"))


def test_http_api_client_https_target_via_https_proxy_uses_manual_tunnel(monkeypatch) -> None:
    class _FakeSocket:
        def __init__(self) -> None:
            self.closed = False
            self.timeout: float | None = None

        def settimeout(self, value: float) -> None:
            self.timeout = value

        def close(self) -> None:
            self.closed = True

    fake_socket = _FakeSocket()
    opened: list[tuple[Any, tuple[str, int], float]] = []
    exchanged: list[bytes] = []

    def _unexpected_urlopen(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("urlopen must not be used for HTTPS target through HTTPS proxy")

    def _fake_open_connection(proxy: Any, address: tuple[str, int], timeout: float) -> _FakeSocket:
        opened.append((proxy, address, timeout))
        return fake_socket

    def _fake_exchange(_sock: Any, _context: Any, **kwargs: Any) -> tuple[bytes, bool]:
        exchanged.append(kwargs["request_payload"])
        return b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}', False

    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", _unexpected_urlopen)
    monkeypatch.setattr("redposture_core.clients.http_api.open_connection_via_proxy", _fake_open_connection)
    monkeypatch.setattr("redposture_core.clients.http_api._tls_over_tls_exchange", _fake_exchange)

    client = HttpApiClient(HttpClientConfig(proxy="https://127.0.0.1:18443", timeout=4.0))
    response = client.get("https://proxmox.internal:8006/api2/json/version", headers={"Accept": "application/json"})

    assert response.status == 200
    assert response.json() == {"ok": True}
    assert response.truncated is False
    assert opened[0][1] == ("proxmox.internal", 8006)
    assert opened[0][2] == 4.0
    assert opened[0][0].scheme == "https"
    assert b"GET /api2/json/version HTTP/1.1" in exchanged[0]
    assert b"Host: proxmox.internal:8006" in exchanged[0]
    assert b"Accept: application/json" in exchanged[0]
    assert fake_socket.closed is True


def test_https_target_via_https_proxy_reports_response_cap_truncation(monkeypatch) -> None:
    class _FakeSocket:
        def settimeout(self, _value: float) -> None:
            return None

        def close(self) -> None:
            return None

    def _fake_open_connection(_proxy: Any, _address: tuple[str, int], timeout: float) -> _FakeSocket:
        _ = timeout
        return _FakeSocket()

    def _fake_exchange(_sock: Any, _context: Any, **_kwargs: Any) -> tuple[bytes, bool]:
        return b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef", False

    monkeypatch.setattr("redposture_core.clients.http_api.open_connection_via_proxy", _fake_open_connection)
    monkeypatch.setattr("redposture_core.clients.http_api._tls_over_tls_exchange", _fake_exchange)

    client = HttpApiClient(HttpClientConfig(proxy="https://127.0.0.1:18443", response_size_cap=3))
    response = client.get("https://proxmox.internal:8006/api2/json/version")

    assert response.status == 200
    assert response.body == b"abc"
    assert response.truncated is True


def test_parse_http_response_bytes_dechunks_lowercase_transfer_encoding() -> None:
    body = b'{"ok":true}'
    chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
    raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" + chunked

    status, headers, decoded = _parse_http_response_bytes(raw, response_cap=1024)

    assert status == 200
    assert headers["transfer-encoding"] == "chunked"
    assert decoded == body


def test_https_target_via_https_proxy_does_not_duplicate_content_length(monkeypatch) -> None:
    class _FakeSocket:
        def settimeout(self, value: float) -> None:
            return None

        def close(self) -> None:
            return None

    exchanged: list[bytes] = []

    def _fake_open_connection(_proxy: Any, _address: tuple[str, int], timeout: float) -> _FakeSocket:
        _ = timeout
        return _FakeSocket()

    def _fake_exchange(_sock: Any, _context: Any, **kwargs: Any) -> tuple[bytes, bool]:
        exchanged.append(kwargs["request_payload"])
        return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", False

    monkeypatch.setattr("redposture_core.clients.http_api.open_connection_via_proxy", _fake_open_connection)
    monkeypatch.setattr("redposture_core.clients.http_api._tls_over_tls_exchange", _fake_exchange)

    client = HttpApiClient(HttpClientConfig(proxy="https://127.0.0.1:18443", timeout=4.0))
    response = client.post(
        "https://proxmox.internal:8006/api2/json/access/ticket",
        headers={"Content-Length": "5"},
        body=b"abc",
    )

    assert response.status == 200
    head = exchanged[0].split(b"\r\n\r\n", 1)[0]
    assert head.lower().count(b"content-length:") == 1


def test_https_target_via_https_proxy_reuses_parsed_proxyconfig_without_reparse(monkeypatch) -> None:
    from redposture_core.network_proxy import ProxyConfig

    class _FakeSocket:
        def settimeout(self, value: float) -> None:
            return None

        def close(self) -> None:
            return None

    def _fake_open_connection(_proxy: Any, _address: tuple[str, int], timeout: float) -> _FakeSocket:
        _ = timeout
        return _FakeSocket()

    def _fake_exchange(_sock: Any, _context: Any, **_kwargs: Any) -> tuple[bytes, bool]:
        return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", False

    def _boom_parse(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("parse_proxy_config must not run when config.proxy is already a ProxyConfig")

    monkeypatch.setattr("redposture_core.clients.http_api.open_connection_via_proxy", _fake_open_connection)
    monkeypatch.setattr("redposture_core.clients.http_api._tls_over_tls_exchange", _fake_exchange)
    monkeypatch.setattr("redposture_core.clients.http_api.parse_proxy_config", _boom_parse)

    proxy = ProxyConfig(
        scheme="https",
        host="127.0.0.1",
        port=18443,
        username=None,
        password=None,
        raw_url="https://127.0.0.1:18443",
    )
    client = HttpApiClient(HttpClientConfig(proxy=proxy, timeout=4.0))
    response = client.get("https://proxmox.internal:8006/api2/json/version")

    assert response.status == 200


def test_decode_chunked_body_valid() -> None:
    body = b"b\r\n" + b'{"ok":true}' + b"\r\n0\r\n\r\n"
    assert _decode_chunked_body(body) == b'{"ok":true}'


@pytest.mark.parametrize(
    "body",
    [
        b"ff\r\nhello",  # declared 255 bytes, only 5 present -> truncated chunk
        b"b\r\n{",  # incomplete chunk header (no CRLF after data)
        b"zz\r\nhello\r\n",  # invalid hex chunk size
        b"5\r\nhello",  # missing terminating 0-chunk
    ],
)
def test_decode_chunked_body_strict_raises_on_malformed(body: bytes) -> None:
    with pytest.raises(ValueError):
        _decode_chunked_body(body, allow_partial=False)


def test_decode_chunked_body_allows_partial_when_truncated() -> None:
    # A body cut short by the response cap is tolerated rather than raising.
    body = b"ff\r\nhello"  # declares 255 bytes, only 5 arrived
    assert _decode_chunked_body(body, allow_partial=True) == b"hello"


def test_parse_http_response_bytes_raises_on_malformed_chunked_when_complete() -> None:
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nhello"
    with pytest.raises(ValueError):
        _parse_http_response_bytes(raw, response_cap=1024, truncated=False)
    # The same bytes are tolerated when the read was cap-truncated.
    _status, _headers, decoded = _parse_http_response_bytes(raw, response_cap=1024, truncated=True)
    assert decoded == b"hello"


def test_https_tunnel_surfaces_malformed_chunked_as_error(monkeypatch) -> None:
    class _FakeSocket:
        def settimeout(self, value: float) -> None:
            return None

        def close(self) -> None:
            return None

    def _fake_open_connection(_proxy: Any, _address: tuple[str, int], timeout: float) -> _FakeSocket:
        _ = timeout
        return _FakeSocket()

    def _fake_exchange(_sock: Any, _context: Any, **_kwargs: Any) -> tuple[bytes, bool]:
        # Complete (not cap-truncated) response with a malformed chunk.
        return b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nhello", False

    monkeypatch.setattr("redposture_core.clients.http_api.open_connection_via_proxy", _fake_open_connection)
    monkeypatch.setattr("redposture_core.clients.http_api._tls_over_tls_exchange", _fake_exchange)

    client = HttpApiClient(HttpClientConfig(proxy="https://127.0.0.1:18443", timeout=4.0))
    response = client.get("https://proxmox.internal:8006/api2/json/version")

    assert response.status == 0
    assert response.body == b""
    assert response.error  # malformed framing surfaced instead of silent partial JSON


def test_http_api_client_download_to_file_success_http_error_and_io_error(monkeypatch, tmp_path) -> None:
    class _ChunkResponse:
        status = 206
        headers = {}

        def __init__(self, chunks: list[bytes]) -> None:
            self.chunks = list(chunks)

        def __enter__(self):
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def read(self, _size: int = -1) -> bytes:
            if not self.chunks:
                return b""
            return self.chunks.pop(0)

        def getcode(self) -> int:
            return self.status

    response = _ChunkResponse([b"abc", b"def"])
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", lambda *_a, **_k: response)

    out_path = tmp_path / "download.bin"
    status, size, error = HttpApiClient(HttpClientConfig(timeout=1.0)).download_to_file(
        "http://127.0.0.1/file",
        str(out_path),
        chunk_size=2,
    )

    assert (status, size, error) == (206, 6, None)
    assert out_path.read_bytes() == b"abcdef"

    http_error = urllib.error.HTTPError("http://127.0.0.1/file", 404, "missing", {}, None)
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", lambda *_a, **_k: http_error)
    assert HttpApiClient().download_to_file("http://127.0.0.1/file", str(out_path)) == (404, 0, None)

    monkeypatch.setattr(
        "redposture_core.clients.http_api.urllib.request.urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("disk/network boom")),
    )
    status, size, error = HttpApiClient().download_to_file("http://127.0.0.1/file", str(out_path))
    assert (status, size) == (0, 0)
    assert "disk/network boom" in str(error)


def test_http_api_client_read_fallback_paths_for_typeerror(monkeypatch) -> None:
    class _NoSizeReadResponse:
        status = 200
        headers = {"X-Test": "fallback"}

        def __enter__(self):
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def read(self, *args: object) -> bytes:
            if args:
                raise TypeError("no size arg")
            return b"fallback-body"

        def getcode(self) -> int:
            return self.status

    monkeypatch.setattr(
        "redposture_core.clients.http_api.urllib.request.urlopen",
        lambda *_a, **_k: _NoSizeReadResponse(),
    )
    response = HttpApiClient().get("http://127.0.0.1/api")
    assert response.body == b"fallback-body"
    assert response.headers == {"X-Test": "fallback"}

    class _NoSizeHTTPError(urllib.error.HTTPError):
        def read(self, *args: object) -> bytes:
            if args:
                raise TypeError("no size arg")
            return b"error-body"

    error = _NoSizeHTTPError("http://127.0.0.1/api", 418, "teapot", {"X-Error": "fallback"}, None)
    monkeypatch.setattr(
        "redposture_core.clients.http_api.urllib.request.urlopen", lambda *_a, **_k: (_ for _ in ()).throw(error)
    )
    response = HttpApiClient().get("http://127.0.0.1/api")
    assert response.status == 418
    assert response.body == b"error-body"


def test_manual_https_proxy_rejects_invalid_target_and_missing_proxy(monkeypatch) -> None:
    client = HttpApiClient(HttpClientConfig(proxy="https://127.0.0.1:18443"))
    response = client._send_https_target_via_https_proxy(  # noqa: SLF001
        urllib.request.Request("https:///missing-host"),
        body=None,
        timeout=1.0,
    )
    assert response.status == 0
    assert "invalid target host" in str(response.error)

    no_proxy = HttpApiClient()
    response = no_proxy._send_https_target_via_https_proxy(  # noqa: SLF001
        urllib.request.Request("https://example.local/"),
        body=None,
        timeout=1.0,
    )
    assert response.status == 0
    assert "missing https proxy config" in str(response.error)


def test_tls_over_tls_exchange_exercises_want_read_write_and_eof_paths() -> None:
    class _FakeSocket:
        def __init__(self) -> None:
            self.sent: list[bytes] = []
            self.recv_chunks = [b"handshake-in", b"read-in", b""]

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

        def recv(self, _size: int) -> bytes:
            return self.recv_chunks.pop(0)

    class _FakeTLS:
        def __init__(self, outgoing: ssl.MemoryBIO) -> None:
            self.outgoing = outgoing
            self.handshake_calls = 0
            self.write_calls = 0
            self.read_calls = 0

        def do_handshake(self) -> None:
            self.handshake_calls += 1
            self.outgoing.write(f"hs{self.handshake_calls}".encode())
            if self.handshake_calls == 1:
                raise ssl.SSLWantReadError()

        def write(self, data: memoryview) -> int:
            self.write_calls += 1
            self.outgoing.write(f"wr{self.write_calls}".encode())
            if self.write_calls == 1:
                raise ssl.SSLWantWriteError()
            return len(data)

        def read(self, _size: int) -> bytes:
            self.read_calls += 1
            if self.read_calls == 1:
                return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
            if self.read_calls == 2:
                raise ssl.SSLWantReadError()
            raise ssl.SSLEOFError()

    class _FakeContext:
        def wrap_bio(self, _incoming: ssl.MemoryBIO, outgoing: ssl.MemoryBIO, **_kwargs: object) -> _FakeTLS:
            return _FakeTLS(outgoing)

    sock = _FakeSocket()
    raw, truncated = _tls_over_tls_exchange(
        sock,
        _FakeContext(),
        server_hostname="example.local",
        request_payload=b"GET / HTTP/1.1\r\n\r\n",
        response_cap=1,
    )

    assert raw.startswith(b"HTTP/1.1 200 OK")
    assert truncated is False
    assert sock.sent == [b"hs1", b"hs2", b"wr1", b"wr2"]


def test_tls_over_tls_exchange_closed_during_handshake_and_write() -> None:
    class _ClosedSocket:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

        def recv(self, _size: int) -> bytes:
            return b""

    class _HandshakeWantReadTLS:
        def __init__(self, outgoing: ssl.MemoryBIO) -> None:
            self.outgoing = outgoing

        def do_handshake(self) -> None:
            self.outgoing.write(b"hs")
            raise ssl.SSLWantReadError()

    class _WriteWantReadTLS:
        def __init__(self, outgoing: ssl.MemoryBIO) -> None:
            self.outgoing = outgoing

        def do_handshake(self) -> None:
            return None

        def write(self, _data: memoryview) -> int:
            self.outgoing.write(b"wr")
            raise ssl.SSLWantReadError()

    class _Context:
        def __init__(self, tls_cls: type) -> None:
            self.tls_cls = tls_cls

        def wrap_bio(self, _incoming: ssl.MemoryBIO, outgoing: ssl.MemoryBIO, **_kwargs: object) -> object:
            return self.tls_cls(outgoing)

    with pytest.raises(OSError, match="handshake closed"):
        _tls_over_tls_exchange(
            _ClosedSocket(),
            _Context(_HandshakeWantReadTLS),
            server_hostname="example.local",
            request_payload=b"x",
            response_cap=10,
        )

    with pytest.raises(OSError, match="write closed"):
        _tls_over_tls_exchange(
            _ClosedSocket(),
            _Context(_WriteWantReadTLS),
            server_hostname="example.local",
            request_payload=b"x",
            response_cap=10,
        )


def test_flush_tls_outgoing_sends_until_empty() -> None:
    class _Sock:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

    outgoing = ssl.MemoryBIO()
    outgoing.write(b"abc")
    outgoing.write(b"def")
    sock = _Sock()
    _flush_tls_outgoing(sock, outgoing)
    assert b"".join(sock.sent) == b"abcdef"
