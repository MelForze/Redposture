from __future__ import annotations

import urllib.error
from typing import Any

import pytest

from redposture_core.clients.http_api import (
    HttpApiClient,
    HttpClientConfig,
    _decode_chunked_body,
    _parse_http_response_bytes,
    normalize_http_error,
)


class _FakeResponse:
    status = 200

    def __init__(self, body: bytes = b'{"ok":true}', headers: dict[str, str] | None = None) -> None:
        self._body = body
        self.headers = headers or {"Content-Type": "application/json"}

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


class _FakeOpener:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.requests: list[Any] = []

    def open(self, req: Any, timeout: float) -> Any:
        self.requests.append((req, timeout))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def test_http_api_client_get_success(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    opener = _FakeOpener(_FakeResponse(b'{"status":"ok"}', {"X-Test": "1"}))
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    client = HttpApiClient(HttpClientConfig(timeout=2.5))
    response = client.get("http://127.0.0.1:8080/api", headers={"Accept": "application/json"})

    assert response.status == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Test"] == "1"
    req, timeout = opener.requests[0]
    assert req.full_url == "http://127.0.0.1:8080/api"
    assert req.get_method() == "GET"
    assert timeout == 2.5
    assert req.get_header("Accept") == "application/json"


def test_http_api_client_post_json_and_response_cap(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    opener = _FakeOpener(_FakeResponse(b"abcdef"))
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    client = HttpApiClient(HttpClientConfig(response_size_cap=3))
    response = client.post("http://127.0.0.1:8080/api", json_body={"a": 1})

    assert response.body == b"abc"
    req, _timeout = opener.requests[0]
    assert req.data == b'{"a":1}'
    assert req.get_header("Content-type") == "application/json"


def test_http_api_client_http_error_is_response(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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


def test_http_api_client_transport_error_is_normalized(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    opener = _FakeOpener(urllib.error.URLError("[Errno 111] Connection refused"))
    monkeypatch.setattr("redposture_core.clients.http_api.urllib.request.urlopen", opener.open)

    response = HttpApiClient(HttpClientConfig(retries=1, backoff=0)).get("http://127.0.0.1/api")

    assert response.status == 0
    assert "Connection refused" in str(response.error)
    assert normalize_http_error(urllib.error.URLError("timed out"))


def test_http_api_client_https_target_via_https_proxy_uses_manual_tunnel(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
    assert opened[0][1] == ("proxmox.internal", 8006)
    assert opened[0][2] == 4.0
    assert opened[0][0].scheme == "https"
    assert b"GET /api2/json/version HTTP/1.1" in exchanged[0]
    assert b"Host: proxmox.internal:8006" in exchanged[0]
    assert b"Accept: application/json" in exchanged[0]
    assert fake_socket.closed is True


def test_parse_http_response_bytes_dechunks_lowercase_transfer_encoding() -> None:
    body = b'{"ok":true}'
    chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
    raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" + chunked

    status, headers, decoded = _parse_http_response_bytes(raw, response_cap=1024)

    assert status == 200
    assert headers["transfer-encoding"] == "chunked"
    assert decoded == body


def test_https_target_via_https_proxy_does_not_duplicate_content_length(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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


def test_https_target_via_https_proxy_reuses_parsed_proxyconfig_without_reparse(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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


def test_https_tunnel_surfaces_malformed_chunked_as_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
