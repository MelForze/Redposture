from __future__ import annotations

import socket

import pytest

from redposture_core import network_proxy as np
from redposture_core.exporters.http_pool import HTTPConnectionPool


@pytest.mark.parametrize(
    ("raw", "expected_error"),
    [
        ("", None),
        ("ftp://proxy.local:21", "unsupported proxy scheme"),
        ("proxy.local:8080", "unsupported proxy scheme"),
        ("http://:8080", "proxy URL must include host"),
        ("http://proxy.local:99999", "proxy URL has invalid port"),
        ("http://proxy.local:abc", "proxy URL has invalid port"),
    ],
)
def test_parse_proxy_config_validation(raw: str, expected_error: str | None) -> None:
    cfg, err = np.parse_proxy_config(raw)
    if expected_error is None:
        assert cfg is None
        assert err is None
        return
    assert cfg is None
    assert expected_error in str(err)


def test_parse_proxy_config_decodes_credentials() -> None:
    cfg, err = np.parse_proxy_config("http://user%20name:pa%40ss@proxy.local:8080")
    assert err is None
    assert cfg is not None
    assert cfg.scheme == "http"
    assert cfg.host == "proxy.local"
    assert cfg.port == 8080
    assert cfg.username == "user name"
    assert cfg.password == "pa@ss"


def test_parse_proxy_config_supports_socks5h() -> None:
    cfg, err = np.parse_proxy_config("socks5h://127.0.0.1:1080")
    assert err is None
    assert cfg is not None
    assert cfg.scheme == "socks5h"
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 1080


@pytest.mark.parametrize("scheme", ["socks4", "socks4a"])
def test_parse_proxy_config_supports_socks4_variants(scheme: str) -> None:
    cfg, err = np.parse_proxy_config(f"{scheme}://audit@127.0.0.1:1080")
    assert err is None
    assert cfg is not None
    assert cfg.scheme == scheme
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 1080
    assert cfg.username == "audit"
    assert cfg.password is None


@pytest.mark.parametrize(
    ("address", "error_substr"),
    [
        (("only_host",), "invalid address tuple"),
        ((("", 80)), "invalid target host"),
        ((("host", "abc")), "invalid target port"),
        ((("host", 70000)), "target port must be in range"),
    ],
)
def test_open_connection_via_proxy_validates_target(address: tuple[object, ...], error_substr: str) -> None:
    proxy = np.ProxyConfig(
        scheme="http",
        host="127.0.0.1",
        port=8080,
        username=None,
        password=None,
        raw_url="http://127.0.0.1:8080",
    )
    with pytest.raises(OSError, match=error_substr):
        np.open_connection_via_proxy(proxy, address)


def test_proxy_socket_patch_routes_socket_create_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[object, ...], object, object]] = []

    class DummySock:
        def setsockopt(self, *_args: object) -> None:
            return

        def close(self) -> None:
            return

    def fake_open_connection_via_proxy(
        proxy: np.ProxyConfig,
        address: tuple[object, ...],
        timeout: object = np._SOCKET_DEFAULT_TIMEOUT,
        source_address: tuple[str, int] | None = None,
    ) -> DummySock:
        _ = proxy
        calls.append((address, timeout, source_address))
        return DummySock()

    monkeypatch.setattr(np, "open_connection_via_proxy", fake_open_connection_via_proxy)

    proxy = np.ProxyConfig(
        scheme="http",
        host="127.0.0.1",
        port=8080,
        username=None,
        password=None,
        raw_url="http://127.0.0.1:8080",
    )
    original = socket.create_connection

    with np.ProxySocketPatch(proxy):
        sock_obj = socket.create_connection(("example.com", 443), timeout=1.5)
        assert isinstance(sock_obj, DummySock)
        assert calls == [(("example.com", 443), 1.5, None)]

    assert socket.create_connection is original


@pytest.mark.parametrize(
    ("client_name", "address"),
    [
        ("redis", ("redis.internal", 6379)),
        ("kafka", ("kafka.internal", 9092)),
        ("zookeeper", ("zookeeper.internal", 2181)),
        ("grpc", ("grpc.internal", 50051)),
        ("postgres", ("postgres.internal", 5432)),
        ("oracle", ("oracle.internal", 1521)),
        ("clickhouse_native", ("clickhouse.internal", 9000)),
        ("kubeapi_websocket", ("kubeapi.internal", 6443)),
    ],
)
def test_proxy_socket_patch_routes_representative_raw_tcp_clients(
    monkeypatch: pytest.MonkeyPatch,
    client_name: str,
    address: tuple[str, int],
) -> None:
    calls: list[tuple[str, tuple[object, ...], object, object]] = []

    class DummySock:
        def setsockopt(self, *_args: object) -> None:
            return

        def close(self) -> None:
            return

    def fake_open_connection_via_proxy(
        proxy: np.ProxyConfig,
        proxied_address: tuple[object, ...],
        timeout: object = np._SOCKET_DEFAULT_TIMEOUT,
        source_address: tuple[str, int] | None = None,
    ) -> DummySock:
        calls.append((proxy.raw_url, proxied_address, timeout, source_address))
        return DummySock()

    monkeypatch.setattr(np, "open_connection_via_proxy", fake_open_connection_via_proxy)

    proxy = np.ProxyConfig(
        scheme="socks5h",
        host="127.0.0.1",
        port=1080,
        username=None,
        password=None,
        raw_url="socks5h://127.0.0.1:1080",
    )
    with np.ProxySocketPatch(proxy):
        socket.create_connection(address, timeout=2.0)

    assert calls == [("socks5h://127.0.0.1:1080", address, 2.0, None)], client_name


def test_proxy_socket_patch_with_none_proxy_keeps_original() -> None:
    original = socket.create_connection
    with np.ProxySocketPatch(None):
        assert socket.create_connection is original
    assert socket.create_connection is original


def test_runtime_network_config_from_args_carries_proxy_and_retries() -> None:
    class _Args:
        timeout = "2.5"
        retries = "3"
        insecure = True
        tls = None

    proxy = np.ProxyConfig(
        scheme="socks5",
        host="127.0.0.1",
        port=9050,
        username=None,
        password=None,
        raw_url="socks5://127.0.0.1:9050",
    )

    config = np.RuntimeNetworkConfig.from_args(_Args(), proxy=proxy)

    assert config.proxy is proxy
    assert config.proxy_enabled is True
    assert config.timeout == 2.5
    assert config.retries == 3
    assert config.insecure is True


@pytest.mark.parametrize(
    ("host", "port", "expected"),
    [
        ("127.0.0.1", 80, "127.0.0.1:80"),
        ("::1", 443, "[::1]:443"),
        ("[::1]", 443, "[::1]:443"),
    ],
)
def test_host_port_for_connect_formats_ipv4_and_ipv6(host: str, port: int, expected: str) -> None:
    assert np._host_port_for_connect(host, port) == expected


def test_open_proxy_connection_uses_socket_create_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[str, int], float | None, tuple[str, int] | None]] = []

    class _DummySocket:
        def close(self) -> None:
            return

    def fake_create_connection(
        address: tuple[str, int],
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
    ) -> _DummySocket:
        calls.append((address, timeout, source_address))
        return _DummySocket()

    monkeypatch.setattr(np, "_RAW_SOCKET_CREATE_CONNECTION", fake_create_connection)

    proxy = np.ProxyConfig(
        scheme="socks5",
        host="::1",
        port=1080,
        username=None,
        password=None,
        raw_url="socks5://[::1]:1080",
    )
    sock = np._open_proxy_connection(proxy, timeout=2.5, source_address=("0.0.0.0", 0))

    assert isinstance(sock, _DummySocket)
    assert calls == [(("::1", 1080), 2.5, ("0.0.0.0", 0))]


def test_proxy_socket_patch_nested_contexts_restore_original(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple[object, ...], object, object]] = []

    class DummySock:
        def setsockopt(self, *_args: object) -> None:
            return

        def close(self) -> None:
            return

    def fake_open_connection_via_proxy(
        proxy: np.ProxyConfig,
        address: tuple[object, ...],
        timeout: object = np._SOCKET_DEFAULT_TIMEOUT,
        source_address: tuple[str, int] | None = None,
    ) -> DummySock:
        calls.append((proxy.raw_url, address, timeout, source_address))
        return DummySock()

    monkeypatch.setattr(np, "open_connection_via_proxy", fake_open_connection_via_proxy)

    original = socket.create_connection
    proxy_a = np.ProxyConfig(
        scheme="http",
        host="127.0.0.1",
        port=8080,
        username=None,
        password=None,
        raw_url="http://127.0.0.1:8080",
    )
    proxy_b = np.ProxyConfig(
        scheme="http",
        host="127.0.0.1",
        port=8081,
        username=None,
        password=None,
        raw_url="http://127.0.0.1:8081",
    )

    with np.ProxySocketPatch(proxy_a):
        assert socket.create_connection is not original
        socket.create_connection(("a.example", 443), timeout=1.0)
        with np.ProxySocketPatch(proxy_b):
            socket.create_connection(("b.example", 443), timeout=2.0)
        socket.create_connection(("c.example", 443), timeout=3.0)

    assert socket.create_connection is original
    assert [item[0] for item in calls] == [
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8081",
        "http://127.0.0.1:8080",
    ]


def test_resolve_timeout_handles_default_invalid_and_negative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(np.socket, "getdefaulttimeout", lambda: 9.5)
    assert np._resolve_timeout(np._SOCKET_DEFAULT_TIMEOUT) == 9.5
    assert np._resolve_timeout("bad") == 9.5
    assert np._resolve_timeout(-1) == 0.0
    assert np._resolve_timeout(1.25) == 1.25


class _FakeSocket:
    def __init__(self, replies: list[bytes]) -> None:
        self._replies = list(replies)
        self.sent: list[bytes] = []
        self.closed = False

    def recv(self, _size: int) -> bytes:
        if not self._replies:
            return b""
        return self._replies.pop(0)

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)

    def close(self) -> None:
        self.closed = True

    def settimeout(self, _timeout: float | None) -> None:
        return


def test_recv_exact_reads_all_requested_bytes() -> None:
    sock = _FakeSocket([b"ab", b"cd"])
    assert np._recv_exact(sock, 4) == b"abcd"

    with pytest.raises(OSError, match="closed unexpectedly"):
        np._recv_exact(_FakeSocket([b"ab"]), 4)


def test_socks5_open_tunnel_with_auth_and_remote_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = _FakeSocket(
        [
            b"\x05\x02",  # choose username/password auth
            b"\x01\x00",  # auth success
            b"\x05\x00\x00\x03",  # connect success, domain bind address
            b"\x01",
            b"a",
            b"\x1f\x90",
        ]
    )
    monkeypatch.setattr(np, "_open_proxy_connection", lambda *_args, **_kwargs: sock)

    proxy = np.ProxyConfig(
        scheme="socks5h",
        host="127.0.0.1",
        port=1080,
        username="user",
        password="pass",
        raw_url="socks5h://user:pass@127.0.0.1:1080",
    )
    returned = np._socks5_open_tunnel(proxy, "example.com", 443, timeout=1.0, source_address=None)

    assert returned is sock
    assert sock.sent[0] == b"\x05\x02\x00\x02"
    assert sock.sent[1] == b"\x01\x04user\x04pass"
    assert sock.sent[2].startswith(b"\x05\x01\x00\x03")
    assert sock.closed is False


def test_socks5_open_tunnel_closes_socket_on_negotiation_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = _FakeSocket([b"\x05\xff"])
    monkeypatch.setattr(np, "_open_proxy_connection", lambda *_args, **_kwargs: sock)

    proxy = np.ProxyConfig(
        scheme="socks5",
        host="127.0.0.1",
        port=1080,
        username=None,
        password=None,
        raw_url="socks5://127.0.0.1:1080",
    )
    with pytest.raises(OSError, match="authentication method negotiation failed"):
        np._socks5_open_tunnel(proxy, "127.0.0.1", 80, timeout=1.0, source_address=None)

    assert sock.closed is True


def test_socks4_open_tunnel_ipv4_request_with_userid(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = _FakeSocket([b"\x00\x5a\x00\x00\x00\x00\x00\x00"])
    monkeypatch.setattr(np, "_open_proxy_connection", lambda *_args, **_kwargs: sock)

    proxy = np.ProxyConfig(
        scheme="socks4",
        host="127.0.0.1",
        port=1080,
        username="audit",
        password=None,
        raw_url="socks4://audit@127.0.0.1:1080",
    )
    returned = np._socks4_open_tunnel(proxy, "192.0.2.10", 9100, timeout=1.0, source_address=None)

    assert returned is sock
    assert sock.sent == [b"\x04\x01\x23\x8c\xc0\x00\x02\x0aaudit\x00"]
    assert sock.closed is False


def test_socks4_open_tunnel_domain_uses_socks4a(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = _FakeSocket([b"\x00\x5a\x00\x00\x00\x00\x00\x00"])
    monkeypatch.setattr(np, "_open_proxy_connection", lambda *_args, **_kwargs: sock)

    proxy = np.ProxyConfig(
        scheme="socks4",
        host="127.0.0.1",
        port=1080,
        username=None,
        password=None,
        raw_url="socks4://127.0.0.1:1080",
    )
    returned = np._socks4_open_tunnel(proxy, "proxy-node-exporter", 9100, timeout=1.0, source_address=None)

    assert returned is sock
    assert sock.sent == [b"\x04\x01\x23\x8c\x00\x00\x00\x01\x00proxy-node-exporter\x00"]
    assert sock.closed is False


def test_socks4a_open_tunnel_forces_remote_dns_even_for_ipv4(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = _FakeSocket([b"\x00\x5a\x00\x00\x00\x00\x00\x00"])
    monkeypatch.setattr(np, "_open_proxy_connection", lambda *_args, **_kwargs: sock)

    proxy = np.ProxyConfig(
        scheme="socks4a",
        host="127.0.0.1",
        port=1080,
        username=None,
        password=None,
        raw_url="socks4a://127.0.0.1:1080",
    )
    returned = np._socks4_open_tunnel(proxy, "192.0.2.10", 9100, timeout=1.0, source_address=None)

    assert returned is sock
    assert sock.sent == [b"\x04\x01\x23\x8c\x00\x00\x00\x01\x00192.0.2.10\x00"]
    assert sock.closed is False


def test_socks4_open_tunnel_closes_socket_on_reject(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = _FakeSocket([b"\x00\x5b\x00\x00\x00\x00\x00\x00"])
    monkeypatch.setattr(np, "_open_proxy_connection", lambda *_args, **_kwargs: sock)

    proxy = np.ProxyConfig(
        scheme="socks4",
        host="127.0.0.1",
        port=1080,
        username=None,
        password=None,
        raw_url="socks4://127.0.0.1:1080",
    )
    with pytest.raises(OSError, match="code=91"):
        np._socks4_open_tunnel(proxy, "192.0.2.10", 9100, timeout=1.0, source_address=None)

    assert sock.closed is True


def test_http_open_tunnel_sends_connect_and_proxy_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = _FakeSocket([])
    monkeypatch.setattr(np, "_open_proxy_connection", lambda *_args, **_kwargs: sock)

    class _FakeHTTPResponse:
        def __init__(self, transport: _FakeSocket) -> None:
            self.transport = transport
            self.status = 200

        def begin(self) -> None:
            return

    monkeypatch.setattr(np.http.client, "HTTPResponse", _FakeHTTPResponse)

    proxy = np.ProxyConfig(
        scheme="http",
        host="proxy.local",
        port=8080,
        username="alice",
        password="secret",
        raw_url="http://alice:secret@proxy.local:8080",
    )
    returned = np._http_open_tunnel(proxy, "example.com", 443, timeout=2.0, source_address=None)

    assert returned is sock
    request = sock.sent[0].decode("utf-8")
    assert "CONNECT example.com:443 HTTP/1.1" in request
    assert "Host: example.com:443" in request
    assert "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0" in request


def test_http_open_tunnel_closes_socket_on_non_200(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = _FakeSocket([])
    monkeypatch.setattr(np, "_open_proxy_connection", lambda *_args, **_kwargs: sock)

    class _FakeHTTPResponse:
        def __init__(self, transport: _FakeSocket) -> None:
            self.transport = transport
            self.status = 407

        def begin(self) -> None:
            return

    monkeypatch.setattr(np.http.client, "HTTPResponse", _FakeHTTPResponse)

    proxy = np.ProxyConfig(
        scheme="http",
        host="proxy.local",
        port=8080,
        username=None,
        password=None,
        raw_url="http://proxy.local:8080",
    )
    with pytest.raises(OSError, match="status=407"):
        np._http_open_tunnel(proxy, "example.com", 443, timeout=2.0, source_address=None)

    assert sock.closed is True


def test_http_connection_pool_uses_proxy_socket_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple[object, ...], object, object]] = []

    class DummySock:
        def setsockopt(self, *_args: object) -> None:
            return

        def close(self) -> None:
            return

    def fake_open_connection_via_proxy(
        proxy: np.ProxyConfig,
        address: tuple[object, ...],
        timeout: object = np._SOCKET_DEFAULT_TIMEOUT,
        source_address: tuple[str, int] | None = None,
    ) -> DummySock:
        calls.append((proxy.raw_url, address, timeout, source_address))
        return DummySock()

    monkeypatch.setattr(np, "open_connection_via_proxy", fake_open_connection_via_proxy)

    proxy = np.ProxyConfig(
        scheme="socks4a",
        host="127.0.0.1",
        port=1080,
        username=None,
        password=None,
        raw_url="socks4a://127.0.0.1:1080",
    )
    pool = HTTPConnectionPool()
    with np.ProxySocketPatch(proxy):
        conn = pool._acquire("proxy-node-exporter", 9100, 1.25)
        conn.connect()

    assert calls == [("socks4a://127.0.0.1:1080", ("proxy-node-exporter", 9100), 1.25, None)]
