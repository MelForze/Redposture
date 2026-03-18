from __future__ import annotations

import socket

import pytest

from redposture_core import network_proxy as np


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


def test_proxy_socket_patch_with_none_proxy_keeps_original() -> None:
    original = socket.create_connection
    with np.ProxySocketPatch(None):
        assert socket.create_connection is original
    assert socket.create_connection is original


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

    monkeypatch.setattr(np.socket, "create_connection", fake_create_connection)

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
