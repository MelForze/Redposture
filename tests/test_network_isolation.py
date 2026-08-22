from __future__ import annotations

import socket

import pytest
from pytest_socket import SocketBlockedError, SocketConnectBlockedError


def test_external_tcp_connections_are_blocked() -> None:
    with pytest.warns(UserWarning, match="A test tried to use socket.socket.connect"):
        with pytest.raises((SocketBlockedError, SocketConnectBlockedError)):
            socket.create_connection(("192.0.2.1", 443), timeout=0.01)


def test_external_dns_resolution_is_blocked() -> None:
    with pytest.raises(RuntimeError, match="external DNS resolution blocked"):
        socket.getaddrinfo("example.com", 443)


def test_loopback_tcp_and_unix_sockets_remain_available() -> None:
    try:
        socket.create_connection(("127.0.0.1", 9), timeout=0.01)
    except (SocketBlockedError, SocketConnectBlockedError) as exc:  # pragma: no cover - contract failure
        pytest.fail(f"loopback must be allowed by pytest-socket: {exc}")
    except OSError:
        pass

    left, right = socket.socketpair()
    left.sendall(b"ok")
    assert right.recv(2) == b"ok"
    left.close()
    right.close()
