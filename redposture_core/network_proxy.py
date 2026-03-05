"""Shared outbound proxy support for module network requests."""

from __future__ import annotations

import base64
import http.client
import ipaddress
import socket
import ssl
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from types import TracebackType
from typing import Any

_SOCKET_DEFAULT_TIMEOUT: Any = getattr(socket, "_GLOBAL_DEFAULT_TIMEOUT", object())


@dataclass(frozen=True)
class ProxyConfig:
    scheme: str
    host: str
    port: int
    username: str | None
    password: str | None
    raw_url: str


def parse_proxy_config(raw_proxy: str | None) -> tuple[ProxyConfig | None, str | None]:
    value = str(raw_proxy or "").strip()
    if not value:
        return None, None

    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return None, "invalid --proxy URL"

    scheme = str(parsed.scheme or "").lower().strip()
    if not scheme:
        return None, "proxy URL must include scheme (http:// or socks5://)"
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        return None, "unsupported proxy scheme (supported: http, https, socks5, socks5h)"

    host = str(parsed.hostname or "").strip()
    if not host:
        return None, "proxy URL must include host"

    try:
        port = int(parsed.port or 0)
    except ValueError:
        return None, "proxy URL has invalid port"
    if port < 1 or port > 65535:
        return None, "proxy URL port must be in range 1..65535"

    username = urllib.parse.unquote(parsed.username) if parsed.username is not None else None
    password = urllib.parse.unquote(parsed.password) if parsed.password is not None else None
    return (
        ProxyConfig(
            scheme=scheme,
            host=host,
            port=port,
            username=username,
            password=password,
            raw_url=value,
        ),
        None,
    )


def _resolve_timeout(timeout: object) -> float | None:
    if timeout is _SOCKET_DEFAULT_TIMEOUT:
        return socket.getdefaulttimeout()
    try:
        value = float(timeout)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return socket.getdefaulttimeout()
    if value <= 0:
        return 0.0
    return value


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("proxy connection closed unexpectedly")
        data += chunk
    return data


def _new_tcp_socket(timeout: float | None, source_address: tuple[str, int] | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    if source_address is not None:
        sock.bind(source_address)
    return sock


def _socks5_open_tunnel(
    proxy: ProxyConfig,
    target_host: str,
    target_port: int,
    timeout: float | None,
    source_address: tuple[str, int] | None,
) -> socket.socket:
    sock = _new_tcp_socket(timeout, source_address)
    try:
        sock.connect((proxy.host, proxy.port))

        methods = [0x00]
        if proxy.username is not None:
            methods.append(0x02)
        sock.sendall(bytes([0x05, len(methods), *methods]))
        hello = _recv_exact(sock, 2)
        if hello[0] != 0x05 or hello[1] == 0xFF:
            raise OSError("socks5 proxy authentication method negotiation failed")

        if hello[1] == 0x02:
            user_raw = str(proxy.username or "").encode("utf-8", errors="replace")
            pass_raw = str(proxy.password or "").encode("utf-8", errors="replace")
            if len(user_raw) > 255 or len(pass_raw) > 255:
                raise OSError("socks5 credentials are too long")
            sock.sendall(bytes([0x01, len(user_raw)]) + user_raw + bytes([len(pass_raw)]) + pass_raw)
            auth_reply = _recv_exact(sock, 2)
            if auth_reply[1] != 0x00:
                raise OSError("socks5 proxy authentication failed")

        use_remote_dns = proxy.scheme == "socks5h"
        if use_remote_dns:
            host_raw = target_host.encode("idna")
            if not host_raw or len(host_raw) > 255:
                raise OSError("invalid target host for socks5h proxy")
            atyp = 0x03
            addr_payload = bytes([len(host_raw)]) + host_raw
        else:
            try:
                ip = ipaddress.ip_address(target_host)
                atyp = 0x01 if ip.version == 4 else 0x04
                addr_payload = ip.packed
            except ValueError as exc:
                host_raw = target_host.encode("idna")
                if not host_raw or len(host_raw) > 255:
                    raise OSError("invalid target host for socks5 proxy") from exc
                atyp = 0x03
                addr_payload = bytes([len(host_raw)]) + host_raw

        req = bytes([0x05, 0x01, 0x00, atyp]) + addr_payload + int(target_port).to_bytes(2, "big")
        sock.sendall(req)
        reply_head = _recv_exact(sock, 4)
        if reply_head[0] != 0x05:
            raise OSError("socks5 proxy returned invalid response")
        rep = reply_head[1]
        if rep != 0x00:
            raise OSError(f"socks5 proxy connect failed (code={rep})")

        rep_atyp = reply_head[3]
        if rep_atyp == 0x01:
            _recv_exact(sock, 4)
        elif rep_atyp == 0x04:
            _recv_exact(sock, 16)
        elif rep_atyp == 0x03:
            domain_len = _recv_exact(sock, 1)[0]
            _recv_exact(sock, domain_len)
        else:
            raise OSError("socks5 proxy returned invalid address type")
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def _host_port_for_connect(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _http_open_tunnel(
    proxy: ProxyConfig,
    target_host: str,
    target_port: int,
    timeout: float | None,
    source_address: tuple[str, int] | None,
) -> socket.socket:
    sock = _new_tcp_socket(timeout, source_address)
    transport: socket.socket | ssl.SSLSocket = sock
    try:
        sock.connect((proxy.host, proxy.port))
        if proxy.scheme == "https":
            context = ssl.create_default_context()
            transport = context.wrap_socket(sock, server_hostname=proxy.host)
            transport.settimeout(timeout)

        target = _host_port_for_connect(target_host, target_port)
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "Proxy-Connection: Keep-Alive"]
        if proxy.username is not None:
            user = str(proxy.username or "")
            pwd = str(proxy.password or "")
            basic_raw = f"{user}:{pwd}".encode("utf-8", errors="replace")
            basic = base64.b64encode(basic_raw).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {basic}")
        lines.extend(["", ""])
        transport.sendall("\r\n".join(lines).encode("utf-8", errors="replace"))

        response = http.client.HTTPResponse(transport)
        response.begin()
        if int(response.status) != 200:
            raise OSError(f"http proxy connect failed (status={int(response.status)})")
        return transport
    except Exception:
        try:
            transport.close()
        except OSError:
            pass
        if transport is not sock:
            try:
                sock.close()
            except OSError:
                pass
        raise


def open_connection_via_proxy(
    proxy: ProxyConfig,
    address: tuple[Any, ...],
    timeout: object = _SOCKET_DEFAULT_TIMEOUT,
    source_address: tuple[str, int] | None = None,
) -> socket.socket:
    if len(address) < 2:
        raise OSError("invalid address tuple")
    host, port_raw = address[0], address[1]
    target_host = str(host or "").strip()
    if not target_host:
        raise OSError("invalid target host")
    try:
        target_port = int(port_raw)
    except (TypeError, ValueError) as exc:
        raise OSError("invalid target port") from exc
    if target_port < 1 or target_port > 65535:
        raise OSError("target port must be in range 1..65535")

    timeout_value = _resolve_timeout(timeout)
    if proxy.scheme in {"socks5", "socks5h"}:
        return _socks5_open_tunnel(proxy, target_host, target_port, timeout_value, source_address)
    if proxy.scheme in {"http", "https"}:
        return _http_open_tunnel(proxy, target_host, target_port, timeout_value, source_address)
    raise OSError("unsupported proxy scheme")


class ProxySocketPatch:
    """Patch socket.create_connection globally to route through a proxy tunnel."""

    def __init__(self, proxy: ProxyConfig | None) -> None:
        self._proxy = proxy
        self._orig_create_connection = socket.create_connection

    def __enter__(self) -> ProxySocketPatch:
        if self._proxy is None:
            return self

        def _patched_create_connection(
            address: tuple[Any, ...],
            timeout: object = _SOCKET_DEFAULT_TIMEOUT,
            source_address: tuple[str, int] | None = None,
        ) -> socket.socket:
            return open_connection_via_proxy(self._proxy, address, timeout=timeout, source_address=source_address)

        socket.create_connection = _patched_create_connection  # type: ignore[assignment]
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        socket.create_connection = self._orig_create_connection  # type: ignore[assignment]


@contextmanager
def proxy_socket_context(proxy: ProxyConfig | None) -> Iterator[None]:
    patch = ProxySocketPatch(proxy)
    with patch:
        yield
