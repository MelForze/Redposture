"""Shared HTTP/API client used by stage modules."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..network_proxy import ProxyConfig, open_connection_via_proxy, parse_proxy_config


@dataclass(frozen=True)
class HttpClientConfig:
    timeout: float = 3.0
    retries: int = 0
    backoff: float = 0.15
    insecure: bool = False
    ca_file: str | None = None
    proxy: ProxyConfig | str | None = None
    response_size_cap: int = 10 * 1024 * 1024
    default_headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | str | None = None
    json_body: Any = None


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str]
    error: str | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


def normalize_http_error(exc: BaseException) -> str:
    text = str(exc).strip()
    if text.startswith("<urlopen error ") and text.endswith(">"):
        text = text[len("<urlopen error ") : -1].strip()
    return text or exc.__class__.__name__


def _ssl_context(insecure: bool, ca_file: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_file or None)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _flush_tls_outgoing(sock: Any, outgoing: ssl.MemoryBIO) -> None:
    while True:
        chunk = outgoing.read()
        if not chunk:
            return
        sock.sendall(chunk)


def _tls_over_tls_exchange(
    sock: Any,
    context: ssl.SSLContext,
    *,
    server_hostname: str,
    request_payload: bytes,
    response_cap: int,
) -> bytes:
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=server_hostname)

    while True:
        try:
            tls.do_handshake()
            _flush_tls_outgoing(sock, outgoing)
            break
        except ssl.SSLWantReadError:
            _flush_tls_outgoing(sock, outgoing)
            chunk = sock.recv(65536)
            if not chunk:
                raise OSError("target TLS handshake closed") from None
            incoming.write(chunk)
        except ssl.SSLWantWriteError:
            _flush_tls_outgoing(sock, outgoing)

    view = memoryview(request_payload)
    while view:
        try:
            written = tls.write(view)
            view = view[written:]
            _flush_tls_outgoing(sock, outgoing)
        except ssl.SSLWantReadError:
            _flush_tls_outgoing(sock, outgoing)
            chunk = sock.recv(65536)
            if not chunk:
                raise OSError("target TLS write closed") from None
            incoming.write(chunk)
        except ssl.SSLWantWriteError:
            _flush_tls_outgoing(sock, outgoing)

    chunks: list[bytes] = []
    total = 0
    max_bytes = max(0, int(response_cap)) + 65536
    while total <= max_bytes:
        try:
            chunk = tls.read(65536)
            if chunk:
                chunks.append(chunk)
                total += len(chunk)
            else:
                break
        except ssl.SSLWantReadError:
            _flush_tls_outgoing(sock, outgoing)
            outer = sock.recv(65536)
            if not outer:
                break
            incoming.write(outer)
        except ssl.SSLEOFError:
            break
    return b"".join(chunks)


def _decode_chunked_body(body: bytes) -> bytes:
    output = bytearray()
    remaining = body
    while remaining:
        line, sep, rest = remaining.partition(b"\r\n")
        if not sep:
            break
        try:
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            return bytes(output) if output else body
        if size == 0:
            break
        if len(rest) < size:
            output.extend(rest)
            break
        output.extend(rest[:size])
        remaining = rest[size + 2 :] if rest[size : size + 2] == b"\r\n" else rest[size:]
    return bytes(output)


def _parse_http_response_bytes(raw: bytes, *, response_cap: int) -> tuple[int, dict[str, str], bytes]:
    header_bytes, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise OSError("invalid HTTP response from target")
    lines = header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    status_line = lines[0] if lines else ""
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise OSError("invalid HTTP status from target")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    if headers.get("Transfer-Encoding", "").lower() == "chunked":
        body = _decode_chunked_body(body)
    cap = max(0, int(response_cap))
    if len(body) > cap:
        body = body[:cap]
    return int(parts[1]), headers, body


class HttpApiClient:
    """Small stdlib HTTP client with normalized errors and shared config.

    Proxy support is intentionally compatible with the global
    `proxy_socket_context`: modules pass the parsed proxy in config for telemetry,
    while the actual socket routing is handled by the shared socket patch.
    """

    def __init__(self, config: HttpClientConfig | None = None) -> None:
        self.config = config or HttpClientConfig()
        self._context = (
            _ssl_context(self.config.insecure, self.config.ca_file)
            if self.config.insecure or self.config.ca_file
            else None
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        json_body: Any = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        request = HttpRequest(
            method=method,
            url=url,
            headers=headers or {},
            body=body,
            json_body=json_body,
        )
        return self.send(request, timeout=timeout)

    def get(self, url: str, *, headers: Mapping[str, str] | None = None, timeout: float | None = None) -> HttpResponse:
        return self.request("GET", url, headers=headers, timeout=timeout)

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        json_body: Any = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        return self.request("POST", url, headers=headers, body=body, json_body=json_body, timeout=timeout)

    def download_to_file(
        self,
        url: str,
        out_path: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        chunk_size: int = 1024 * 64,
    ) -> tuple[int, int, str | None]:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={**{str(k): str(v) for k, v in self.config.default_headers.items()}, **dict(headers or {})},
        )
        try:
            timeout_value = float(timeout if timeout is not None else self.config.timeout)
            request_kwargs: dict[str, Any] = {"timeout": timeout_value}
            if self._context is not None:
                request_kwargs["context"] = self._context
            with urllib.request.urlopen(req, **request_kwargs) as resp:
                size = 0
                with open(out_path, "wb") as fh:
                    while True:
                        chunk = resp.read(max(1, int(chunk_size)))
                        if not chunk:
                            break
                        fh.write(chunk)
                        size += len(chunk)
                return int(getattr(resp, "status", 0) or resp.getcode()), size, None
        except urllib.error.HTTPError as exc:
            return int(exc.code), 0, None
        except Exception as exc:
            return 0, 0, normalize_http_error(exc)

    def send(self, request: HttpRequest, *, timeout: float | None = None) -> HttpResponse:
        attempts = max(1, int(self.config.retries) + 1)
        last_error = ""
        for attempt in range(1, attempts + 1):
            response = self._send_once(request, timeout=timeout)
            if response.error is None:
                return response
            last_error = response.error
            if attempt < attempts:
                time.sleep(max(0.0, float(self.config.backoff)) * attempt)
        return HttpResponse(status=0, body=b"", headers={}, error=last_error or "request failed")

    def _send_once(self, request: HttpRequest, *, timeout: float | None = None) -> HttpResponse:
        headers = {str(key): str(value) for key, value in self.config.default_headers.items()}
        headers.update({str(key): str(value) for key, value in request.headers.items()})
        body = request.body
        if request.json_body is not None:
            body = json.dumps(request.json_body, separators=(",", ":")).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            body = body.encode("utf-8")

        req = urllib.request.Request(
            request.url,
            data=body,
            method=str(request.method or "GET").upper(),
            headers=headers,
        )
        if self._requires_manual_https_proxy_tunnel(request.url):
            return self._send_https_target_via_https_proxy(
                req,
                body=body,
                timeout=timeout,
            )
        try:
            timeout_value = float(timeout if timeout is not None else self.config.timeout)
            request_kwargs: dict[str, Any] = {"timeout": timeout_value}
            if self._context is not None:
                request_kwargs["context"] = self._context
            open_response = urllib.request.urlopen(req, **request_kwargs)
            with open_response as resp:
                read_size = max(0, int(self.config.response_size_cap)) + 1
                try:
                    payload = resp.read(read_size)
                except TypeError:
                    payload = resp.read()
                if len(payload) > int(self.config.response_size_cap):
                    payload = payload[: int(self.config.response_size_cap)]
                return HttpResponse(
                    status=int(getattr(resp, "status", 0) or resp.getcode()),
                    body=payload,
                    headers={str(key): str(value) for key, value in getattr(resp, "headers", {}).items()},
                    error=None,
                )
        except urllib.error.HTTPError as exc:
            try:
                read_size = max(0, int(self.config.response_size_cap)) + 1
                try:
                    payload = exc.read(read_size)
                except TypeError:
                    payload = exc.read()
            except Exception:
                payload = b""
            if len(payload) > int(self.config.response_size_cap):
                payload = payload[: int(self.config.response_size_cap)]
            return HttpResponse(
                status=int(exc.code),
                body=payload,
                headers={str(key): str(value) for key, value in exc.headers.items()},
                error=None,
            )
        except Exception as exc:
            return HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc))

    def _requires_manual_https_proxy_tunnel(self, url: str) -> bool:
        proxy = self._proxy_config()
        if proxy is None or proxy.scheme != "https":
            return False
        parsed = urllib.parse.urlsplit(str(url or ""))
        return parsed.scheme.lower() == "https"

    def _proxy_config(self) -> ProxyConfig | None:
        proxy = self.config.proxy
        if proxy is None or isinstance(proxy, ProxyConfig):
            return proxy
        parsed, error = parse_proxy_config(str(proxy))
        if error:
            return None
        return parsed

    def _send_https_target_via_https_proxy(
        self,
        req: urllib.request.Request,
        *,
        body: bytes | None,
        timeout: float | None,
    ) -> HttpResponse:
        proxy = self._proxy_config()
        if proxy is None:
            return HttpResponse(status=0, body=b"", headers={}, error="missing https proxy config")
        parsed = urllib.parse.urlsplit(req.full_url)
        host = str(parsed.hostname or "").strip()
        if not host:
            return HttpResponse(status=0, body=b"", headers={}, error="invalid target host")
        port = int(parsed.port or 443)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        timeout_value = float(timeout if timeout is not None else self.config.timeout)
        host_header = f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
        if port == 443:
            host_header = f"[{host}]" if ":" in host and not host.startswith("[") else host

        headers = {str(k): str(v) for k, v in req.header_items()}
        headers.setdefault("Host", host_header)
        headers.setdefault("Connection", "close")
        if body is not None:
            headers.setdefault("Content-Length", str(len(body)))

        request_head = [f"{req.get_method()} {path} HTTP/1.1"]
        request_head.extend(f"{key}: {value}" for key, value in headers.items())
        payload = ("\r\n".join(request_head) + "\r\n\r\n").encode("iso-8859-1", errors="replace") + (body or b"")

        outer = None
        try:
            outer = open_connection_via_proxy(proxy, (host, port), timeout=timeout_value)
            outer.settimeout(timeout_value)
            tls_context = self._context or _ssl_context(False, self.config.ca_file)
            response_raw = _tls_over_tls_exchange(
                outer,
                tls_context,
                server_hostname=host,
                request_payload=payload,
                response_cap=max(0, int(self.config.response_size_cap)),
            )
            status, response_headers, response_body = _parse_http_response_bytes(
                response_raw,
                response_cap=max(0, int(self.config.response_size_cap)),
            )
            return HttpResponse(status=status, body=response_body, headers=response_headers, error=None)
        except Exception as exc:
            return HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc))
        finally:
            if outer is not None:
                try:
                    outer.close()
                except OSError:
                    pass


__all__ = [
    "HttpApiClient",
    "HttpClientConfig",
    "HttpRequest",
    "HttpResponse",
    "normalize_http_error",
]
