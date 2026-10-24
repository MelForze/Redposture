"""Native asyncio HTTP/1.1 GET transport restricted to anonymous detection.

Unsupported response semantics explicitly request the established sync path.
There is no authentication, write operation or discovery download here.
"""

from __future__ import annotations

import asyncio
import http.client
import io
import ipaddress
import ssl
from typing import Any, cast
from urllib.parse import urlsplit

from . import transport
from .http_api import HttpResponse, decode_http_content, normalize_http_error
from .tls_cache import shared_client_ssl_context

_HEADER_CAP = 64 * 1024


class AsyncHttpFallback(Exception):
    """The synchronous client must verify this target; never a negative verdict."""


class _HeaderSocket:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def makefile(self, *_args: Any, **_kwargs: Any) -> io.BytesIO:
        return io.BytesIO(self.data)


class AsyncDetectionHttp:
    def __init__(
        self,
        *,
        timeout: float,
        retries: int,
        max_bytes: int,
        ssl_context: ssl.SSLContext | None = None,
        decode_content: bool = True,
        escalate_timeouts: bool = True,
    ) -> None:
        self.timeout = max(0.1, float(timeout)) if escalate_timeouts else float(timeout)
        self.escalate_timeouts = escalate_timeouts
        self.retries = max(0, int(retries))
        self.max_bytes = max(0, int(max_bytes))
        self.ssl_context = ssl_context
        self.decode_content = decode_content
        self.last_exception: BaseException | None = None
        self.last_reason: str | None = None
        self._connection: tuple[tuple[str, str, int], asyncio.StreamReader, asyncio.StreamWriter] | None = None
        self._stats = dict(requests=0, connections=0, reused=0, retries=0)
        self._buffer = bytearray()

    async def __aenter__(self) -> AsyncDetectionHttp:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        await self.close()

    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def close(self) -> None:
        current, self._connection = self._connection, None
        self._buffer.clear()
        if current is None:
            return
        writer = current[2]
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 0.25)
        except (TimeoutError, OSError, ssl.SSLError):
            writer.transport.abort()
        except asyncio.CancelledError:
            writer.transport.abort()
            raise

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        return await self.request("GET", url, headers=headers, replay_safe=True)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        replay_safe: bool = False,
    ) -> HttpResponse:
        method = method.upper()
        if method not in {"GET", "HEAD", "POST"}:
            raise AsyncHttpFallback("unsupported detection HTTP method")
        retries = self.retries if method in {"GET", "HEAD"} or replay_safe else 0
        self.last_exception = None
        for attempt in range(retries + 1):
            timeout = transport.escalating_timeout(self.timeout, attempt) if self.escalate_timeouts else self.timeout
            try:
                if method == "GET" and body is None:
                    return await self._once(url, timeout, headers or {})
                return await self._once(url, timeout, headers or {}, method=method, body=body)
            except AsyncHttpFallback:
                await self.close()
                raise
            except (
                OSError,
                ValueError,
                http.client.HTTPException,
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
            ) as exc:
                await self.close()
                if isinstance(exc, asyncio.IncompleteReadError):
                    exc = http.client.RemoteDisconnected("unexpected EOF: incomplete HTTP response")
                self.last_exception = exc
                error = "timed out" if isinstance(exc, TimeoutError) else normalize_http_error(exc)
                retryable = transport.is_escalating_reason(transport.classify_failure_reason(error)) or isinstance(
                    exc, http.client.RemoteDisconnected
                )
                if attempt < retries and retryable:
                    self._stats["retries"] += 1
                    await asyncio.sleep(min(1.5, 0.2 * (2**attempt)))
                    continue
                return HttpResponse(
                    status=0, body=b"", headers={}, error=error or type(exc).__name__, request_url=url, final_url=url
                )
        raise AssertionError("unreachable")

    async def _until(self, reader: asyncio.StreamReader, separator: bytes, timeout: float, cap: int) -> bytes:
        # Socket timeouts measure inactivity, not total response duration.
        # Keep bytes read after a delimiter for the next framed read.
        while True:
            index = self._buffer.find(separator)
            if index >= 0:
                end = index + len(separator)
                if end > cap:
                    raise AsyncHttpFallback("large HTTP headers or framing")
                result = bytes(self._buffer[:end])
                del self._buffer[:end]
                return result
            if len(self._buffer) >= cap:
                raise AsyncHttpFallback("large HTTP headers or framing")
            chunk = await asyncio.wait_for(reader.read(min(65536, cap + 1 - len(self._buffer))), timeout)
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(self._buffer), None)
            self._buffer.extend(chunk)

    async def _read(self, reader: asyncio.StreamReader, size: int, timeout: float, *, exact: bool = True) -> bytes:
        data = bytearray(self._buffer[:size])
        del self._buffer[:size]
        while len(data) < size:
            chunk = await asyncio.wait_for(reader.read(min(65536, size - len(data))), timeout)
            if not chunk:
                if exact:
                    raise asyncio.IncompleteReadError(bytes(data), size)
                break
            data.extend(chunk)
        return bytes(data)

    async def _once(
        self, url: str, timeout: float, headers: dict[str, str], *, method: str = "GET", body: bytes | None = None
    ) -> HttpResponse:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        if scheme not in {"http", "https"} or not host or parsed.username is not None:
            raise AsyncHttpFallback("unsupported request URL")
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            # asyncio's default resolver owns non-daemon executor threads;
            # blocked DNS survives cancellation. Keep DNS on the daemon sync
            # path until a bounded cancellable resolver is available.
            raise AsyncHttpFallback("hostname requires synchronous resolver") from exc
        if "%" in host:
            # asyncio also resolves zone-indexed IPv6 through its executor.
            raise AsyncHttpFallback("scoped IPv6 requires synchronous resolver")
        port = parsed.port or (443 if scheme == "https" else 80)
        key = (scheme, host, port)
        if self._connection is not None and (self._connection[0] != key or self._connection[2].is_closing()):
            await self.close()
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        authority = f"[{host}]" if ":" in host else host
        if port != (443 if scheme == "https" else 80):
            authority += f":{port}"
        try:
            supplied = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
            if any(any(c in str(value) for c in "\r\n\x00") for pair in headers.items() for value in pair):
                raise AsyncHttpFallback("invalid request header")
            lowered = {str(key).lower() for key in headers}
            defaults = {"Host": authority, "Accept-Encoding": "identity", "Connection": "keep-alive"}
            if body is not None and "content-length" not in lowered:
                defaults["Content-Length"] = str(len(body))
            automatic = "".join(f"{key}: {value}\r\n" for key, value in defaults.items() if key.lower() not in lowered)
            request = (f"{method} {path} HTTP/1.1\r\n{automatic}{supplied}\r\n").encode("ascii") + (body or b"")
        except UnicodeError as exc:
            raise AsyncHttpFallback("non-ASCII request URL") from exc
        if any(c in path for c in "\r\n\x00"):
            raise AsyncHttpFallback("invalid request path")
        if self._connection is None:
            tls = self.ssl_context or shared_client_ssl_context(insecure=False) if scheme == "https" else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port, ssl=tls, server_hostname=host if tls else None, limit=_HEADER_CAP + 4
                ),
                timeout,
            )
            self._connection = (key, reader, writer)
            self._stats["connections"] += 1
        else:
            _, reader, writer = self._connection
            self._stats["reused"] += 1
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout)
        self._stats["requests"] += 1
        raw = await self._until(reader, b"\r\n\r\n", timeout, _HEADER_CAP)
        # HTTPResponse.begin itself consumes a following header block for 100.
        # Our bounded header buffer intentionally contains only one block.
        try:
            raw_status = int(raw.split(b"\r\n", 1)[0].split()[1])
        except (ValueError, IndexError) as exc:
            raise AsyncHttpFallback("invalid HTTP status") from exc
        if 100 <= raw_status < 200:
            raise AsyncHttpFallback("interim HTTP response")
        message = http.client.HTTPResponse(cast(Any, _HeaderSocket(raw)))
        message.begin()
        self.last_reason = str(message.reason)
        status = message.status
        header_items = message.getheaders()
        headers = {str(k): str(v) for k, v in header_items}
        names = [k.lower() for k, _ in header_items]
        lower = {k.lower(): v for k, v in header_items}
        if (
            100 <= status < 200
            or 300 <= status < 400
            or names.count("content-length") > 1
            or names.count("transfer-encoding") > 1
        ):
            raise AsyncHttpFallback("redirect or ambiguous framing")
        encoding = lower.get("transfer-encoding", "").strip().lower()
        if encoding and (encoding != "chunked" or "content-length" in lower):
            raise AsyncHttpFallback("unsupported transfer encoding")
        response_body = bytearray()
        truncated = False
        if method == "HEAD" or status in {204, 304}:
            pass
        elif message.chunked:
            trailer_size = 0
            while True:
                line = await self._until(reader, b"\n", timeout, 128)
                if not line or len(line) > 128:
                    raise AsyncHttpFallback("invalid chunk size")
                size = int(line.split(b";", 1)[0].strip(), 16)
                if size < 0:
                    raise AsyncHttpFallback("negative chunk")
                if size == 0:
                    while True:
                        line = await self._until(reader, b"\n", timeout, _HEADER_CAP)
                        trailer_size += len(line)
                        if trailer_size > _HEADER_CAP or not line:
                            raise AsyncHttpFallback("invalid chunk trailers")
                        if line in {b"\r\n", b"\n"}:
                            break
                    break
                take = min(size, self.max_bytes + 1 - len(response_body))
                response_body.extend(await self._read(reader, take, timeout))
                if len(response_body) > self.max_bytes:
                    truncated = True
                    break
                if await self._read(reader, 2, timeout) != b"\r\n":
                    raise AsyncHttpFallback("invalid chunk ending")
        elif message.length is not None:
            length = message.length
            if length < 0:
                raise AsyncHttpFallback("negative content length")
            response_body.extend(await self._read(reader, min(length, self.max_bytes + 1), timeout))
            truncated = length > self.max_bytes
        else:
            response_body.extend(await self._read(reader, self.max_bytes + 1, timeout, exact=False))
            truncated = len(response_body) > self.max_bytes
        if truncated or message.will_close:
            await self.close()
        response = HttpResponse(
            status=status,
            body=bytes(response_body[: self.max_bytes]),
            headers=headers,
            truncated=truncated,
            request_url=url,
            final_url=url,
        )
        return decode_http_content(response, max_bytes=self.max_bytes) if self.decode_content else response
