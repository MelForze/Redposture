"""ClickHouse Connect's original HTTP initializer over retained native sockets.

Driver code sees only immutable, already received responses during replay. All
TCP/TLS work runs through RetainedSocketIO; the completed synchronous client
adopts the same fully consumed socket for its existing downstream worker.
"""

from __future__ import annotations

import http.client
import io
import uuid
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import parse_qsl, urlsplit

from .async_http_detect import AsyncHttpFallback
from .async_retained_socket import RetainedSocketIO
from .tls_cache import shared_client_ssl_context

_BODY_CAP = 10 * 1024 * 1024
_HEADER_CAP = 64 * 1024


class _NeedRequest(BaseException):
    def __init__(self, method: str, url: str, options: dict[str, Any]) -> None:
        self.method, self.url, self.options = method, url, options


@dataclass
class _Response:
    status: int
    headers: Any
    body: bytes
    reason: str

    def materialize(self, options: dict[str, Any]) -> Any:
        from urllib3.response import HTTPResponse

        return HTTPResponse(
            body=io.BytesIO(self.body),
            headers=self.headers,
            status=self.status,
            reason=self.reason,
            preload_content=bool(options.get("preload_content", True)),
            decode_content=True,
        )


class _ReplayPool:
    def __init__(self) -> None:
        self.responses: list[tuple[Any, _Response | BaseException]] = []
        self.position = 0

    @staticmethod
    def key(method: str, url: str, options: dict[str, Any]) -> Any:
        parsed = urlsplit(url)
        params = tuple((name, value) for name, value in parse_qsl(parsed.query) if name != "query_id")
        return method, parsed.scheme, parsed.netloc, parsed.path, params, options.get("body")

    def request(self, method: str, url: str, **options: Any) -> Any:
        key = self.key(method, url, options)
        if self.position == len(self.responses):
            raise _NeedRequest(method, url, options)
        expected, response = self.responses[self.position]
        self.position += 1
        if key != expected:
            raise AsyncHttpFallback("ClickHouse HTTP initializer is not replay-stable")
        if isinstance(response, BaseException):
            raise response
        return response.materialize(options)

    def clear(self) -> None:
        # The original driver's expiration check can only clear response memory
        # here. A real pool is installed after the initializer has completed.
        pass


class _HeaderSocket:
    def __init__(self, headers: bytes) -> None:
        self.headers = headers

    def makefile(self, *_args: Any, **_kwargs: Any) -> io.BytesIO:
        return io.BytesIO(self.headers)


class NativeClickHouseHttp:
    def __init__(
        self,
        io_backend: RetainedSocketIO,
        host: str,
        port: int,
        timeout: float,
        username: str,
        password: str,
        database: str,
        tls_config: Any,
        proxy: Any,
    ) -> None:
        from clickhouse_connect import common
        from clickhouse_connect.driver.httputil import check_env_proxy

        if proxy is not None and str(getattr(proxy, "raw_url", proxy) or "").strip():
            raise AsyncHttpFallback("proxied ClickHouse HTTP detection")
        self.io = io_backend
        self.host, self.port, self.timeout = host, port, timeout
        self.username, self.password, self.database = username, password, database
        self.tls = tls_config
        self.secure = bool(tls_config and tls_config.enabled)
        if check_env_proxy("https" if self.secure else "http", host, port):
            raise AsyncHttpFallback("ClickHouse HTTP environment proxy")
        self.socket: Any = None
        self.buffer = bytearray()
        self.pool = _ReplayPool()
        self.client: Any = None
        self.session_id = str(uuid.uuid4()) if common.get_setting("autogenerate_session_id") else None

    async def _drive(self, function: Any) -> Any:
        self.pool.responses.clear()
        while True:
            self.pool.position = 0
            try:
                return function()
            except _NeedRequest as request:
                try:
                    response: Any = await self._exchange(request)
                except AsyncHttpFallback:
                    raise
                except OSError as exc:
                    self._discard_socket()
                    # urllib3 distinguishes connect/read/status retry budgets.
                    # Let its original transport classify and retry ambiguous
                    # failures instead of weakening that policy in replay.
                    raise AsyncHttpFallback("ClickHouse HTTP transport needs original retry policy") from exc
                self.pool.responses.append((self.pool.key(request.method, request.url, request.options), response))
                if len(self.pool.responses) > 64:
                    raise AsyncHttpFallback("large ClickHouse HTTP initializer request sequence") from request

    async def initialize(self) -> Any:
        import clickhouse_connect
        from clickhouse_connect.driver import create_client

        from ..modules.clickhouse import actions

        if clickhouse_connect.get_client is not create_client:
            raise AsyncHttpFallback("ClickHouse Connect HTTP factory override")
        kwargs: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "database": self.database,
            "interface": "https" if self.secure else "http",
            "secure": self.secure,
            "connect_timeout": float(self.timeout),
            "send_receive_timeout": float(self.timeout),
            "pool_mgr": self.pool,
            "session_id": self.session_id,
        }
        if self.tls is not None and self.tls.proxy_path:
            kwargs["proxy_path"] = self.tls.proxy_path
        if self.secure:
            kwargs.update(
                verify=self.tls.verify,
                ca_cert=self.tls.ca_file,
                client_cert=self.tls.cert_file,
                client_cert_key=self.tls.key_file,
                server_host_name=self.tls.server_name or self.host,
            )
        kwargs = {key: value for key, value in kwargs.items() if value is not None}
        try:
            self.client = await self._drive(lambda: create_client(**kwargs))
        except TypeError as exc:
            # Match the original factory's older-driver timeout compatibility.
            if not actions.is_signature_compat_typeerror(
                exc, expected_keywords={"connect_timeout", "send_receive_timeout"}
            ):
                raise
            unsupported = "send_receive_timeout" if "send_receive_timeout" in str(exc) else "connect_timeout"
            kwargs.pop(unsupported, None)
            self.client = await self._drive(lambda: create_client(**kwargs))
        return self.client

    async def query(self, sql: str, *, rows: bool = False) -> Any:
        if self.client is None:
            raise AsyncHttpFallback("ClickHouse HTTP client is uninitialized")
        if rows:
            return await self._drive(lambda: self.client.query(sql).result_rows)
        return await self._drive(lambda: self.client.query(sql))

    async def _until(self, separator: bytes, limit: int) -> bytes:
        while True:
            index = self.buffer.find(separator)
            if index >= 0:
                end = index + len(separator)
                if end > limit:
                    raise AsyncHttpFallback("large ClickHouse HTTP framing")
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result
            if len(self.buffer) >= limit:
                raise AsyncHttpFallback("large ClickHouse HTTP framing")
            chunk = await self.io.recv(self.socket, min(4096, limit - len(self.buffer)))
            if not chunk:
                raise ConnectionError("unexpected EOF in ClickHouse HTTP response")
            self.buffer.extend(chunk)

    async def _exact(self, size: int) -> bytes:
        if size < 0 or size > _BODY_CAP:
            raise AsyncHttpFallback("large ClickHouse HTTP detection response")
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        if len(result) < size:
            result += await self.io.recv_exact(self.socket, size - len(result))
        return result

    async def _exchange(self, request: _NeedRequest) -> _Response:
        parsed = urlsplit(request.url)
        if (
            parsed.hostname != self.host
            or parsed.port != self.port
            or parsed.scheme != ("https" if self.secure else "http")
        ):
            raise AsyncHttpFallback("ClickHouse HTTP initializer changed origin")
        if request.method not in {"GET", "HEAD", "POST"} or request.options.get("fields"):
            raise AsyncHttpFallback("unsupported ClickHouse HTTP initializer request")
        body = request.options.get("body") or b""
        if isinstance(body, str):
            body = body.encode()
        if not isinstance(body, bytes):
            raise AsyncHttpFallback("streaming ClickHouse detection request")
        query = body.decode("utf-8").strip() or dict(parse_qsl(parsed.query)).get("query", "").strip()
        if not query.upper().startswith("SELECT "):
            raise AsyncHttpFallback("ClickHouse detection request is not a read-only SELECT")
        timeout = request.options.get("timeout")
        connect_timeout = getattr(timeout, "connect_timeout", self.timeout)
        read_timeout = getattr(timeout, "read_timeout", self.timeout)
        if self.socket is None:
            self.socket = await self.io.open((self.host, self.port), connect_timeout)
            if self.secure:
                ca_file = self.tls.ca_file
                if ca_file == "certifi":
                    import certifi

                    ca_file = certifi.where()
                context = shared_client_ssl_context(
                    insecure=not self.tls.verify,
                    ca_file=ca_file,
                    cert_file=self.tls.cert_file,
                    key_file=self.tls.key_file,
                )
                self.socket = await self.io.wrap(
                    context, self.socket, server_hostname=self.tls.server_name or self.host
                )
        self.io.sockets[self.socket] = read_timeout
        headers = dict(request.options.get("headers") or {})
        authority = f"[{self.host}]" if ":" in self.host else self.host
        headers.setdefault("Host", f"{authority}:{self.port}")
        headers.setdefault("Accept-Encoding", "identity")
        headers.setdefault("Content-Length", str(len(body)))
        if any(any(char in str(value) for char in "\r\n\x00") for pair in headers.items() for value in pair):
            raise AsyncHttpFallback("invalid ClickHouse HTTP detection header")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        header_text = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
        wire = f"{request.method} {path} HTTP/1.1\r\n{header_text}\r\n".encode("latin-1") + body
        await self.io.sendall(self.socket, wire)
        raw_headers = bytearray()
        while True:
            part = await self._until(b"\r\n\r\n", _HEADER_CAP)
            raw_headers.extend(part)
            if len(raw_headers) > _HEADER_CAP:
                raise AsyncHttpFallback("large ClickHouse HTTP response headers")
            if part.split(b" ", 2)[1:2] != [b"100"]:
                break
        response = http.client.HTTPResponse(cast(Any, _HeaderSocket(bytes(raw_headers))), method=request.method)
        try:
            response.begin()
        except http.client.HTTPException as exc:
            raise AsyncHttpFallback("unsupported ClickHouse HTTP response framing") from exc
        if response.status in {301, 302, 303, 307, 308}:
            raise AsyncHttpFallback("ClickHouse HTTP redirect requires original pool policy")
        if response.chunked:
            content = bytearray()
            while True:
                line = await self._until(b"\r\n", _HEADER_CAP)
                try:
                    size = int(line.split(b";", 1)[0], 16)
                except ValueError as exc:
                    raise AsyncHttpFallback("invalid ClickHouse HTTP chunk size") from exc
                if size == 0:
                    trailers_size = 0
                    while True:
                        trailer = await self._until(b"\r\n", _HEADER_CAP)
                        trailers_size += len(trailer)
                        if trailers_size > _HEADER_CAP:
                            raise AsyncHttpFallback("large ClickHouse HTTP trailers")
                        if trailer == b"\r\n":
                            break
                    break
                if size < 0 or len(content) + size > _BODY_CAP:
                    raise AsyncHttpFallback("large ClickHouse HTTP chunked response")
                content.extend(await self._exact(size))
                if await self._exact(2) != b"\r\n":
                    raise AsyncHttpFallback("invalid ClickHouse HTTP chunk terminator")
            payload = bytes(content)
        elif response.length is not None:
            payload = await self._exact(response.length)
        else:
            content = bytearray(self.buffer)
            self.buffer.clear()
            while True:
                chunk = await self.io.recv(self.socket, 4096)
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > _BODY_CAP:
                    raise AsyncHttpFallback("large ClickHouse close-delimited HTTP response")
            payload = bytes(content)
        if self.buffer:
            raise AsyncHttpFallback("unsolicited ClickHouse HTTP response bytes")
        result = _Response(response.status, list(response.getheaders()), payload, response.reason)
        if response.will_close:
            self._discard_socket()
        return result

    def _discard_socket(self) -> None:
        if self.socket is not None:
            self.io.sockets.pop(self.socket, None)
            self.socket.close()
            self.socket = None
        self.buffer.clear()

    def adopt(self) -> None:
        from clickhouse_connect.driver import httputil

        if self.client is None:
            return
        if self.secure:
            options: dict[str, Any] = {"verify": self.tls.verify}
            for name, value in (
                ("ca_cert", self.tls.ca_file),
                ("client_cert", self.tls.cert_file),
                ("client_cert_key", self.tls.key_file),
            ):
                if value:
                    options[name] = value
            server_name = self.tls.server_name or self.host
            options["server_hostname"] = server_name
            if self.tls.verify:
                options["assert_hostname"] = server_name
            manager = httputil.get_pool_manager(**options)
            owned = True
        else:
            manager = httputil.default_pool_manager()
            owned = False
        httputil.check_conn_expiration(manager)
        if self.socket is not None:
            pool = manager.connection_from_url(self.client.url)
            connection = pool._get_conn(timeout=0)
            if connection.sock is not None:
                pool._put_conn(connection)
                if owned:
                    manager.clear()
                raise AsyncHttpFallback("ClickHouse HTTP pool already owns a live socket")
            connection.sock = self.socket
            connection.timeout = self.timeout
            if self.secure:
                connection.is_verified = self.tls.verify
            pool._put_conn(connection)
            self.socket = None
        self.client.http = manager
        self.client._owns_pool_manager = owned
        httputil.all_managers.pop(cast(Any, self.pool), None)

    def close(self) -> None:
        from clickhouse_connect.driver import httputil

        self._discard_socket()
        httputil.all_managers.pop(cast(Any, self.pool), None)
