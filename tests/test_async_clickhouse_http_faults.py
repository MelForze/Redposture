"""Fault handling for native ClickHouse HTTP replay and retained-pool adoption."""

from __future__ import annotations

import asyncio
import gzip
import ssl
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from urllib3.exceptions import DecodeError

from redposture_core.clients import async_clickhouse_http_detect as http_detect
from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.clients.async_retained_socket import RetainedSocketIO


class IdleSocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class ForbiddenIO:
    """Reject accidental network work in validation/factory-only regressions."""

    def __init__(self):
        self.sockets: dict[Any, Any] = {}

    async def open(self, *args, **kwargs):
        pytest.fail("request validation must finish before opening a socket")


def transport(backend=None, *, tls=None, proxy=None, port=8123):
    return http_detect.NativeClickHouseHttp(
        backend if backend is not None else ForbiddenIO(), "127.0.0.1", port, 1, "default", "", "default", tls, proxy
    )


def tls_config(**overrides):
    values = dict(
        enabled=True, verify=False, ca_file=None, cert_file=None, key_file=None, server_name=None, proxy_path=None
    )
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.fixture(autouse=True)
def no_environment_proxy(monkeypatch):
    from clickhouse_connect.driver import httputil

    monkeypatch.setattr(httputil, "check_env_proxy", lambda *args: None)


@asynccontextmanager
async def exchange(payload, *, secure_context=None, tls=None, close_after_response=True):
    """Serve one complete request, retaining peer-close evidence on every exit."""
    requests = []
    closed = asyncio.Event()

    async def peer(reader, writer):
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            length = next(
                (
                    int(line.split(b":", 1)[1])
                    for line in headers.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                ),
                0,
            )
            body = await reader.readexactly(length)
            requests.append((headers, body))
            writer.write(payload)
            await writer.drain()
            if not close_after_response:
                await reader.read()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, TimeoutError):
                pass
            closed.set()

    server = await asyncio.start_server(peer, "127.0.0.1", 0, ssl=secure_context)
    backend = RetainedSocketIO()
    adapter = transport(backend, port=server.sockets[0].getsockname()[1], tls=tls)
    try:
        async with server:
            yield adapter, requests, closed
    finally:
        adapter.close()
        backend.close()
        if requests:
            await asyncio.wait_for(closed.wait(), 2)


async def request(adapter, *, method="POST", body=b"SELECT 1", path="/", **options):
    scheme = "https" if adapter.secure else "http"
    return await adapter._drive(
        lambda: adapter.pool.request(method, f"{scheme}://127.0.0.1:{adapter.port}{path}", body=body, **options)
    )


@pytest.mark.parametrize("case", ["explicit_proxy", "environment_proxy", "factory_override"])
def test_unsupported_factory_or_proxy_declines_before_network(case, monkeypatch):
    import clickhouse_connect
    from clickhouse_connect.driver import httputil

    if case == "explicit_proxy":
        with pytest.raises(AsyncHttpFallback, match="proxied"):
            transport(proxy=SimpleNamespace(raw_url="http://proxy.invalid:3128"))
    elif case == "environment_proxy":
        monkeypatch.setattr(httputil, "check_env_proxy", lambda *args: "http://proxy.invalid:3128")
        with pytest.raises(AsyncHttpFallback, match="environment proxy"):
            transport()
    else:
        monkeypatch.setattr(clickhouse_connect, "get_client", lambda **kwargs: pytest.fail("override called"))

        async def run():
            with pytest.raises(AsyncHttpFallback, match="factory override"):
                await transport().initialize()

        asyncio.run(run())


@pytest.mark.parametrize("unsupported", ["connect_timeout", "send_receive_timeout", None])
def test_driver_constructor_timeout_compatibility_and_non_signature_error(unsupported, monkeypatch):
    import clickhouse_connect
    from clickhouse_connect import driver

    calls = []
    client = SimpleNamespace()

    def create(**kwargs):
        calls.append(kwargs)
        if unsupported is None:
            raise TypeError("unexpected column codec type")
        if unsupported in kwargs:
            raise TypeError(f"create_client() got an unexpected keyword argument '{unsupported}'")
        return client

    monkeypatch.setattr(driver, "create_client", create)
    monkeypatch.setattr(clickhouse_connect, "get_client", create)

    async def run():
        adapter = transport(
            tls=tls_config(
                proxy_path="/clickhouse",
                server_name="database.internal",
                ca_file="ca.pem",
                cert_file="client.pem",
                key_file="client.key",
            )
        )
        if unsupported is None:
            with pytest.raises(TypeError, match="column codec"):
                await adapter.initialize()
            assert len(calls) == 1
        else:
            assert await adapter.initialize() is client
            assert len(calls) == 2
            assert unsupported in calls[0] and unsupported not in calls[1]
            assert calls[1]["interface"] == "https"
            assert calls[1]["proxy_path"] == "/clickhouse"
            assert calls[1]["server_host_name"] == "database.internal"
            assert calls[1]["client_cert_key"] == "client.key"

    asyncio.run(run())


@pytest.mark.parametrize(
    "method,url,options,reason",
    [
        ("POST", "http://elsewhere.invalid:8123/", {"body": b"SELECT 1"}, "changed origin"),
        ("POST", "http://127.0.0.1:8124/", {"body": b"SELECT 1"}, "changed origin"),
        ("POST", "https://127.0.0.1:8123/", {"body": b"SELECT 1"}, "changed origin"),
        ("PUT", "http://127.0.0.1:8123/", {"body": b"SELECT 1"}, "unsupported"),
        ("POST", "http://127.0.0.1:8123/", {"body": b"SELECT 1", "fields": {"sql": "SELECT 1"}}, "unsupported"),
        ("POST", "http://127.0.0.1:8123/", {"body": bytearray(b"SELECT 1")}, "streaming"),
        ("POST", "http://127.0.0.1:8123/", {"body": b"DROP TABLE important"}, "read-only SELECT"),
    ],
)
def test_unsupported_requests_decline_before_connect(method, url, options, reason):
    async def run():
        adapter = transport()
        with pytest.raises(AsyncHttpFallback, match=reason):
            await adapter._exchange(http_detect._NeedRequest(method, url, options))

    asyncio.run(run())


@pytest.mark.parametrize(
    "method,body,path",
    [
        ("POST", "SELECT 1", "/prefix?database=default"),
        ("GET", b"", "/?query=SELECT%201"),
        ("HEAD", b"", "/?query=SELECT%201"),
    ],
)
def test_string_body_query_parameter_and_head_response_are_preserved(method, body, path):
    async def run():
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        async with exchange(payload) as (adapter, requests, closed):
            response = await request(adapter, method=method, body=body, path=path)
            assert response.status == 200 and response.data == b""
            assert requests[0][0].startswith(f"{method} {path} HTTP/1.1\r\n".encode())
            assert requests[0][1] == (body.encode() if isinstance(body, str) else body)

    asyncio.run(run())


@pytest.mark.parametrize(
    "payload,expected",
    [
        (b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", b"ok"),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;extension=yes\r\nok\r\n0\r\nX-Query-Id: q1\r\n\r\n",
            b"ok",
        ),
        (b"HTTP/1.0 200 OK\r\n\r\nclose-delimited", b"close-delimited"),
    ],
)
def test_interim_chunked_with_trailers_and_close_delimited_body(payload, expected):
    async def run():
        async with exchange(payload) as (adapter, requests, closed):
            response = await request(adapter)
            assert response.status == 200 and response.data == expected
            assert len(requests) == 1

    asyncio.run(run())


@pytest.mark.parametrize(
    "payload,reason",
    [
        (b"NOT-HTTP\r\n\r\n", "unsupported.*framing"),
        (b"HTTP/1.1 307 Redirect\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n", "redirect"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", "original retry policy"),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnot-hex\r\n", "chunk size"),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n", "large.*chunked"),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nokXX", "chunk terminator"),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nx", "original retry policy"),
        (b"HTTP/1.1 200 OK\r\nContent-Length:", "original retry policy"),
    ],
)
def test_malformed_or_truncated_response_requests_full_legacy_verification(payload, reason):
    async def run():
        async with exchange(payload) as (adapter, requests, closed):
            with pytest.raises(AsyncHttpFallback, match=reason):
                await request(adapter)
            assert len(requests) == 1

    asyncio.run(run())


@pytest.mark.parametrize(
    "kind", ["content_length", "chunked", "close_delimited", "headers", "interim_headers", "trailers"]
)
def test_bounded_http_framing_and_payloads_decline_without_partial_success(kind, monkeypatch):
    monkeypatch.setattr(http_detect, "_BODY_CAP", 16)
    monkeypatch.setattr(http_detect, "_HEADER_CAP", 128)
    if kind == "content_length":
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n" + bytes(17)
    elif kind == "chunked":
        payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n11\r\n" + bytes(17) + b"\r\n0\r\n\r\n"
    elif kind == "close_delimited":
        payload = b"HTTP/1.0 200 OK\r\n\r\n" + bytes(8192)
    elif kind == "headers":
        payload = b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 128 + b"\r\n\r\n"
    elif kind == "interim_headers":
        payload = (
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 80 + b"\r\nContent-Length: 0\r\n\r\n"
        )
    else:
        payload = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n" + (b"X-Trailer: padding\r\n" * 8) + b"\r\n"
        )

    async def run():
        async with exchange(payload) as (adapter, requests, closed):
            with pytest.raises(AsyncHttpFallback, match="large"):
                await request(adapter)

    asyncio.run(run())


@pytest.mark.parametrize("valid", [False, True])
def test_driver_response_materialization_preserves_gzip_decode_errors(valid):
    body = gzip.compress(b"24.10.1\tUTC\n") if valid else b"not a gzip stream"
    payload = (
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )

    async def run():
        async with exchange(payload) as (adapter, requests, closed):
            if valid:
                response = await request(adapter)
                assert response.data == b"24.10.1\tUTC\n"
            else:
                with pytest.raises(DecodeError):
                    await request(adapter)

    asyncio.run(run())


def test_tls_certifi_alias_and_explicit_server_name_are_used_on_real_handshake(monkeypatch, mtls_material):
    import certifi

    monkeypatch.setattr(certifi, "where", lambda: str(mtls_material["ca_cert"]))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(mtls_material["server_cert"], mtls_material["server_key"])
    config = tls_config(verify=True, ca_file="certifi", server_name="localhost")

    async def run():
        async with exchange(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", secure_context=server_context, tls=config
        ) as (adapter, requests, closed):
            response = await request(adapter)
            assert response.data == b"ok"
            assert requests[0][1] == b"SELECT 1"

    asyncio.run(run())


def test_replay_ignores_only_query_id_and_preserves_error_identity():
    pool = http_detect._ReplayPool()
    options = {"body": b"SELECT 1"}
    url = "http://127.0.0.1:8123/?database=default&query_id=first"
    response = http_detect._Response(200, {}, b"1", "OK")
    pool.responses.append((pool.key("POST", url, options), response))
    actual = pool.request("POST", url.replace("first", "second"), **options)
    assert actual.data == b"1"
    pool.position = 0
    with pytest.raises(AsyncHttpFallback, match="not replay-stable"):
        pool.request("POST", url.replace("database=default", "database=other"), **options)
    error = RuntimeError("original driver failure")
    pool.responses[:] = [(pool.key("POST", url, options), error)]
    pool.position = 0
    with pytest.raises(RuntimeError) as caught:
        pool.request("POST", url, **options)
    assert caught.value is error


@pytest.mark.parametrize("count", [64, 65])
def test_initializer_sequence_budget_preserves_completed_requests(count, monkeypatch):
    adapter = transport()
    sent = []

    async def respond(need):
        sent.append(need.options["body"])
        return http_detect._Response(200, {}, b"1", "OK")

    monkeypatch.setattr(adapter, "_exchange", respond)

    def initialize():
        for index in range(count):
            adapter.pool.request("POST", "http://127.0.0.1:8123/", body=f"SELECT {index}".encode())
        return "initialized"

    async def run():
        if count == 65:
            with pytest.raises(AsyncHttpFallback, match="large.*request sequence"):
                await adapter._drive(initialize)
        else:
            assert await adapter._drive(initialize) == "initialized"
        assert sent == [f"SELECT {index}".encode() for index in range(count)]

    asyncio.run(run())


@pytest.mark.parametrize("rows", [False, True])
def test_query_requires_initialized_driver_and_preserves_result_mode(rows):
    async def run():
        adapter = transport()
        with pytest.raises(AsyncHttpFallback, match="uninitialized"):
            await adapter.query("SELECT 1", rows=rows)
        result = SimpleNamespace(result_rows=[(1,)])
        statements = []

        def query(sql):
            statements.append(sql)
            return result

        adapter.client = SimpleNamespace(query=query)
        actual = await adapter.query("SELECT 1", rows=rows)
        assert actual == [(1,)] if rows else actual is result
        assert statements == ["SELECT 1"]

    asyncio.run(run())


@pytest.mark.parametrize(
    "secure,verify,conflict",
    [(False, False, False), (True, False, False), (True, True, False), (True, True, True), (False, False, True)],
)
def test_adoption_transfers_socket_and_respects_secure_pool_ownership(secure, verify, conflict, monkeypatch):
    from clickhouse_connect.driver import httputil

    source_socket, existing_socket = IdleSocket(), IdleSocket()
    connection = SimpleNamespace(sock=existing_socket if conflict else None)
    returned, options, cleared = [], [], []
    pool = SimpleNamespace(_get_conn=lambda **kwargs: connection, _put_conn=returned.append)
    manager = SimpleNamespace(connection_from_url=lambda url: pool, clear=lambda: cleared.append(True))
    monkeypatch.setattr(httputil, "default_pool_manager", lambda: manager)
    monkeypatch.setattr(httputil, "get_pool_manager", lambda **kwargs: options.append(kwargs) or manager)
    monkeypatch.setattr(httputil, "check_conn_expiration", lambda target: None)
    config = (
        tls_config(
            verify=verify,
            ca_file="ca.pem",
            cert_file="client.pem",
            key_file="client.key",
            server_name="database.internal",
        )
        if secure
        else None
    )
    adapter = transport(tls=config)
    adapter.client = SimpleNamespace(url="https://127.0.0.1:8123" if secure else "http://127.0.0.1:8123")
    adapter.socket = source_socket
    adapter.io.sockets[source_socket] = 1
    httputil.all_managers[adapter.pool] = 1
    try:
        if conflict:
            with pytest.raises(AsyncHttpFallback, match="already owns a live socket"):
                adapter.adopt()
            assert cleared == ([True] if secure else [])
            assert connection.sock is existing_socket and not existing_socket.closed
        else:
            adapter.adopt()
            assert connection.sock is source_socket
            assert connection.timeout == 1
            assert adapter.client.http is manager
            assert adapter.client._owns_pool_manager is secure
            if secure:
                assert connection.is_verified is verify
                assert options[0]["server_hostname"] == "database.internal"
                assert ("assert_hostname" in options[0]) is verify
                assert options[0]["client_cert_key"] == "client.key"
            assert not source_socket.closed
        assert returned == [connection]
    finally:
        adapter.close()
    assert source_socket.closed is conflict
    assert adapter.pool not in httputil.all_managers


def test_close_without_client_or_socket_is_idempotent_and_removes_replay_registration(monkeypatch):
    from clickhouse_connect.driver import httputil

    adapter = transport()
    monkeypatch.setattr(httputil, "default_pool_manager", lambda: pytest.fail("uninitialized client adopted"))
    adapter.adopt()
    httputil.all_managers[adapter.pool] = 1
    adapter.close()
    adapter.close()
    assert adapter.pool not in httputil.all_managers


def test_cancellation_during_body_read_closes_peer_and_replay_state():
    async def run():
        requested, closed = asyncio.Event(), asyncio.Event()

        async def peer(reader, writer):
            try:
                headers = await reader.readuntil(b"\r\n\r\n")
                length = next(
                    int(line.split(b":", 1)[1])
                    for line in headers.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                )
                await reader.readexactly(length)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx")
                await writer.drain()
                requested.set()
                await reader.read()
            except ConnectionError:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass
                finally:
                    closed.set()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        async with server:
            backend = RetainedSocketIO()
            adapter = transport(backend, port=server.sockets[0].getsockname()[1])

            async def drive():
                try:
                    await request(adapter)
                finally:
                    adapter.close()
                    backend.close()

            task = asyncio.create_task(drive())
            await requested.wait()
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(closed.wait(), 2)
            assert not backend.sockets

    asyncio.run(run())


@pytest.mark.parametrize("headers", [{"X-Value": "unsafe\r\nInjected: true"}, {"X-Bad\x00Name": "value"}])
def test_invalid_request_headers_never_reach_send_and_cleanup_closes_candidate(headers):
    class ValidationIO(ForbiddenIO):
        async def open(self, *args, **kwargs):
            sock = IdleSocket()
            self.sockets[sock] = 1
            return sock

        async def sendall(self, *args, **kwargs):
            pytest.fail("invalid headers reached the wire")

    async def run():
        backend = ValidationIO()
        adapter = transport(backend)
        try:
            with pytest.raises(AsyncHttpFallback, match="invalid.*header"):
                await request(adapter, headers=headers)
            sock = adapter.socket
        finally:
            adapter.close()
        assert sock.closed and not backend.sockets

    asyncio.run(run())


def test_unsolicited_response_bytes_cannot_be_adopted_as_a_clean_http_session():
    class BufferedIO(ForbiddenIO):
        def __init__(self):
            super().__init__()
            self.incoming = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokUNSOLICITED"

        async def open(self, *args, **kwargs):
            sock = IdleSocket()
            self.sockets[sock] = 1
            return sock

        async def sendall(self, *args, **kwargs):
            pass

        async def recv(self, sock, size):
            data, self.incoming = self.incoming[:size], self.incoming[size:]
            return data

    async def run():
        backend = BufferedIO()
        adapter = transport(backend)
        try:
            with pytest.raises(AsyncHttpFallback, match="unsolicited"):
                await request(adapter)
        finally:
            adapter.close()
        assert not backend.sockets

    asyncio.run(run())
