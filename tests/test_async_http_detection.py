"""Real loopback HTTP exchanges, not mocked asyncio behavior."""

from __future__ import annotations

import asyncio
import gzip

import pytest


def test_async_http_keepalive_chunked_gzip_and_size_limit():
    from redposture_core.clients.async_http_detect import AsyncDetectionHttp

    async def scenario():
        connections = []
        requests = []

        async def serve(reader, writer):
            connections.append(1)
            try:
                while True:
                    try:
                        request = await reader.readuntil(b"\r\n\r\n")
                    except asyncio.IncompleteReadError:
                        return
                    requests.append(request.split(b" ")[1])
                    if requests[-1] == b"/zip":
                        body = gzip.compress(b'{"version":"1.0"}')
                        writer.write(
                            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
                            + str(len(body)).encode()
                            + b"\r\n\r\n"
                            + body
                        )
                    else:
                        writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            async with AsyncDetectionHttp(timeout=0.5, retries=0, max_bytes=256) as client:
                first = await client.get(f"http://127.0.0.1:{port}/chunk")
                second = await client.get(f"http://127.0.0.1:{port}/zip")
                assert first.body == b"hello" and first.status == 200
                assert second.json() == {"version": "1.0"} and second.error is None
                assert len(connections) == 1 and requests == [b"/chunk", b"/zip"]
            async with AsyncDetectionHttp(timeout=0.5, retries=0, max_bytes=3) as client:
                limited = await client.get(f"http://127.0.0.1:{port}/chunk")
                assert limited.truncated and len(limited.body) <= 3

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "payload",
    [
        b"HTTP/1.1 302 Found\r\nLocation: /prefix\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nfail",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: unusual\r\n\r\nfail",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        b"HTTP/1.1 200 OK\r\n" + b"X-Padding: " + b"a" * 65000 + b"\r\nX-Extra: " + b"b" * 2000 + b"\r\n\r\n",
    ],
    ids=["redirect", "duplicate-length", "transfer-encoding", "interim", "large-headers"],
)
def test_unsupported_response_is_explicit_fallback_not_service_absence(payload):
    from redposture_core.clients.async_http_detect import AsyncDetectionHttp, AsyncHttpFallback

    async def scenario():
        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(payload)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server, AsyncDetectionHttp(timeout=0.5, retries=0, max_bytes=100) as client:
            with pytest.raises(AsyncHttpFallback):
                await client.get(f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/")

    asyncio.run(scenario())


def test_incomplete_response_and_refused_are_errors_not_empty_success():
    from redposture_core.clients.async_http_detect import AsyncDetectionHttp

    async def scenario():
        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server, AsyncDetectionHttp(timeout=0.5, retries=0, max_bytes=100) as client:
            result = await client.get(f"http://127.0.0.1:{port}/")
            assert result.error and result.status == 0
        async with AsyncDetectionHttp(timeout=0.5, retries=0, max_bytes=100) as client:
            result = await client.get(f"http://127.0.0.1:{port}/")
            assert result.error and result.status == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "identity,correct_ca,allowed", [(True, True, True), (False, True, False), (True, False, False)]
)
def test_native_tls_preserves_ca_and_client_certificate_requirements(mtls_material, identity, correct_ca, allowed):
    from redposture_core.clients.async_http_detect import AsyncDetectionHttp
    from redposture_core.clients.tls_cache import shared_client_ssl_context
    from tests.test_real_mtls_integration import _serve_mtls_http

    context = shared_client_ssl_context(
        insecure=False,
        ca_file=str(mtls_material["ca_cert" if correct_ca else "wrong_ca_cert"]),
        cert_file=str(mtls_material["client_cert"]) if identity else None,
        key_file=str(mtls_material["client_key"]) if identity else None,
    )
    # This corpus isolates CA/client authentication. Hostname routing stays on
    # the established transport; IP certificates are covered by its TLS suite.
    import ssl

    numeric_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    numeric_context.check_hostname = False
    numeric_context.load_verify_locations(str(mtls_material["ca_cert" if correct_ca else "wrong_ca_cert"]))
    if identity:
        numeric_context.load_cert_chain(str(mtls_material["client_cert"]), str(mtls_material["client_key"]))
    assert context.verify_mode == numeric_context.verify_mode

    async def request(port):
        async with AsyncDetectionHttp(timeout=0.5, retries=0, max_bytes=100, ssl_context=numeric_context) as client:
            return await client.get(f"https://127.0.0.1:{port}/")

    with _serve_mtls_http(mtls_material) as port:
        response = asyncio.run(request(port))
    assert (response.status == 200) is allowed
    assert (response.error is None) is allowed


def test_timeout_retries_and_cancellation_close_the_socket():
    from redposture_core.clients.async_http_detect import AsyncDetectionHttp

    async def scenario():
        accepted = []
        closed = []

        async def serve(reader, writer):
            accepted.append(1)
            try:
                await reader.readuntil(b"\r\n\r\n")
                await reader.read()
                closed.append(1)
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server, AsyncDetectionHttp(timeout=0.1, retries=1, max_bytes=100) as client:
            url = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/"
            response = await client.get(url)
            assert response.status == 0 and response.error
            assert len(accepted) == 2 and client.stats()["retries"] == 1
            pending = asyncio.create_task(client.get(url))
            while len(accepted) < 3:
                await asyncio.sleep(0.001)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        for _ in range(100):
            if len(closed) == 3:
                break
            await asyncio.sleep(0.002)
        assert len(closed) == 3

    asyncio.run(scenario())


def test_premature_eof_retries_the_complete_request():
    from redposture_core.clients.async_http_detect import AsyncDetectionHttp

    async def scenario():
        calls = []

        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            calls.append(1)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n" + (b"ok" if len(calls) == 2 else b"o"))
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server, AsyncDetectionHttp(timeout=0.1, retries=1, max_bytes=100) as client:
            result = await client.get(f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/")
            assert result.status == 200 and result.body == b"ok"
            assert len(calls) == 2 and client.stats()["retries"] == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("chunked", [False, True])
def test_streaming_uses_inactivity_timeout_not_whole_response_deadline(chunked):
    from redposture_core.clients.async_http_detect import AsyncDetectionHttp

    async def scenario():
        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            try:
                for piece in [b"HTTP/1.1 200 OK\r\n", b"X-One: a\r\n", b"X-Two: b\r\n", b"X-Three: c\r\n"]:
                    writer.write(piece)
                    await writer.drain()
                    await asyncio.sleep(0.03)
                writer.write(b"Transfer-Encoding: chunked\r\n\r\n5\r\n" if chunked else b"Content-Length: 5\r\n\r\n")
                for byte in b"hello":
                    writer.write(bytes([byte]))
                    await writer.drain()
                    await asyncio.sleep(0.03)
                if chunked:
                    writer.write(b"\r\n0\r\n\r\n")
                    await writer.drain()
            finally:
                writer.close()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server, AsyncDetectionHttp(timeout=0.1, retries=0, max_bytes=100) as client:
            result = await client.get(f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/")
            assert result.status == 200 and result.body == b"hello" and not result.error

    asyncio.run(scenario())


def test_hostname_requests_fall_back_without_starting_executor_dns(monkeypatch):
    from redposture_core.clients.async_http_detect import AsyncDetectionHttp, AsyncHttpFallback

    async def scenario():
        def forbidden(*args, **kwargs):
            pytest.fail("native detection must not start an uncancellable executor DNS lookup")

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", forbidden)
        async with AsyncDetectionHttp(timeout=0.1, retries=0, max_bytes=100) as client:
            with pytest.raises(AsyncHttpFallback, match="hostname"):
                await client.get("http://qa.example.test/")
            with pytest.raises(AsyncHttpFallback, match="scoped"):
                await client.get("http://[fe80::1%en0]/")

    asyncio.run(scenario())
