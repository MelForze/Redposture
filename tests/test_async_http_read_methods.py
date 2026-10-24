"""Native detection supports existing read-only POST probes, not write actions."""

from __future__ import annotations

import asyncio

import pytest

from redposture_core.clients.async_http_detect import AsyncDetectionHttp


def test_post_body_explicit_host_and_head_keepalive_are_framed_correctly():
    received = []

    async def run():
        async def serve(reader, writer):
            try:
                for index in range(3):
                    headers = await reader.readuntil(b"\r\n\r\n")
                    length = next(
                        (
                            int(x.split(b":", 1)[1])
                            for x in headers.split(b"\r\n")
                            if x.lower().startswith(b"content-length:")
                        ),
                        0,
                    )
                    body = await reader.readexactly(length)
                    received.append((headers, body))
                    payload = b'{"enabled":false}'
                    writer.write(
                        b"HTTP/1.1 200 Product Status\r\nContent-Length: "
                        + str(len(payload)).encode()
                        + b"\r\n\r\n"
                        + (b"" if index == 1 else payload)
                    )
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            url = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/v3/auth/status"
            async with AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as http:
                first = await http.request(
                    "POST", url, headers={"Host": "qa:2379", "Content-Type": "application/json"}, body=b"{}"
                )
                head = await http.request("HEAD", url)
                last = await http.get(url)
                assert http.last_reason == "Product Status"
                assert first.json() == last.json() == {"enabled": False}
                assert head.status == 200 and head.body == b""
                assert http.stats()["connections"] == 1

    asyncio.run(run())
    assert received[0][0].startswith(b"POST ")
    assert received[0][0].lower().count(b"host:") == 1
    assert b"Host: qa:2379\r\n" in received[0][0]
    assert received[0][1] == b"{}"


def test_unmarked_post_cannot_run_in_native_detection():
    from redposture_core.clients.async_http_detect import AsyncHttpFallback
    from redposture_core.clients.http_session import HttpSessionPool
    from redposture_core.detection_io import HttpRead, read_http

    pool = HttpSessionPool(timeout=1)

    async def run():
        async with AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as http:
            with pytest.raises(AsyncHttpFallback):
                await read_http(HttpRead(pool, "POST", "http://127.0.0.1:1/write", {"body": b"{}"}), http)

    try:
        asyncio.run(run())
    finally:
        pool.close()
