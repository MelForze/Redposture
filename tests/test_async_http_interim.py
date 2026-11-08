from __future__ import annotations

import asyncio

import pytest

from redposture_core.clients.async_http_detect import AsyncDetectionHttp, AsyncHttpFallback


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("continues", [1, 3])
def test_100_continue_is_consumed_without_replaying_request(retained, continues):
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp

    async def run():
        requests = []

        async def serve(reader, writer):
            try:
                requests.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(
                    b"HTTP/1.1 100 Continue\r\nX-Fixture: interim\r\n\r\n" * continues
                    + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        options = {"timeout": 1, "retries": 0, "max_bytes": 1024}
        client = (
            RetainedDetectionHttp(budget=HttpHandoffBudget(1), **options) if retained else AsyncDetectionHttp(**options)
        )
        async with server, client:
            response = await client.get(f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/")
        assert response.status == 200 and response.body == b"ok" and len(requests) == 1
        assert "X-Fixture" not in response.headers

    asyncio.run(run())


@pytest.mark.parametrize("status", [101, 102, 103])
def test_other_interim_statuses_keep_original_fallback(status):
    async def run():
        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(f"HTTP/1.1 {status} Interim\r\n\r\n".encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server, AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as client:
            with pytest.raises(AsyncHttpFallback):
                await client.get(f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/")

    asyncio.run(run())
