"""Native redirect traversal must match the existing sync policy."""

from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import replace

import pytest

from redposture_core.clients.async_http_detect import AsyncDetectionHttp, AsyncHttpFallback
from redposture_core.clients.http_session import HttpSessionPool
from tests.test_http_redirect_policy import _serve, tls_material  # noqa: F401


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("method", ["GET", "HEAD", "POST"])
def test_native_redirect_has_sync_method_body_headers_and_history(status, method):
    auth = {
        "Authorization": "Bearer own-qa",
        "Cookie": "session=own-qa",
        "Host": "operator-host",
        "Content-Type": "application/json",
    }
    with _serve(lambda *a: (200, {}, b"complete")) as (destination, received):
        with _serve(lambda *a: (status, {"Location": destination + "/prefix/final?x=a%2Fb#frag"}, b"")) as (
            source,
            sent,
        ):

            async def run():
                async with AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as client:
                    return await client.request(
                        method,
                        source + "/start",
                        headers=auth,
                        body=b"{}" if method == "POST" else None,
                        replay_safe=True,
                    )

            native = asyncio.run(run())
            native_calls = received[:]
            received.clear()
            with closing(HttpSessionPool(timeout=1, retries=0)) as pool:
                sync = pool.request(method, source + "/start", headers=auth, body=b"{}" if method == "POST" else None)
            assert replace(native, headers={k: v for k, v in native.headers.items() if k.lower() != "date"}) == replace(
                sync, headers={k: v for k, v in sync.headers.items() if k.lower() != "date"}
            )
            assert received == native_calls
            assert len(sent) == 2 and len(received) == 1


def test_native_cross_origin_restriction_blocks_before_destination():
    with _serve(lambda *a: (200, {}, b"other")) as (destination, received):
        with _serve(lambda *a: (302, {"Location": destination + "/final"}, b"")) as (source, sent):

            async def run():
                async with AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as client:
                    return await client.get(source + "/start", allow_cross_origin_redirects=False)

            response = asyncio.run(run())
            assert response.status == 302 and "cross-origin redirect blocked" in response.error
            assert received == [] and len(sent) == 1


@pytest.mark.parametrize("mode", ["loop", "limit", "missing", "unsupported", "not-a-redirect"])
def test_native_redirect_errors_and_unfollowed_responses_match_sync(mode):
    def reply(method, path, headers, body):
        if mode == "missing":
            return 302, {}, b"no location"
        if mode == "unsupported":
            return 302, {"Location": "file:///tmp/not-http"}, b""
        if mode == "not-a-redirect":
            return 304, {}, b""
        return 302, {"Location": "/start" if mode == "loop" else "/" + str(int(path.strip("/") or "0") + 1)}, b""

    with _serve(reply) as (base, calls):
        url = base + ("/0" if mode == "limit" else "/start")

        async def run():
            async with AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as client:
                return await client.get(url)

        native = asyncio.run(run())
        count = len(calls)
        calls.clear()
        with closing(HttpSessionPool(timeout=1, retries=0)) as pool:
            sync = pool.request("GET", url)
        assert replace(native, headers={k: v for k, v in native.headers.items() if k.lower() != "date"}) == replace(
            sync, headers={k: v for k, v in sync.headers.items() if k.lower() != "date"}
        )
        assert len(calls) == count


def test_unmarked_post_is_sent_once_and_never_redirected_or_retried():
    with _serve(lambda *a: (200, {}, b"not-reached")) as (destination, received):
        with _serve(lambda *a: (307, {"Location": destination + "/write"}, b"")) as (source, sent):

            async def run():
                async with AsyncDetectionHttp(timeout=1, retries=2, max_bytes=1024) as client:
                    return await client.request("POST", source + "/write", body=b"action")

            response = asyncio.run(run())
            assert response.status == 307 and len(sent) == 1 and received == []


def test_dns_redirect_handles_refusal_and_releases_native_connection():
    with _serve(lambda *a: (302, {"Location": "http://localhost:1/final"}, b"")) as (source, sent):

        async def run():
            async with AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as client:
                response = await client.get(source + "/start")
                assert response.status == 0 and response.error
                assert client._connection is None

        asyncio.run(run())
        assert len(sent) == 1


@pytest.mark.parametrize("preserve", [False, True])
def test_operator_authorization_obeys_same_cross_origin_policy_as_pool(preserve):
    from redposture_core.http_headers import custom_http_headers

    with _serve(lambda *a: (200, {}, b"done")) as (destination, received):
        with _serve(lambda *a: (302, {"Location": destination + "/final"}, b"")) as (source, sent):

            async def run():
                async with AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as client:
                    return await client.get(source + "/start", preserve_authorization_on_cross_origin=preserve)

            with custom_http_headers([("Authorization", "Bearer operator"), ("Cookie", "session=qa")]):
                native = asyncio.run(run())
                before = received[:]
                received.clear()
                with closing(HttpSessionPool(timeout=1, retries=0)) as pool:
                    sync = pool.request("GET", source + "/start", preserve_authorization_on_cross_origin=preserve)
            assert native.body == sync.body == b"done"
            assert received == before
            assert received[0][2].get("authorization") == ("Bearer operator" if preserve else None)
            assert received[0][2]["cookie"] == "session=qa"


def test_tls_redirect_uses_original_verification_context(tls_material):  # noqa: F811 - imported pytest fixture
    import ssl

    server_context, cert = tls_material
    with _serve(lambda *a: (200, {}, b"tls-final"), server_context) as (destination, received):
        with _serve(lambda *a: (302, {"Location": destination + "/api/health"}, b"")) as (source, sent):

            async def run():
                async with AsyncDetectionHttp(
                    timeout=2, retries=0, max_bytes=1024, ssl_context=ssl.create_default_context(cafile=cert)
                ) as client:
                    return await client.get(source + "/api/health")

            native = asyncio.run(run())
            assert (
                native.status == 200 and native.body == b"tls-final" and native.final_url == destination + "/api/health"
            )
            assert len(sent) == len(received) == 1


def test_explicit_deadline_spans_redirect_hops_and_cancellation_closes_final_socket():
    import time

    async def run():
        closed = asyncio.Event()
        at_final = asyncio.Event()

        async def serve(reader, writer):
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                if b"/start " in request:
                    writer.write(
                        b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    await writer.drain()
                else:
                    at_final.set()
                    await reader.read()
                    closed.set()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server, AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as client:
            url = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/start"
            start = time.monotonic()
            response = await client.get(url, deadline=start + 0.2)
            assert response.status == 0 and response.error == "timed out"
            assert time.monotonic() - start < 1
            await asyncio.wait_for(closed.wait(), 1)
            assert client._connection is None
            at_final.clear()
            closed.clear()
            task = asyncio.create_task(client.get(url))
            await asyncio.wait_for(at_final.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(closed.wait(), 1)
            assert client._connection is None

    asyncio.run(run())


def test_large_redirect_does_not_hide_truncation_and_request_final_url():
    with _serve(lambda *a: (200, {}, b"done")) as (destination, received):
        with _serve(lambda *a: (302, {"Location": destination + "/final"}, b"x" * 1000)) as (source, sent):

            async def run():
                async with AsyncDetectionHttp(timeout=1, retries=0, max_bytes=32) as client:
                    with pytest.raises(AsyncHttpFallback, match="redirect body"):
                        await client.get(source + "/start")

            asyncio.run(run())
            assert len(sent) == 1 and received == []


@pytest.mark.parametrize("allowed", [False, True])
@pytest.mark.parametrize("preserve", [False, True])
def test_detection_continuation_passes_origin_authorization_and_deadline(allowed, preserve):
    import time

    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.detection_io import HttpRead, read_http

    seen = []

    class Native:
        timeout = 2
        retries = 0
        max_bytes = 1024
        ssl_context = None

        async def close(self):
            pass

        async def get(self, url, **options):
            seen.append(options)
            return HttpResponse(200, b"{}", {})

    with closing(HttpSessionPool(timeout=2, retries=0)) as pool:
        options = {
            "allow_cross_origin_redirects": allowed,
            "preserve_authorization_on_cross_origin": preserve,
            "timeout": 1.0,
        }
        start = time.monotonic()
        response = asyncio.run(read_http(HttpRead(pool, "GET", "http://127.0.0.1:1/read", options), Native()))
    assert response.status == 200
    assert seen[0]["allow_cross_origin_redirects"] is allowed
    assert seen[0]["preserve_authorization_on_cross_origin"] is preserve
    assert start + 0.9 < seen[0]["deadline"] < time.monotonic() + 1.1


def test_repeated_set_cookie_fields_are_preserved_after_redirect_keepalive():
    from redposture_core.html_fingerprint import set_cookie_names

    async def run():
        async def serve(reader, writer):
            try:
                for index in range(2):
                    await reader.readuntil(b"\r\n\r\n")
                    if index == 0:
                        writer.write(b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n")
                    else:
                        writer.write(
                            b"HTTP/1.1 200 OK\r\nSet-Cookie: first=qa; Path=/\r\nset-cookie: grafana_session=qa; Path=/\r\nContent-Length: 2\r\n\r\nok"
                        )
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server, AsyncDetectionHttp(timeout=1, retries=0, max_bytes=1024) as client:
            response = await client.get(f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/start")
            assert response.status == 200 and response.body == b"ok"
            cookie = next(v for k, v in response.headers.items() if k.lower() == "set-cookie")
            assert set_cookie_names(cookie) == {"first", "grafana_session"}
            assert client.stats()["connections"] == 1 and client.stats()["requests"] == 2

    asyncio.run(run())


@pytest.mark.parametrize("malformed", [False, True])
def test_unmarked_post_never_requests_sync_replay_after_response_limit_or_framing(malformed):
    headers = {"Transfer-Encoding": "unsupported"} if malformed else {}
    with _serve(lambda *args: (307, {"Location": "/second", **headers}, b"" if malformed else b"x" * 1024)) as (
        source,
        sent,
    ):

        async def run():
            async with AsyncDetectionHttp(timeout=1, retries=2, max_bytes=16) as client:
                return await client.request("POST", source + "/write", body=b"action")

        result = asyncio.run(run())
        assert len(sent) == 1
        if malformed:
            assert result.status == 0 and "not replayed" in result.error
        else:
            assert result.status == 307 and result.truncated
