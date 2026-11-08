"""Hostname detection must keep the original HTTP identity and cancellation."""

from __future__ import annotations

import asyncio
import socket
from contextlib import closing

import pytest

from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
from redposture_core.clients.http_session import HttpSessionPool
from tests.test_http_redirect_policy import _serve, tls_material  # noqa: F401


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("redirect", [False, True])
def test_dns_keeps_hostname_host_header_and_sync_result(retained, redirect):
    with _serve(lambda *a: (200, {}, b"hostname-product")) as (base, calls):
        destination = base.replace("127.0.0.1", "localhost") + "/prefix/final"
        with _serve(lambda *a: (302, {"Location": destination}, b"")) as (source, source_calls):
            url = source + "/start" if redirect else destination

            async def run():
                options = {"timeout": 1, "retries": 0, "max_bytes": 1024}
                client = (
                    RetainedDetectionHttp(budget=HttpHandoffBudget(2), **options)
                    if retained
                    else AsyncDetectionHttp(**options)
                )
                async with client:
                    return await client.get(url)

            response = asyncio.run(run())
            before = calls[:]
            calls.clear()
            with closing(HttpSessionPool(timeout=1, retries=0)) as pool:
                reference = pool.request("GET", url)
            assert response.status == reference.status == 200
            assert response.body == reference.body == b"hostname-product"
            assert response.final_url == reference.final_url == destination
            assert before == calls
            assert before[0][2]["host"].startswith("localhost:")
            assert len(source_calls) == (2 if redirect else 0)


@pytest.mark.parametrize("retained", [False, True])
def test_every_resolved_address_is_tried_in_original_order(monkeypatch, retained):
    original = socket.getaddrinfo
    with _serve(lambda *a: (200, {}, b"address-list")) as (base, calls):
        port = int(base.rsplit(":", 1)[1])

        def resolve(host, port, *a, **kw):
            if host == "native-qa.invalid":
                return [
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
                ]
            return original(host, port, *a, **kw)

        monkeypatch.setattr(socket, "getaddrinfo", resolve)
        order = []
        client_type = RetainedDetectionHttp if retained else AsyncDetectionHttp
        original_open = client_type._open_address

        async def tracked_open(self, address, *args, **kwargs):
            order.append(address)
            return await original_open(self, address, *args, **kwargs)

        monkeypatch.setattr(client_type, "_open_address", tracked_open)

        async def run():
            options = {"timeout": 1, "retries": 0, "max_bytes": 1024}
            client = (
                RetainedDetectionHttp(budget=HttpHandoffBudget(2), **options)
                if retained
                else AsyncDetectionHttp(**options)
            )
            async with client:
                response = await client.get(f"http://native-qa.invalid:{port}/")
            assert response.status == 200 and response.body == b"address-list"
            assert client._connection is None

        asyncio.run(run())
        assert order == ["::1", "127.0.0.1"]
        assert len(calls) == 1 and calls[0][2]["host"] == f"native-qa.invalid:{port}"


@pytest.mark.parametrize("retained", [False, True])
def test_hostname_tls_keeps_original_server_name(tls_material, monkeypatch, retained):  # noqa: F811
    import ssl

    server_context, cert = tls_material
    with _serve(lambda *a: (200, {}, b"tls-host"), server_context) as (base, calls):
        seen = []
        server_context.set_servername_callback(lambda sock, name, ctx: seen.append(name))

        async def run():
            options = dict(timeout=2, retries=0, max_bytes=1024, ssl_context=ssl.create_default_context(cafile=cert))
            client = (
                RetainedDetectionHttp(budget=HttpHandoffBudget(2), **options)
                if retained
                else AsyncDetectionHttp(**options)
            )
            async with client:
                return await client.get(base.replace("127.0.0.1", "localhost") + "/")

        response = asyncio.run(run())
        assert response.status == 200 and response.body == b"tls-host"
        assert seen == ["localhost"] and len(calls) == 1
