"""A framed anonymous detect connection can become the target's sync socket."""

from __future__ import annotations

import asyncio
import gzip
import importlib
import json
import ssl
import threading
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients.http_session import HttpSessionPool


@contextmanager
def peer(*, secure=False, material=None, framing="length", responses=None, drop_after=0, responder=None):
    connections, requests = [], []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        disable_nagle_algorithm = True

        def setup(self):
            super().setup()
            connections.append(self.connection)

        def do_GET(self):
            requests.append((self.path, self.headers.get("Authorization"), self.headers.get("Cookie")))
            if self.path == "/after" and sum(path == "/after" for path, _, _ in requests) <= drop_after:
                self.close_connection = True
                return
            status, body = (responses or {}).get(self.path, (200, b'{"ok":true}'))
            extra = {}
            if responder is not None:
                response = responder(
                    f"{'https' if secure else 'http'}://127.0.0.1:{self.server.server_port}" + self.path
                )
                status, body, extra = response.status, response.body, response.headers
            self.send_response(status)
            for key, value in extra.items():
                self.send_header(key, value)
            if framing == "gzip":
                body = gzip.compress(body)
                self.send_header("Content-Encoding", "gzip")
            if framing == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
            else:
                self.send_header("Content-Length", str(len(body)))
                if framing == "close":
                    self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            self.wfile.flush()

        def do_HEAD(self):
            self.do_GET()

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.do_GET()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    if secure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(material["server_cert"], material["server_key"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"{'https' if secure else 'http'}://127.0.0.1:{server.server_port}", connections, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("secure", [False, True])
@pytest.mark.parametrize("framing", ["length", "chunked", "gzip"])
def test_detect_auth_share_one_real_connection(secure, framing, mtls_material, monkeypatch):
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http

    budget = HttpHandoffBudget(1)
    with peer(secure=secure, material=mtls_material, framing=framing) as (url, connections, requests):
        with closing(HttpSessionPool(timeout=1, insecure=True)) as pool:

            async def detect():
                async with RetainedDetectionHttp(timeout=1, retries=0, max_bytes=1024, budget=budget) as http:
                    monkeypatch.setattr(
                        asyncio.get_running_loop(), "run_in_executor", lambda *a, **k: pytest.fail("blocking detect")
                    )
                    response = await read_http(HttpRead(pool, "GET", url + "/detect", {}), http)
                    assert response.json() == {"ok": True}
                    assert http.handoff() is True
                    assert budget.active == 1
                    assert http.stats()["connections"] == 1

            asyncio.run(detect())
            response = pool.request("GET", url + "/auth", headers={"Authorization": "Basic dXNlcjpwYXNz"})
            assert response.json() == {"ok": True}
            assert budget.active == 0
            assert len(connections) == 1
            assert requests == [("/detect", None, None), ("/auth", "Basic dXNlcjpwYXNz", None)]
            assert pool.stats()["connections"] == 0 and pool.stats()["reused"] == 1


def test_handoff_budget_and_pool_close_bound_unclaimed_sockets():
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http

    budget = HttpHandoffBudget(1)
    with peer() as (url, connections, _):
        first, second = HttpSessionPool(timeout=1), HttpSessionPool(timeout=1)

        async def detect(pool):
            async with RetainedDetectionHttp(timeout=1, retries=0, max_bytes=1024, budget=budget) as http:
                await read_http(HttpRead(pool, "GET", url, {}), http)
                return http.handoff()

        try:
            assert asyncio.run(detect(first)) is True
            assert asyncio.run(detect(second)) is False
            assert budget.active == 1
            first.close()
            assert budget.active == 0
            assert asyncio.run(detect(second)) is True
            assert len(connections) == 3
        finally:
            first.close()
            second.close()
        assert budget.active == 0


@pytest.mark.parametrize("headers", [{"Authorization": "Basic x"}, {"Cookie": "sid=x"}])
def test_authenticated_detect_is_not_transferred_between_identities(headers):
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http

    with peer() as (url, _, _), closing(HttpSessionPool(timeout=1)) as pool:

        async def detect():
            async with RetainedDetectionHttp(timeout=1, retries=0, max_bytes=1024, budget=HttpHandoffBudget(1)) as http:
                await read_http(HttpRead(pool, "GET", url, {"headers": headers}), http)
                assert http.handoff() is False

        asyncio.run(detect())


def test_connection_close_response_is_not_adopted():
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http

    with peer(framing="close") as (url, _, _), closing(HttpSessionPool(timeout=1)) as pool:

        async def detect():
            async with RetainedDetectionHttp(timeout=1, retries=0, max_bytes=1024, budget=HttpHandoffBudget(1)) as http:
                assert (await read_http(HttpRead(pool, "GET", url, {}), http)).status == 200
                assert http.handoff() is False

        asyncio.run(detect())


@pytest.mark.parametrize("module", ["grafana", "qdrant", "portainer"])
def test_runner_transfers_actual_detect_socket_to_correct_target_pool(module):
    from redposture_core.stage_runtime import AuditCommandRunner

    responses = {
        "/api/health": (200, b'{"database":"ok","version":"11.2.0","commit":"abcdef"}'),
        "/api/datasources": (401, b"{}"),
        "/api/user": (401, b"{}"),
        "/api/system/status": (200, b'{"Version":"2.45.2","InstanceID":"qa"}'),
        "/api/endpoints": (401, b"{}"),
        "/": (200, b"<title>Portainer</title>" if module == "portainer" else b'{"title":"qdrant","version":"1.11.0"}'),
        "/collections": (200, json.dumps({"result": {"collections": []}, "status": "ok", "time": 0.1}).encode()),
    }
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    with peer(responses=responses) as (url, connections, _):
        port = int(url.rsplit(":", 1)[1])
        args = SimpleNamespace(timeout=1.0, retries=0, port=port)
        spec = getattr(stage, f"build_{module}_spec")(args)
        runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
        outcome = asyncio.run(runner._run_async_detect_with_state("127.0.0.1", port, None, None))
        assert outcome is not None and runner._is_detected(outcome.record)
        try:
            state = outcome.lifecycle_state
            pool = state._panel_http if module == "portainer" else state.http
            assert pool.request("GET", url + "/after").json() == {"ok": True}
            assert len(connections) == 1
            assert pool.stats()["reused"] >= 1
        finally:
            runner._close_all_lifecycle_states()
        assert runner._http_handoff_budget.active == 0


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("drops", [1, 2])
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_first_handoff_get_disconnect_reconnects_at_most_once(stream, drops, method):
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http

    with peer(drop_after=drops) as (url, connections, requests), closing(HttpSessionPool(timeout=1)) as pool:

        async def detect():
            async with RetainedDetectionHttp(timeout=1, retries=0, max_bytes=1024, budget=HttpHandoffBudget(1)) as http:
                await read_http(HttpRead(pool, "GET", url + "/detect", {}), http)
                assert http.handoff()

        asyncio.run(detect())
        chunks = []
        response = (
            pool.request_stream(method, url + "/after", on_chunk=chunks.append)
            if stream
            else pool.request(method, url + "/after", retries=0)
        )
        assert len(connections) == 2
        assert [path for path, _, _ in requests] == ["/detect", "/after", "/after"]
        assert pool.stats()["retries"] == 1
        if drops == 1:
            assert response.status == 200 and not response.error
            assert (b"".join(chunks) if stream else response.body) == (b'{"ok":true}' if method == "GET" else b"")
        else:
            assert response.error


def test_first_post_does_not_reuse_detect_socket_and_is_never_replayed():
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http

    with peer(drop_after=1) as (url, connections, requests), closing(HttpSessionPool(timeout=1)) as pool:

        async def detect():
            async with RetainedDetectionHttp(timeout=1, retries=0, max_bytes=1024, budget=HttpHandoffBudget(1)) as http:
                await read_http(HttpRead(pool, "GET", url + "/detect", {}), http)
                assert http.handoff()

        asyncio.run(detect())
        response = pool.request_once("POST", url + "/after", body=b"one-shot")
        assert response.error
        assert len(connections) == 2
        assert [path for path, _, _ in requests] == ["/detect", "/after"]
        assert pool.stats()["reused"] == pool.stats()["retries"] == 0


@pytest.mark.parametrize("module", ["elastic", "kubeapi"])
def test_cancel_between_custom_session_claim_and_assignment_keeps_socket_owned(module, monkeypatch):
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http
    from redposture_core.modules.elastic.http_session import ElasticHttpSession
    from redposture_core.modules.kubeapi.http_session import KubeApiHttpSession

    with peer() as (url, _, requests):
        port = int(url.rsplit(":", 1)[1])
        client: Any = (
            ElasticHttpSession("127.0.0.1", port, timeout=1)
            if module == "elastic"
            else KubeApiHttpSession("127.0.0.1", port, timeout=1, use_https=False, insecure=False, ca_file=None)
        )
        policy = client.detection_pool()
        budget = HttpHandoffBudget(1)

        async def detect():
            async with RetainedDetectionHttp(timeout=1, retries=0, max_bytes=1024, budget=budget) as http:
                await read_http(HttpRead(policy, "GET", url + "/detect", {}), http)
                assert http.handoff()

        asyncio.run(detect())
        take = policy.take_handoff
        borrowed = []

        def cancel_after_claim(*args, **kwargs):
            connection = take(*args, **kwargs)
            borrowed.append(connection)
            client.close()
            return connection

        monkeypatch.setattr(policy, "take_handoff", cancel_after_claim)
        try:
            response = (
                client.request("http", "GET", "/after")
                if module == "elastic"
                else client.request("GET", url + "/after")
            )
            assert response.error
            assert [path for path, _, _ in requests] == ["/detect"]
            assert borrowed[0].sock is None
        finally:
            client.close()
            for connection in borrowed:
                if connection is not None:
                    connection.close()
        assert budget.active == 0


def test_many_targets_share_bounded_budget_and_release_every_idle_socket():
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http

    budget = HttpHandoffBudget(4)
    with peer() as (url, _, _):
        pools = [HttpSessionPool(timeout=2) for _ in range(24)]

        async def detect(pool):
            async with RetainedDetectionHttp(timeout=2, retries=0, max_bytes=1024, budget=budget) as http:
                await read_http(HttpRead(pool, "GET", url, {}), http)
                return http.handoff()

        async def campaign():
            # Bound the peer as well; no artificial server backlog failures.
            semaphore = asyncio.Semaphore(4)

            async def one(pool):
                async with semaphore:
                    return await detect(pool)

            return await asyncio.gather(*(one(pool) for pool in pools))

        try:
            assert sum(asyncio.run(campaign())) == 4
            assert budget.active == 4
            assert sum(len(pool._retained_claims) for pool in pools) == 4
            for pool in pools:
                assert pool.request("GET", url + "/after").status == 200
            assert budget.active == 0
        finally:
            connections = [conn for pool in pools for conn in pool._connections]
            for pool in pools:
                pool.close()
        assert all(conn.sock is None for conn in connections)
        assert budget.active == 0


@pytest.mark.parametrize("taint", ["set-cookie", "api-key", "vault-token", "custom-cookie"])
def test_session_bearing_detect_is_never_lent_to_another_stage(taint):
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http
    from redposture_core.http_headers import custom_http_headers

    response_headers = {"Set-Cookie": "session=only-detect"} if taint == "set-cookie" else {}
    headers = (
        {"X-API-Key": "only-detect"}
        if taint == "api-key"
        else {"X-Vault-Token": "only-detect"}
        if taint == "vault-token"
        else {}
    )
    with peer(responder=lambda _: HttpResponse(200, b"{}", response_headers)) as (url, _, _):
        with closing(HttpSessionPool(timeout=1)) as pool:

            async def detect():
                async with RetainedDetectionHttp(
                    timeout=1, retries=0, max_bytes=1024, budget=HttpHandoffBudget(1)
                ) as http:
                    response = await read_http(HttpRead(pool, "GET", url, {"headers": headers}), http)
                    assert response.status == 200
                    assert http.handoff() is False

            if taint == "custom-cookie":
                # The user's global overrides are applied before the handoff decision.
                with custom_http_headers([("Cookie", "custom=only-detect")]):
                    asyncio.run(detect())
            else:
                asyncio.run(detect())


def test_cancelled_panel_lifecycle_cannot_reopen_a_late_http_pool():
    from redposture_core import web_panels
    from redposture_core.stage_runtime import AuditCommandRunner

    state = SimpleNamespace()
    ctx = SimpleNamespace(args=SimpleNamespace(timeout=1), lifecycle_state=state, reuse_http=True)
    with peer() as (url, connections, _):
        with web_panels._panel_http_scope(ctx) as pool:
            assert pool.request("GET", url).status == 200
        AuditCommandRunner._close_panel_http(state)
        before = len(connections)
        with web_panels._panel_http_scope(ctx) as late:
            with pytest.raises(RuntimeError, match="closed"):
                late.request("GET", url)
            assert len(connections) == before
        late.close()


@pytest.mark.parametrize("policy", ["tls", "proxy", "origin"])
def test_handoff_refuses_an_incompatible_transport_policy(policy, mtls_material):
    from redposture_core.clients.http_handoff import HttpHandoffBudget, RetainedDetectionHttp
    from redposture_core.detection_io import HttpRead, read_http

    budget = HttpHandoffBudget(1)
    with peer(secure=True, material=mtls_material) as (url, _, _):
        with (
            closing(HttpSessionPool(timeout=1, insecure=True)) as good,
            closing(HttpSessionPool(timeout=1, insecure=policy != "tls")) as bad,
        ):
            if policy == "proxy":
                from redposture_core.network_proxy import ProxyConfig

                bad.proxy = ProxyConfig("http", "127.0.0.1", 1, None, None, "http://127.0.0.1:1")

            async def detect():
                async with RetainedDetectionHttp(timeout=1, retries=0, max_bytes=1024, budget=budget) as http:
                    assert (await read_http(HttpRead(good, "GET", url, {}), http)).status == 200
                    if policy == "origin":
                        port = int(url.rsplit(":", 1)[1])
                        assert not good.adopt_socket(
                            ("https", "127.0.0.2", port),
                            http._connection[2].sock,
                            tls_context=good._target_context(),
                            on_claim=lambda: None,
                        )
                    else:
                        assert not http.handoff(bad)
                    assert budget.active == 0
                    assert http.handoff(good)

            asyncio.run(detect())
            assert good.request("GET", url + "/after").status == 200
            assert budget.active == 0
