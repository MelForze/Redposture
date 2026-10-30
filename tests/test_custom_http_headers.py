from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from redposture_core import cli, http_headers
from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.clients.docker_engine import DockerEngineClient
from redposture_core.clients.http_api import HttpApiClient, HttpClientConfig, HttpResponse
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.exporters import http_client as exporter_client
from redposture_core.exporters import http_pool as exporter_pool
from redposture_core.modules.clickhouse import actions as clickhouse_actions
from redposture_core.modules.elastic import async_detect as elastic_async_detect
from redposture_core.modules.elastic import http_session as elastic_http_session
from redposture_core.modules.kubeapi import http_session as kube_http_session


def test_user_headers_override_module_headers_case_insensitively() -> None:
    with http_headers.custom_http_headers([("authorization", "Bearer custom"), ("X-Tenant", "qa")]):
        merged = http_headers.merge_custom_http_headers(
            {"Authorization": "Basic internal", "Cookie": "session=internal", "x-tenant": "internal"}
        )

    assert merged == {"Cookie": "session=internal", "authorization": "Bearer custom", "X-Tenant": "qa"}
    assert http_headers.merge_custom_http_headers({"Authorization": "Basic internal"}) == {
        "Authorization": "Basic internal"
    }


def test_cli_header_scope_reaches_command_and_is_removed_afterward(monkeypatch) -> None:
    seen: list[dict[str, str]] = []

    def fake_run(_args: Any, _logger: Any) -> int:
        seen.append(http_headers.merge_custom_http_headers({"Authorization": "Basic internal"}))
        return 0

    monkeypatch.setattr(cli, "_run_command", fake_run)
    assert cli.main(["elastic", "-t", "127.0.0.1:9200", "-H", "Authorization: Bearer custom"]) == 0
    assert seen == [{"Authorization": "Bearer custom"}]
    assert http_headers.merge_custom_http_headers({"Authorization": "Basic internal"}) == {
        "Authorization": "Basic internal"
    }


def test_http_api_client_sends_custom_headers_on_requests(monkeypatch) -> None:
    requests: list[dict[str, str]] = []

    def fake_open(req: Any, *, timeout: float, context: Any = None) -> Any:
        requests.append(dict(req.header_items()))

        class Response:
            status = 200
            headers: dict[str, str] = {}

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_args: Any) -> None:
                return None

            def read(self, _size: int = -1) -> bytes:
                return b"ok"

            def getcode(self) -> int:
                return 200

            def geturl(self) -> str:
                return req.full_url

        return Response()

    monkeypatch.setattr("redposture_core.clients.http_api._open_http_request", fake_open)
    with http_headers.custom_http_headers([("Authorization", "Bearer custom"), ("X-Tenant", "qa")]):
        response = HttpApiClient(HttpClientConfig(default_headers={"Authorization": "Basic internal"})).get(
            "http://127.0.0.1:8080/api", headers={"Cookie": "session=module"}
        )

    assert response.status == 200
    assert len(requests) == 1
    assert requests[0]["Authorization"] == "Bearer custom"
    assert requests[0]["X-tenant"] == "qa"
    assert requests[0]["Cookie"] == "session=module"


def test_http_session_pool_sends_custom_headers_on_requests(monkeypatch) -> None:
    seen: list[dict[str, str]] = []
    pool = HttpSessionPool(timeout=1.0)

    def fake_once(_method: str, _url: str, *, headers: dict[str, str], **_kw: Any):
        seen.append(dict(headers))
        return HttpResponse(200, b"ok", {}), None, False

    monkeypatch.setattr(pool, "_request_once", fake_once)
    try:
        with http_headers.custom_http_headers([("Cookie", "session=custom"), ("X-Tenant", "qa")]):
            response = pool.request(
                "GET",
                "http://127.0.0.1:8080/api",
                headers={"Cookie": "session=module", "Authorization": "Basic internal"},
            )
    finally:
        pool.close()

    assert response.status == 200
    assert seen == [{"Authorization": "Basic internal", "Cookie": "session=custom", "X-Tenant": "qa"}]


def test_custom_authorization_wins_after_request_signing(monkeypatch) -> None:
    seen: list[dict[str, str]] = []
    pool = HttpSessionPool(timeout=1.0)

    def fake_once(_method: str, _url: str, *, headers: dict[str, str], **_kw: Any):
        seen.append(dict(headers))
        return HttpResponse(200, b"ok", {}), None, False

    def signer(_method: str, _url: str, headers: dict[str, str], _body: bytes | None) -> dict[str, str]:
        return {**headers, "Authorization": "AWS4-HMAC-SHA256 internal"}

    monkeypatch.setattr(pool, "_request_once", fake_once)
    try:
        with http_headers.custom_http_headers([("Authorization", "Bearer custom")]):
            response = pool.request("GET", "http://127.0.0.1:8080/api", prepare_request=signer)
    finally:
        pool.close()
    assert response.status == 200
    assert seen == [{"Authorization": "Bearer custom"}]


def test_async_detection_sends_custom_headers(monkeypatch) -> None:
    seen: list[dict[str, str]] = []
    client = AsyncDetectionHttp(timeout=1.0, retries=0, max_bytes=4096)

    async def fake_once(_url: str, _timeout: float, headers: dict[str, str], **_kw: Any) -> HttpResponse:
        seen.append(dict(headers))
        return HttpResponse(200, b"ok", {})

    monkeypatch.setattr(client, "_once", fake_once)
    with http_headers.custom_http_headers([("Authorization", "Bearer custom")]):
        response = asyncio.run(client.get("http://127.0.0.1:8080/api", headers={"Authorization": "Basic internal"}))

    assert response.status == 200
    assert seen == [{"Authorization": "Bearer custom"}]


def test_special_http_transports_apply_custom_headers_before_redirects(monkeypatch) -> None:
    seen: list[dict[str, str]] = []

    def fake_redirect(_send: Any, _method: str, _url: str, *, headers: dict[str, str], **_kw: Any) -> HttpResponse:
        seen.append(dict(headers))
        return HttpResponse(200, b"{}", {})

    monkeypatch.setattr(elastic_http_session, "follow_redirects", fake_redirect)
    monkeypatch.setattr(kube_http_session, "follow_redirects", fake_redirect)
    monkeypatch.setattr("redposture_core.clients.docker_engine.follow_redirects", fake_redirect)
    with http_headers.custom_http_headers([("Authorization", "Bearer custom"), ("Cookie", "session=custom")]):
        elastic = elastic_http_session.ElasticHttpSession("127.0.0.1", 9200)
        kube = kube_http_session.KubeApiHttpSession(
            "127.0.0.1", 6443, use_https=False, timeout=1.0, insecure=False, ca_file=None
        )
        docker = DockerEngineClient("127.0.0.1", 2375)
        try:
            assert elastic.request("http", "GET", "/", headers={"Authorization": "Basic internal"}).status == 200
            assert (
                kube.request("GET", "http://127.0.0.1:6443/version", headers={"Authorization": "Basic internal"}).status
                == 200
            )
            assert docker.request("GET", "/version", headers={"Authorization": "Basic internal"}).status == 200
        finally:
            elastic.close()
            kube.close()
            docker.close()

    assert len(seen) == 3
    assert all(
        headers["Authorization"] == "Bearer custom" and headers["Cookie"] == "session=custom" for headers in seen
    )


def test_exporter_pool_sends_custom_headers(monkeypatch) -> None:
    seen: list[dict[str, str]] = []
    pool = exporter_pool.HTTPConnectionPool()

    def fake_once(_url: str, _timeout: float, *, headers: dict[str, str], **_kw: Any):
        seen.append(dict(headers))
        return 200, b"ok", "text/plain", None, False, {"Content-Type": "text/plain"}

    monkeypatch.setattr(pool, "_get_once", fake_once)
    try:
        with http_headers.custom_http_headers([("Authorization", "Bearer custom"), ("X-Tenant", "qa")]):
            result = pool.get("http://127.0.0.1:9100/metrics", 1.0)
    finally:
        pool.close()
    assert result[:3] == (200, b"ok", "text/plain")
    assert seen == [{"Authorization": "Bearer custom", "X-Tenant": "qa"}]


def test_exporter_urlopen_sends_custom_headers() -> None:
    seen: list[dict[str, str]] = []

    class Response:
        status = 200
        headers = {"Content-Type": "text/plain"}

        def __enter__(self):
            return self

        def __exit__(self, *_args: Any):
            return None

        def read(self, _size: int = -1) -> bytes:
            return b"ok"

    def opener(request: Any, *, timeout: float) -> Response:
        seen.append(dict(request.header_items()))
        return Response()

    with http_headers.custom_http_headers([("Authorization", "Bearer custom")]):
        assert exporter_client.http_get_text("http://127.0.0.1:9100/metrics", 1, retries=0, urlopen_fn=opener) == (
            200,
            "ok",
        )
        assert (
            exporter_client.http_get_details("http://127.0.0.1:9100/metrics", 1, retries=0, urlopen_fn=opener)["status"]
            == 200
        )
    assert len(seen) == 2
    assert all(headers["Authorization"] == "Bearer custom" for headers in seen)


def test_elastic_direct_detection_request_includes_custom_headers() -> None:
    with http_headers.custom_http_headers([("Authorization", "Bearer custom"), ("X-Tenant", "qa")]):
        raw = elastic_async_detect._direct_request("localhost", 9200, "/_cluster/health", "http")
    assert b"Authorization: Bearer custom\r\n" in raw
    assert b"X-Tenant: qa\r\n" in raw


def test_clickhouse_http_driver_receives_custom_headers_at_initialization(monkeypatch) -> None:
    seen: list[dict[str, Any]] = []

    class FakeModule:
        @staticmethod
        def get_client(**kwargs: Any) -> object:
            seen.append(kwargs)
            return object()

    monkeypatch.setattr(clickhouse_actions, "_load_clickhouse_connect_module", lambda: FakeModule)
    with http_headers.custom_http_headers([("Authorization", "Bearer custom"), ("X-Tenant", "qa")]):
        clickhouse_actions._open_clickhouse_client("http", "localhost", 8123, 1.0, "default", "", "default")
    assert seen[0]["headers"] == {"Authorization": "Bearer custom", "X-Tenant": "qa"}


def test_qdrant_cli_sends_header_during_detection_and_inventory(capsys) -> None:
    seen: list[tuple[str, str | None, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            tenant = self.headers.get("X-Tenant")
            authorization = self.headers.get("Authorization")
            seen.append((self.path, tenant, authorization))
            if tenant != "qa":
                self.send_error(404)
                return
            payload: dict[str, Any] = {"title": "qdrant - vector search engine", "version": "1.15.0"}
            if self.path.startswith("/collections"):
                payload = {"status": "ok", "result": {"collections": []}}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert (
            cli.main(
                [
                    "qdrant",
                    "-t",
                    f"127.0.0.1:{server.server_port}",
                    "--collections",
                    "-H",
                    "X-Tenant: qa",
                    "-H",
                    "Authorization: Bearer custom",
                ]
            )
            == 0
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert seen
    assert any(path == "/" for path, _, _ in seen)
    assert any(path.startswith("/collections") for path, _, _ in seen)
    assert all(tenant == "qa" and authorization == "Bearer custom" for _, tenant, authorization in seen)
    assert "Qdrant" in capsys.readouterr().out
