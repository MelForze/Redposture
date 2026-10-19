from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core import web_panels
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import http_surfaces
from redposture_core.modules.kafka import render as kafka_render


def _response(body: Any, *, status: int = 200, headers: dict[str, str] | None = None) -> HttpResponse:
    data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    return HttpResponse(status=status, body=data, headers=headers or {})


class _Pool:
    def __init__(self, responses: dict[str, HttpResponse]) -> None:
        self.responses = responses
        self.paths: list[str] = []

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        assert method == "GET"
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        self.paths.append(path)
        return self.responses.get(path, _response("", status=404))

    def close(self) -> None:
        pass


@pytest.mark.parametrize(
    ("port", "responses", "product", "read"),
    [
        (
            8080,
            {
                "/": _response("<title>AKHQ</title>"),
                "/api/me": _response({"logged": False, "roles": [{"actions": ["READ"]}]}),
            },
            "akhq",
            True,
        ),
        (
            8080,
            {
                "/": _response("<title>Redpanda Console</title>"),
                "/admin/startup": _response({"version": "1"}),
                "/api/topics": _response([{"name": "orders"}]),
            },
            "redpanda_console",
            True,
        ),
        (
            8082,
            {
                "/topics": _response(["orders"], headers={"Content-Type": "application/vnd.kafka.v2+json"}),
                "/v3/clusters": _response({"kind": "KafkaClusterList", "data": []}),
            },
            "kafka_rest_proxy",
            True,
        ),
        (
            8083,
            {
                "/": _response({"version": "3.7.0", "commit": "abc", "kafka_cluster_id": "id"}),
                "/connectors": _response(["db"]),
            },
            "kafka_connect",
            True,
        ),
        (
            8088,
            {
                "/info": _response(
                    {"KsqlServerInfo": {"version": "1.0", "kafkaClusterId": "id", "serverStatus": "RUNNING"}}
                )
            },
            "ksqldb",
            None,
        ),
        (
            8081,
            {
                "/subjects": _response(
                    ["orders-value"], headers={"Content-Type": "application/vnd.schemaregistry.v1+json"}
                )
            },
            "schema_registry",
            True,
        ),
    ],
)
def test_kafka_http_surface_fingerprints(
    port: int, responses: dict[str, HttpResponse], product: str, read: bool | None
) -> None:
    pool = _Pool(responses)
    result = http_surfaces.detect(pool, "http://qa", SimpleNamespace(host="qa", port=port))
    assert result is not None
    assert result["ui_vendor"] == product
    assert result["anonymous_read"] is read
    assert len(result["detection_signals"]) >= 2


@pytest.mark.parametrize("port", [8080, 8081, 8082, 8083, 8088])
def test_foreign_http_does_not_confirm_kafka_surface(port: int) -> None:
    pool = _Pool(
        {
            "/": _response("<title>Dashboard</title>"),
            "/topics": _response([]),
            "/subjects": _response([]),
            "/info": _response({"version": "1"}),
        }
    )
    assert http_surfaces.detect(pool, "http://qa", SimpleNamespace(host="qa", port=port)) is None


def test_explicit_nonstandard_port_checks_every_http_product() -> None:
    pool = _Pool(
        {
            "/topics": _response(["orders"], headers={"Content-Type": "application/vnd.kafka.v2+json"}),
            "/v3/clusters": _response({"kind": "KafkaClusterList", "data": []}),
        }
    )
    ctx = SimpleNamespace(
        host="qa", port=19999, args=SimpleNamespace(port=None), target=SimpleNamespace(explicit_port=19999)
    )
    result = http_surfaces.detect(pool, "http://qa", ctx)
    assert result is not None and result["ui_vendor"] == "kafka_rest_proxy"


def test_dashboard_and_postgrest_require_independent_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {
        "/": _response("<title>Kubernetes Dashboard</title><kd-root></kd-root>"),
    }
    monkeypatch.setattr(
        web_panels, "_get", lambda _pool, _base, path, **_kwargs: responses.get(path, _response("", status=404))
    )
    assert web_panels._fingerprints("kubeapi", object(), "http://qa") == (
        "kubernetes_dashboard",
        None,
        ["dashboard_title", "dashboard_angular_root"],
    )
    responses["/"] = _response(
        {"swagger": "2.0", "paths": {"/items": {"get": {}}}},
        headers={"Server": "postgrest/12.0", "Content-Type": "application/openapi+json"},
    )
    assert web_panels._fingerprints("postgres", object(), "http://qa") == (
        "postgrest",
        "12.0",
        ["postgrest_server", "postgrest_openapi"],
    )
    responses["/"] = _response({"swagger": "2.0", "paths": {}}, headers={"Content-Type": "application/openapi+json"})
    assert web_panels._fingerprints("postgres", object(), "http://qa") is None


def test_postgrest_read_access_is_proved_by_table_not_openapi(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = _Pool(
        {
            "/": _response(
                {"swagger": "2.0", "paths": {"/items": {"get": {}}}},
                headers={"Server": "postgrest/12.0", "Content-Type": "application/openapi+json"},
            ),
            "/items?limit=1": _response([{"name": "alpha"}]),
        }
    )
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kwargs: pool)
    ctx = SimpleNamespace(
        host="qa",
        port=3000,
        args=SimpleNamespace(timeout=1, secure=False, _proxy_config=None),
        target=SimpleNamespace(scheme="http", path="", explicit_port=3000),
    )
    result = web_panels.detect_panel("postgres", ctx)
    assert result is not None and result["ui_product"] == "postgrest"
    assert result["ui"]["anonymous_read"] is True
    assert result["auth_required"] is False
    assert result["credential_verification_status"] == "unavailable"


def test_dashboard_login_page_is_not_anonymous_api_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = _Pool({"/": _response("<title>Kubernetes Dashboard</title><kd-root></kd-root>")})
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kwargs: pool)
    ctx = SimpleNamespace(
        host="qa",
        port=8443,
        args=SimpleNamespace(timeout=1, secure=False, _proxy_config=None),
        target=SimpleNamespace(scheme="http", path="", explicit_port=8443),
    )
    result = web_panels.detect_panel("kubeapi", ctx)
    assert result is not None and result["ui_product"] == "kubernetes_dashboard"
    assert result["auth_required"] is None and result["status"] == "unknown_auth"


def test_url_without_explicit_port_still_checks_dashboard(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = _Pool({"/": _response("<title>Kubernetes Dashboard</title><kd-root></kd-root>")})
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kwargs: pool)
    ctx = SimpleNamespace(
        host="qa",
        port=443,
        args=SimpleNamespace(timeout=1, secure=False, _proxy_config=None),
        target=SimpleNamespace(scheme="https", path="", explicit_port=None),
    )
    result = web_panels.detect_panel("kubeapi", ctx)
    assert result is not None and result["ui_product"] == "kubernetes_dashboard"


def test_confirmed_http_read_lines_use_access_color() -> None:
    class PaintConsole:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def _paint(self, value: str, color: str, _stream: object) -> str:
            self.calls.append((value, color))
            return value

        def plain(self, _value: str) -> None:
            pass

    console = PaintConsole()
    assert kafka_render._render_colored_kafka_line(
        console, "KAFKA\tqa\t8082\t [+] Anonymous READ available through Kafka REST Proxy"
    )
    assert any("Anonymous READ" in value and color == "red" for value, color in console.calls)
    console.calls.clear()
    assert web_panels.colorize_panel_line(
        console, "POSTGRES\tqa\t3000\t [+] Anonymous READ available through PostgREST", "POSTGRES"
    )
    assert any("Anonymous READ" in value and color == "red" for value, color in console.calls)
