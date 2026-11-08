"""A failed mandatory product signal cannot be repaired by a second request."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from redposture_core import web_panels
from redposture_core.clients.http_api import HttpResponse
from redposture_core.detection_steps import run_async_requests, run_requests


def response(payload="", *, status=200, error=None, truncated=False, headers=None):
    body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
    return HttpResponse(status=status, body=body, headers=headers or {}, error=error, truncated=truncated)


def probe(module, routes, native):
    calls = []

    def send(base, path, options=None):
        assert base == "https://qa/prefix"
        calls.append(path)
        assert path in routes, f"unnecessary dependent probe: {module} {path}"
        return routes[path]

    if native:

        async def async_send(base, path, options=None):
            return send(base, path, options)

        result = asyncio.run(
            run_async_requests(web_panels.fingerprint_requests(module, "https://qa/prefix"), async_send)
        )
    else:
        result = run_requests(web_panels.fingerprint_requests(module, "https://qa/prefix"), send)
    return result, calls


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize(
    "module,title", [("redis", "Redis Insight"), ("mongodb", "Mongo Express"), ("minio", "MinIO Console")]
)
@pytest.mark.parametrize("fault", ["timeout", "foreign", "comment", "truncated", "denied", "transport"])
def test_absent_mandatory_page_stops_only_its_dependent_probe(native, module, title, fault):
    page = response("<title>Other service</title>")
    if fault == "timeout":
        page = response(status=0, error="timed out")
    elif fault == "comment":
        page = response(f"<!-- <title>{title}</title> -->")
    elif fault == "truncated":
        page = response(f"<title>{title}</title>", truncated=True)
    elif fault == "denied":
        page = response(f"<title>{title}</title>", status=403)
    elif fault == "transport":
        page = response(f"<title>{title}</title>", error="connection reset")
    result, calls = probe(module, {"/": page}, native)
    assert result is None and calls == ["/"]


@pytest.mark.parametrize("native", [False, True])
def test_mongo_logo_marker_is_required_before_loading_the_logo(native):
    result, calls = probe("mongodb", {"/": response("<title>Mongo Express</title>")}, native)
    assert result is None and calls == ["/"]


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("module", ["redis", "mongodb", "minio"])
@pytest.mark.parametrize("secondary_valid", [False, True])
def test_real_page_still_needs_its_independent_api_or_asset_evidence(native, module, secondary_valid):
    if module == "redis":
        routes = {
            "/": response("<title>Redis Insight</title>"),
            "/api/info": response(
                {"appVersion": "2.68.0", "appType": "DOCKER", "buildType": "DOCKER_ON_PREMISE"}
                if secondary_valid
                else {"version": "2.68.0"}
            ),
        }
        product, secondary = "redis_insight", "/api/info"
    elif module == "mongodb":
        routes = {
            "/": response('<title>Mongo Express</title><img src="/public/img/mongo-express-logo.png">'),
            "/public/img/mongo-express-logo.png": response(
                "asset", status=200 if secondary_valid else 404, headers={"content-type": "image/png"}
            ),
        }
        product, secondary = "mongo_express", "/public/img/mongo-express-logo.png"
    else:
        routes = {
            "/": response("<title>MinIO Console</title>"),
            "/api/v1/session": response(
                {"message": "invalid session"} if secondary_valid else {"message": "forbidden"},
                status=403,
                headers={"server": "MinIO Console"},
            ),
        }
        product, secondary = "minio_console", "/api/v1/session"
    result, calls = probe(module, routes, native)
    assert calls == ["/", secondary]
    assert (result[0] if result else None) == (product if secondary_valid else None)


@pytest.mark.parametrize("native", [False, True])
def test_unbranded_pgadmin_login_skips_ping_but_preserves_postgrest_fallback(native):
    routes = {
        "/login": response("<title>Other</title>"),
        "/": response(
            {"swagger": "2.0", "paths": {"/billing": {}}},
            headers={"server": "postgrest/12.2.0", "content-type": "application/openapi+json"},
        ),
    }
    result, calls = probe("postgres", routes, native)
    assert result[0:2] == ("postgrest", "12.2.0") and calls == ["/login", "/"]


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("ping_valid", [False, True])
def test_pgadmin_page_still_needs_ping_and_keeps_alternate_backend_on_failure(native, ping_valid):
    routes = {
        "/login": response("<title>pgAdmin 4</title>"),
        "/misc/ping": response("PING" if ping_valid else "other"),
        "/": response("not PostgREST"),
    }
    result, calls = probe("postgres", routes, native)
    assert (result[0] if result else None) == ("pgadmin" if ping_valid else None)
    assert calls == ["/login", "/misc/ping"] + ([] if ping_valid else ["/"])


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("kind", ["none", "kibana", "opensearch", "both"])
@pytest.mark.parametrize("spaces_valid", [False, True])
def test_elastic_verifiers_require_their_own_status_brand_before_loading_collections(native, kind, spaces_valid):
    headers = {}
    if kind in {"kibana", "both"}:
        headers["kbn-name"] = "qa-kibana"
    if kind in {"opensearch", "both"}:
        headers["osd-name"] = "qa-dashboards"
    routes = {"/api/status": response({"version": {"number": "8.15.0"}}, headers=headers)}
    if "kbn-name" in headers:
        routes["/api/spaces/space"] = response(
            [{"id": "default"}] if spaces_valid else {"error": "unavailable"}, headers={"kbn-name": "qa-kibana"}
        )
    if "osd-name" in headers:
        routes["/api/saved_objects/_find?type=dashboard&per_page=1"] = response(
            {"saved_objects": []}, headers={"osd-name": "qa-dashboards"}
        )
    result, calls = probe("elastic", routes, native)
    kibana = "kbn-name" in headers and spaces_valid
    assert (result[0] if result else None) == (
        "kibana" if kibana else "opensearch_dashboards" if "osd-name" in headers else None
    )
    expected = ["/api/status"] + (["/api/spaces/space"] if "kbn-name" in headers else [])
    if "osd-name" in headers and not kibana:
        expected += ["/api/saved_objects/_find?type=dashboard&per_page=1"]
    assert calls == expected


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize(
    "module,product",
    [("redis", "redis_insight"), ("mongodb", "mongo_express"), ("minio", "minio_console"), ("postgres", "pgadmin")],
)
def test_failed_http_prerequisite_does_not_skip_the_independent_https_surface(native, module, product):
    ctx = SimpleNamespace(
        host="qa",
        port=6379,
        args=SimpleNamespace(),
        target=SimpleNamespace(scheme=None, path="/tenant", explicit_port=6379),
    )
    https = {
        "redis": {
            "/": response("<title>Redis Insight</title>"),
            "/api/info": response({"appVersion": "2.68.0", "appType": "DOCKER", "buildType": "DOCKER_ON_PREMISE"}),
            "/api/databases": response([], status=401),
        },
        "mongodb": {
            "/": response('<title>Mongo Express</title><img src="/public/img/mongo-express-logo.png">'),
            "/public/img/mongo-express-logo.png": response("asset", headers={"content-type": "image/png"}),
        },
        "minio": {
            "/": response("<title>MinIO Console</title>"),
            "/api/v1/session": response(
                {"message": "invalid session"}, status=403, headers={"server": "MinIO Console"}
            ),
            "/api/v1/buckets": response({}, status=401),
        },
        "postgres": {
            "/login": response("<title>pgAdmin 4</title>"),
            "/misc/ping": response("PING"),
            "/browser/": response({}, status=401),
        },
    }[module]
    calls = []

    def send(base, path, options=None):
        assert base in {"http://qa:6379/tenant", "https://qa:6379/tenant"}
        calls.append((base, path))
        if base.startswith("http://"):
            assert path in ({"/login", "/"} if module == "postgres" else {"/"})
            return response("<title>Other service</title>")
        assert path in https
        return https[path]

    if native:

        async def async_send(base, path, options=None):
            return send(base, path, options)

        result = asyncio.run(run_async_requests(web_panels.panel_requests(module, ctx), async_send))
    else:
        result = run_requests(web_panels.panel_requests(module, ctx), send)
    assert result["is_ui"] is True and result["ui_product"] == product
    assert result["ui"]["endpoint"] == "https://qa:6379/tenant"
    assert [path for base, path in calls if base.startswith("http://")] == (
        ["/login", "/"] if module == "postgres" else ["/"]
    )


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("home_status,expected", [(200, "not_service"), (0, "transport_failure")])
def test_portainer_keeps_its_separate_availability_observation(native, home_status, expected):
    ctx = SimpleNamespace(
        host="qa", port=9000, args=SimpleNamespace(), target=SimpleNamespace(scheme="http", path="", explicit_port=9000)
    )
    calls = []

    def send(base, path, options=None):
        calls.append(path)
        if path == "/api/system/status":
            return response(status=0, error="timed out")
        assert path == "/"
        return response("Other service", status=home_status, error=None if home_status else "timed out")

    if native:

        async def async_send(base, path, options=None):
            return send(base, path, options)

        result = asyncio.run(
            run_async_requests(web_panels.panel_requests("portainer", ctx, report_failure=True), async_send)
        )
    else:
        result = run_requests(web_panels.panel_requests("portainer", ctx, report_failure=True), send)
    assert result["status"] == expected and result["is_portainer"] is False
    assert calls == ["/api/system/status", "/"]
