"""Foreign products and incomplete companion responses must not confirm a UI."""

import asyncio
from dataclasses import replace

import pytest

from redposture_core import web_panels
from redposture_core.detection_steps import run_async_requests
from tests.test_web_panels import _FIXTURES, _response


@pytest.mark.parametrize("module", tuple(web_panels.MODULE_PRODUCTS))
@pytest.mark.parametrize("fixture", tuple(_FIXTURES))
def test_foreign_product_matrix_has_identical_sync_async_decisions(module, fixture, monkeypatch):
    routes = _FIXTURES[fixture]

    def send(base, path, options=None):
        return routes.get(path, _response(404, {}))

    monkeypatch.setattr(web_panels, "_get", lambda pool, base, path, **opts: send(base, path, opts))
    sync = web_panels._fingerprints(module, object(), "http://qa")

    async def request(base, path, options=None):
        return send(base, path, options)

    native = asyncio.run(run_async_requests(web_panels.fingerprint_requests(module, "http://qa"), request))
    assert native == sync
    expected = "elastic" if fixture.startswith("elastic_") else fixture
    assert (sync is not None) is (module == expected)


@pytest.mark.parametrize(
    "fixture,path",
    [
        ("mongodb", "/public/img/mongo-express-logo.png"),
        ("postgres", "/misc/ping"),
        ("minio", "/api/v1/session"),
    ],
)
@pytest.mark.parametrize("damage", ["error", "truncated"])
def test_incomplete_companion_is_not_second_proof(fixture, path, damage, monkeypatch):
    routes = dict(_FIXTURES[fixture])
    routes[path] = replace(
        routes[path], **({"error": "incomplete response"} if damage == "error" else {"truncated": True})
    )
    monkeypatch.setattr(web_panels, "_get", lambda pool, base, route, **opts: routes.get(route, _response(404, {})))
    assert web_panels._fingerprints(fixture, object(), "http://qa") is None


@pytest.mark.parametrize(
    "fixture,path",
    [
        ("portainer", "/"),
        ("mongodb", "/"),
        ("redis", "/"),
        ("postgres", "/login"),
        ("minio", "/"),
    ],
)
def test_documentation_comment_is_not_a_product_page(fixture, path, monkeypatch):
    routes = dict(_FIXTURES[fixture])
    routes[path] = _response(200, "<title>Documentation</title><!-- example: " + routes[path].text + " -->")
    monkeypatch.setattr(web_panels, "_get", lambda pool, base, route, **opts: routes.get(route, _response(404, {})))
    assert web_panels._fingerprints(fixture, object(), "http://qa") is None


@pytest.mark.parametrize("module", tuple(web_panels.MODULE_PRODUCTS))
@pytest.mark.parametrize("status", [200, 301, 302, 401, 403, 404, 429, 500])
def test_generic_login_errors_and_redirects_do_not_identify_product(module, status, monkeypatch):
    response = _response(
        status,
        "<title>Sign in</title><p>Grafana Kibana pgAdmin Portainer MinIO Console Redis Insight Mongo Express</p>",
        headers={"Location": "https://sso.example/login", "Server": "nginx"},
    )
    monkeypatch.setattr(web_panels, "_get", lambda *args, **kw: response)
    assert web_panels._fingerprints(module, object(), "http://qa") is None


def test_kibana_elastic_branding_uses_real_injected_metadata(monkeypatch):
    routes = {
        "/api/status": _response(401, {}, headers={"kbn-name": "qa"}),
        "/login": _response(
            200,
            '<title>Elastic</title><script id="kbn-injected-metadata" type="application/json">{}</script>',
            headers={"kbn-name": "qa"},
        ),
    }
    monkeypatch.setattr(web_panels, "_get", lambda pool, base, path, **kw: routes.get(path, _response(404, {})))
    proof = web_panels._fingerprints("elastic", object(), "http://qa")
    assert proof is not None and proof[0] == "kibana"
    routes["/login"] = _response(
        200, '<title>SSO</title><!-- <script id="kbn-injected-metadata">kibana</script> -->', headers={"kbn-name": "qa"}
    )
    assert web_panels._fingerprints("elastic", object(), "http://qa") is None
