"""Cross-product structural HTML negatives; examples must not become evidence."""

from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core import auth_detection, web_panels
from redposture_core.clients.http_api import HttpResponse
from redposture_core.detection_steps import run_requests
from redposture_core.modules.gitlab import actions as gitlab
from redposture_core.modules.jenkins import actions as jenkins
from redposture_core.modules.kafka import http_surfaces
from redposture_core.modules.kafka import ui as kafka_ui
from redposture_core.modules.minio import actions as minio
from redposture_core.modules.nomad import actions as nomad
from redposture_core.modules.rabbitmq import actions as rabbitmq
from redposture_core.modules.spark import actions as spark
from tests.application_markup import application_page

PAGES = {
    "jenkins": '<title>Jenkins</title><form action="j_spring_security_check"><input name="j_username"><input name="j_password"></form>',
    "gitlab": '<title>GitLab</title><form action="/users/sign_in"><input name="user[login]"></form>',
    "spark": '<title>Spark Master at spark://master:7077</title><span class="version">3.5.6</span>',
    "panels": "<title>Portainer</title>",
    "minio": application_page("minio"),
    "sso": '<form id="kc-form-login"><input id="kc-login"></form>',
}


def _response(body, status=200):
    return HttpResponse(status, body.encode(), {})


def _pool(routes):
    return SimpleNamespace(request=lambda method, url, **options: routes.get(urlsplit(url).path, _response("{}", 404)))


def _proof(product, body):
    if product == "jenkins":
        return jenkins._login(_response(body))
    if product == "gitlab":
        return gitlab._detect_login_page(body)
    if product == "spark":
        return spark._ui_version(_response(body)) is not None
    if product == "panels":
        return web_panels._product_page(_response(body), "Portainer")
    if product == "minio":
        return minio._is_minio_console(
            SimpleNamespace(http_status=200, transport_error=None, body=body.encode(), truncated=False)
        )
    return auth_detection.detect_browser_sso(body=body) is not None


@pytest.mark.parametrize("product", PAGES)
@pytest.mark.parametrize("wrapper", ["comment", "script", "template", "attribute"])
def test_embedded_examples_are_not_product_or_sso_proof(product, wrapper):
    body = PAGES[product]
    fake = {
        "comment": "<title>Documentation</title><!-- " + body + " -->",
        "script": "<title>Documentation</title><script>const example = `" + body + "`;</script>",
        "template": "<title>Documentation</title><template>" + body + "</template>",
        "attribute": "<title>Documentation</title><div data-example='" + body + "'></div>",
    }[wrapper]
    assert _proof(product, fake) is False


@pytest.mark.parametrize("product", PAGES)
def test_real_markup_is_still_positive(product):
    assert _proof(product, PAGES[product]) is True


def test_jenkins_field_names_as_plain_text_are_not_input_controls():
    assert _proof("jenkins", "<form>j_username j_password Jenkins</form>") is False


@pytest.mark.parametrize("wrapper", ["comment", "script", "template"])
def test_nomad_generic_leader_and_embedded_ui_do_not_confirm_product(wrapper):
    markup = '<title>Nomad</title><meta name="nomad-ui/config/environment">'
    body = {
        "comment": "<!--" + markup + "-->",
        "script": "<script>const sample = `" + markup + "`;</script>",
        "template": "<template>" + markup + "</template>",
    }[wrapper]
    ctx = SimpleNamespace(host="qa", port=4646, target=None, args=SimpleNamespace())

    def send(base, path):
        if path == "/v1/status/leader":
            return _response('"qa:4647"')
        if path == "/ui/":
            return _response(body)
        return _response("{}", 403)

    result = run_requests(nomad.detect_requests(ctx), send)
    assert result["is_nomad"] is False


@pytest.mark.parametrize("product,title", [("akhq", "AKHQ"), ("redpanda_console", "Redpanda Console")])
@pytest.mark.parametrize("wrapper", ["comment", "script", "template"])
def test_kafka_http_generic_json_and_embedded_title_are_not_confirmation(monkeypatch, product, title, wrapper):
    markup = f"<title>{title}</title>"
    body = {
        "comment": "<!--" + markup + "-->",
        "script": "<script>const sample = `" + markup + "`;</script>",
        "template": "<template>" + markup + "</template>",
    }[wrapper]
    routes = {"/": _response(body)}
    routes["/api/me"] = _response('{"logged":false,"roles":[]}')
    routes["/admin/startup"] = _response("{}")
    monkeypatch.setattr(http_surfaces, "_get", lambda pool, base, path: routes.get(path, _response("{}", 404)))
    ctx = SimpleNamespace(host="qa", port=8080, target=SimpleNamespace(explicit_port=8080, scheme="http"))
    assert http_surfaces.detect(object(), "http://qa:8080", ctx) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://docs.example/help?example=https://accounts.google.com/login",
        "https://docs.example/help?example=https://tenant.auth0.com/authorize",
        "https://docs.example/help?example=/realms/demo/protocol/openid-connect/auth",
        "https://accounts.google.com.attacker.example/login",
        "https://panel.example/ui/login",
    ],
)
def test_sso_provider_is_not_taken_from_query_examples_or_lookalike_hosts(url):
    assert auth_detection.detect_browser_sso(final_url=url) is None


@pytest.mark.parametrize("brand", ["Kafbat", "Provectus"])
@pytest.mark.parametrize("wrapper", ["comment", "script", "template"])
def test_kafka_ui_embedded_brand_does_not_select_execution_vendor(monkeypatch, brand, wrapper):
    body = {
        "comment": f"<!-- {brand} -->",
        "script": f'<script>const sample="{brand}";</script>',
        "template": f"<template>{brand}</template>",
    }[wrapper]
    routes = {
        "/api/info": _response('{"build":{"version":"1.0.0","commitId":"abc"}}'),
        "/api/config/authentication": _response('{"authType":"DISABLED"}'),
        "/api/authorization": _response('{"rbacEnabled":false,"userInfo":null}'),
        "/api/clusters": _response("[]"),
        "/": _response(body),
    }
    monkeypatch.setattr(kafka_ui, "_get", lambda pool, base, path: routes.get(path, _response("{}", 404)))
    ctx = SimpleNamespace(host="qa", port=8080, target=SimpleNamespace(scheme="http", path=""), args=SimpleNamespace())
    state = SimpleNamespace(ui_http=_pool(routes))
    record = kafka_ui.detect_ui(ctx, state)
    assert record["is_kafka_ui"] is True
    assert record["ui_vendor"] is None


@pytest.mark.parametrize("wrapper", ["comment", "script", "template"])
def test_kafbat_branded_title_in_example_does_not_complete_api_evidence(monkeypatch, wrapper):
    markup = '<title>Kafbat UI</title><form><input name="username"><input name="password"></form>'
    body = {
        "comment": "<!--" + markup + "-->",
        "script": "<script>const sample=`" + markup + "`;</script>",
        "template": "<template>" + markup + "</template>",
    }[wrapper]
    routes = {
        "/api/config/authentication": _response('{"authType":"LOGIN_FORM"}'),
        "/api/authorization": _response('{"rbacEnabled":false,"userInfo":null}'),
        "/login": _response(body),
    }
    monkeypatch.setattr(kafka_ui, "_get", lambda pool, base, path: routes.get(path, _response("{}", 404)))
    ctx = SimpleNamespace(host="qa", port=8080, target=SimpleNamespace(scheme="http", path=""), args=SimpleNamespace())
    record = kafka_ui.detect_ui(ctx, SimpleNamespace(ui_http=_pool(routes)))
    assert record["is_kafka_ui"] is False


@pytest.mark.parametrize("wrapper", ["comment", "script", "template"])
def test_rabbitmq_generic_denial_and_embedded_title_do_not_confirm(monkeypatch, wrapper):
    markup = "<title>RabbitMQ Management</title>"
    body = {
        "comment": "<!--" + markup + "-->",
        "script": "<script>const sample=`" + markup + "`;</script>",
        "template": "<template>" + markup + "</template>",
    }[wrapper]
    api = SimpleNamespace(status=401, headers={}, data={"error": "unauthorized"}, error=None, outcome="denied")
    root = SimpleNamespace(status=200, body=body.encode(), headers={}, error=None)
    client = SimpleNamespace(
        base_url="http://qa",
        get=lambda path: root if path == "/" else api,
        collection=lambda *args, **kwargs: SimpleNamespace(status="denied", items=[]),
    )
    monkeypatch.setattr(rabbitmq, "_state", lambda ctx: SimpleNamespace(resolve=lambda: api, client=lambda: client))
    result = rabbitmq.detect_record(SimpleNamespace(host="qa", port=15672))
    assert result["is_rabbitmq"] is False


@pytest.mark.parametrize("wrapper", ["template", "svg"])
def test_kibana_metadata_inside_inert_container_is_not_proof(wrapper):
    body = f'<title>Other</title><{wrapper}><script id="kbn-injected-metadata">{{}}</script></{wrapper}>'
    assert web_panels._product_page(_response(body), "Kibana", identifier="kbn-injected-metadata") is False
