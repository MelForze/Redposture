"""Canonical transport redirects and product/auth proof are separate decisions."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse, http_target_context
from redposture_core.modules.grafana import actions
from tests.test_http_effective_origin import SequencePool


@pytest.fixture
def setup():
    previous = vars(actions._THREAD_LOCAL_HTTP).copy()
    states = []

    def create(path, final_url, body=b"{}", status=200):
        response = HttpResponse(
            status,
            body,
            {},
            request_url="http://source.qa:3000" + path,
            final_url=final_url,
            redirect_history=("http://source.qa:3000" + path,),
        )
        pool = SequencePool([response, HttpResponse(200, b"<title>Other product</title>", {})])
        state = actions.GrafanaLifecycleState(http=pool, scheme="http", host="source.qa", port=3000)
        actions._activate_grafana_transport(state)
        states.append(state)
        return pool, state

    yield create
    for state in states:
        state.close()
    vars(actions._THREAD_LOCAL_HTTP).clear()
    vars(actions._THREAD_LOCAL_HTTP).update(previous)


@pytest.mark.parametrize(
    "path,status,body",
    [
        ("/api/health", 200, b"{}"),
        ("/api/health", 401, b"{}"),
        ("/api/health", 403, b"{}"),
        ("/api/health", 404, b"{}"),
        ("/api/user", 200, b"{}"),
        ("/api/user", 401, b"{}"),
        ("/login", 200, b"<title>Grafana</title>"),
    ],
)
def test_canonical_route_preserving_redirect_is_reused_without_inventing_proof(setup, path, status, body):
    pool, state = setup(path, "https://canonical.qa:3443" + path, body, status)
    with http_target_context(SimpleNamespace(scheme="http", path="")):
        observed = actions._http_request("source.qa", 3000, path, 1)
        actions._http_request("source.qa", 3000, "/api/user", 1)
    assert pool.calls[-1] == "https://canonical.qa:3443/api/user"
    assert (state.scheme, state.host, state.port) == ("https", "canonical.qa", 3443)
    if path == "/api/health":
        assert actions._looks_like_grafana_health(observed[0], observed[1])[0] is False


@pytest.mark.parametrize(
    "path,final_url,body",
    [
        ("/api/health", "https://external.qa/landing", b"{}"),
        ("/api/user", "https://external.qa/login", b"<title>Sign in</title>"),
        ("/login", "https://external.qa/login", b"<title>Enter infrastructure</title>"),
        ("/api/health", "https://external.qa/api/health", b'<form id="kc-form-login"></form>'),
    ],
)
def test_external_landing_or_idp_never_becomes_api_origin(setup, path, final_url, body):
    pool, state = setup(path, final_url, body)
    with http_target_context(SimpleNamespace(scheme="http", path="")):
        actions._http_request("source.qa", 3000, path, 1)
        actions._http_request("source.qa", 3000, "/api/user", 1)
    assert pool.calls[-1] == "http://source.qa:3000/api/user"
    assert (state.scheme, state.host, state.port) == ("http", "source.qa", 3000)


def test_canonical_health_empty_json_does_not_identify_grafana(setup):
    pool, state = setup("/api/health", "https://canonical.qa:3443/api/health")
    ctx = SimpleNamespace(
        host="source.qa", port=3000, lifecycle_state=state, args=SimpleNamespace(timeout=1, retries=0, debug=False)
    )
    with http_target_context(SimpleNamespace(scheme="http", path="")):
        record = actions.detect_grafana(ctx, {"show_datasources": False, "check_urls": []})
    assert record["is_grafana"] is False and record["status"] == "not_grafana"
    assert pool.calls == ["http://source.qa:3000/api/health", "https://canonical.qa:3443/login"]
