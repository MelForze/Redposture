"""Keep the original decisions and requests across real module HTTP adapters."""

from __future__ import annotations

import asyncio

import pytest

from redposture_core.clients import http_handoff
from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.stage_runtime import AuditCommandRunner
from redposture_core.targeting import ScanTargetSpec
from tests.http_detect_fixtures import detection_response
from tests.test_async_http_timeout_retries import MODULES, make_runner
from tests.test_async_retained_parity import normalize
from tests.test_http_detect_handoff import peer

EXTRA_MODULES = (
    "airflow",
    "vault",
    "nomad",
    "jupyter",
    "jenkins",
    "keycloak",
    "spark",
    "yarn",
    "harbor",
    "nexus",
    "kafka",
)


def module_response(module, url):
    import json
    from urllib.parse import urlsplit

    from redposture_core.clients.http_api import HttpResponse
    from tests.test_async_rollout_http import MODULES as rollout_modules
    from tests.test_async_rollout_http import reply

    if module in rollout_modules:
        return reply(module, url, True)
    path = urlsplit(url).path
    routes = {
        "vault": {"/v1/sys/health": {"initialized": True, "sealed": False, "standby": False, "version": "1.17.5"}},
        "nomad": {
            "/v1/agent/self": {"config": {"Version": "1.8.4", "ACL": {"Enabled": True}}, "stats": {}},
            "/v1/status/leader": "127.0.0.1:4647",
        },
        "jupyter": {
            "/api": {"version": "2.14.2"},
            "/api/status": {
                "started": "2026-01-01T00:00:00Z",
                "last_activity": "2026-01-01T00:00:00Z",
                "kernels": 0,
                "connections": 0,
            },
            "/api/kernels": [],
            "/api/terminals": [],
        },
        "harbor": {"/api/v2.0/systeminfo": {"harbor_version": "v2.11.1", "auth_mode": "db_auth", "registry_url": "qa"}},
        "kafka": {
            "/api/info": {"build": {"version": "1.4.2", "commitId": "abc"}, "name": "Kafbat UI"},
            "/api/config/authentication": {"authType": "LOGIN_FORM"},
            "/api/authorization": {"rbacEnabled": False, "userInfo": None},
        },
        "nexus": {"/service/rest/v1/status": {"productName": "Sonatype Nexus Repository", "version": "3.72.0"}},
    }
    if module == "airflow":
        data = (
            {"version": "3.0.2", "git_version": "abc"}
            if path.endswith("/version")
            else {"dags": [], "variables": [], "connections": [], "total_entries": 0}
        )
        return HttpResponse(200, json.dumps(data).encode(), {}, request_url=url, final_url=url)
    if module == "harbor" and path == "/v2/":
        return HttpResponse(
            200, b"{}", {"Docker-Distribution-Api-Version": "registry/2.0"}, request_url=url, final_url=url
        )
    if module in routes:
        data = routes[module].get(path)
        return HttpResponse(
            200 if data is not None else 403, json.dumps(data or {}).encode(), {}, request_url=url, final_url=url
        )
    return detection_response(module, url)


def pools(state, seen=None):
    seen = set() if seen is None else seen
    if state is None or id(state) in seen:
        return
    seen.add(id(state))
    if isinstance(state, HttpSessionPool):
        yield state
        return
    for name in (
        "http",
        "pool",
        "http_pool",
        "http_session",
        "web",
        "registry",
        "client",
        "session",
        "ui_state",
        "ui_http",
        "_detect_pool",
    ):
        child = getattr(state, name, None)
        if child is not None and child is not state:
            yield from pools(child, seen)


@pytest.mark.parametrize("module", MODULES + EXTRA_MODULES)
@pytest.mark.parametrize("secure", [False, True])
def test_each_http_module_reuses_target_pool_without_changing_detection(module, secure, mtls_material, monkeypatch):
    real_factory = http_handoff.RetainedDetectionHttp

    def previous_transport(*, budget, **options):
        return AsyncDetectionHttp(**options)

    with peer(secure=secure, material=mtls_material, responder=lambda url: module_response(module, url)) as (
        url,
        connections,
        requests,
    ):
        port = int(url.rsplit(":", 1)[1])
        target = ScanTargetSpec(
            "127.0.0.1", scheme="https" if secure else "http", explicit_port=port, surface_hint="backend"
        )
        results, calls, connection_counts = [], [], []
        for optimized in (False, True):
            monkeypatch.setattr(
                http_handoff, "RetainedDetectionHttp", real_factory if optimized else previous_transport
            )
            args, spec = make_runner(module)
            runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
            begin, before_connections = len(requests), len(connections)
            try:
                outcome = asyncio.run(runner._run_async_detect_with_state(target.host, port, target, None))
                assert outcome is not None and runner._is_detected(outcome.record)
                results.append(normalize(outcome.record.to_dict()))
                candidates = list(pools(outcome.lifecycle_state))
                if optimized:
                    retained = [pool for pool in candidates if pool._retained_claims]
                    assert len(retained) == 1, (module, vars(outcome.lifecycle_state))
                    pool = retained[0]
                else:
                    assert candidates
                    pool = candidates[0]
                if module == "elastic":
                    result = outcome.lifecycle_state.session.request(target.scheme, "GET", "/handoff-check")
                elif module == "kubeapi":
                    result = outcome.lifecycle_state.http_session.request("GET", url + "/handoff-check")
                else:
                    result = pool.request("GET", url + "/handoff-check")
                assert result.error is None
                calls.append(requests[begin:])
                connection_counts.append(len(connections) - before_connections)
            finally:
                runner._close_all_lifecycle_states()
            assert runner._http_handoff_budget.active == 0
        assert results[0] == results[1]
        assert calls[0] == calls[1]
        assert connection_counts[1] < connection_counts[0], connection_counts


@pytest.mark.parametrize("secure", [False, True])
def test_docker_engine_hands_detect_socket_to_original_sync_client(secure, mtls_material, monkeypatch):
    import json
    from types import SimpleNamespace
    from urllib.parse import urlsplit

    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.docker import actions, stage

    def response(url):
        path = urlsplit(url).path
        data = {
            "/version": {"Version": "25.0.5", "ApiVersion": "1.45", "Os": "linux"},
            "/info": {"ServerVersion": "25.0.5", "Containers": 4, "Images": 7, "OSType": "linux"},
        }.get(path)
        return HttpResponse(200, b"OK" if data is None else json.dumps(data).encode(), {})

    monkeypatch.setattr(actions, "_transport_order", lambda port: ["tls" if secure else "plaintext"])
    with peer(secure=secure, material=mtls_material, responder=response) as (url, connections, requests):
        port = int(url.rsplit(":", 1)[1])
        args = SimpleNamespace(timeout=1, retries=0, port=port, insecure=True)
        target = ScanTargetSpec("127.0.0.1", scheme="https" if secure else "http", explicit_port=port)
        runner = AuditCommandRunner(args=args, spec=stage.build_docker_spec(args), emit_line=lambda _: None)
        try:
            outcome = asyncio.run(runner._run_async_detect_with_state(target.host, port, target, None))
            assert outcome is not None and runner._is_detected(outcome.record)
            assert runner._http_handoff_budget.active == 1
            before = len(connections)
            record = actions.host_stage(target.host, port, 1, 0, insecure=True, lifecycle_state=outcome.lifecycle_state)
            assert record["is_docker"] is True, record.get("error")
            assert len(connections) == before
            assert requests[-3:][0][0] == "/_ping"
        finally:
            runner._close_all_lifecycle_states()
        assert runner._http_handoff_budget.active == 0


@pytest.mark.parametrize("fixture", ["mongodb", "redis", "postgres", "minio", "elastic_kibana", "elastic_osd"])
def test_independent_ui_pool_is_reused_and_closed(fixture):
    import importlib
    from urllib.parse import urlsplit

    from redposture_core.cli_args import parse_args
    from redposture_core.clients.http_api import HttpResponse
    from tests.test_web_panels import _FIXTURES

    module = "elastic" if fixture.startswith("elastic_") else fixture
    routes = _FIXTURES[fixture]
    with peer(
        responder=lambda url: routes.get(
            urlsplit(url).path + ("?" + urlsplit(url).query if urlsplit(url).query else ""),
            HttpResponse(401, b"{}", {}),
        )
    ) as (url, connections, requests):
        port = int(url.rsplit(":", 1)[1])
        args = parse_args([module, "-t", url, "--timeout", "1", "--retries", "0", "--no-color"])
        stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
        spec = getattr(stage, f"build_{module}_spec")(args)
        runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
        target = ScanTargetSpec("127.0.0.1", scheme="http", explicit_port=port, surface_hint="ui")
        try:
            outcome = asyncio.run(runner._run_async_detect_with_state(target.host, port, target, None))
            assert outcome is not None and outcome.record.extra.get("is_ui") is True
            pool = outcome.lifecycle_state._panel_http
            assert pool is not getattr(outcome.lifecycle_state, "http", None)
            assert runner._http_handoff_budget.active == 1
            before = len(connections)
            result = pool.request("GET", url + "/after")
            assert result.status == 401
            assert len(connections) == before
        finally:
            runner._close_all_lifecycle_states()
        assert pool._closed and runner._http_handoff_budget.active == 0


@pytest.mark.parametrize("proxy_scheme", ["http", "socks5h"])
def test_etcd_sync_fallback_keeps_parsed_proxy_policy(proxy_scheme):
    from redposture_core.network_proxy import ProxyConfig
    from tests.test_proxy_end_to_end import _running, _TunnelProxy

    with peer(responder=lambda url: detection_response("etcd", url)) as (url, connections, requests):
        port = int(url.rsplit(":", 1)[1])
        proxy = _TunnelProxy(proxy_scheme)
        raw = f"{proxy_scheme}://127.0.0.1:{proxy.server_address[1]}"
        args, spec = make_runner("etcd")
        args.proxy = raw
        args._proxy_config = ProxyConfig(proxy_scheme, "127.0.0.1", proxy.server_address[1], None, None, raw)
        target = ScanTargetSpec("127.0.0.1", scheme="http", explicit_port=port)
        runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
        with _running(proxy):
            try:
                outcome = runner._run_detect_with_state(target.host, port, target, None)
                assert runner._is_detected(outcome.record), outcome.record.to_dict()
                assert requests
                assert proxy.requested_hosts and all(
                    endpoint == (target.host, port) for endpoint in proxy.requested_hosts
                )
                assert outcome.lifecycle_state.pool.proxy is args._proxy_config
            finally:
                runner._close_all_lifecycle_states()
