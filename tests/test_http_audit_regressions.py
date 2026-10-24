"""Consumer-visible regressions for the October HTTP/API audit findings."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import SimpleNamespace as NS
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.clients.airflow_api import AirflowClient
from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.console import Console
from redposture_core.modules.consul import actions as consul
from redposture_core.modules.consul.stage import _build_consul_host_stage_options
from redposture_core.modules.grafana import actions as grafana
from redposture_core.modules.grpc import actions as grpc
from redposture_core.modules.jenkins import actions as jenkins
from redposture_core.modules.keycloak import actions as keycloak
from redposture_core.modules.keycloak import render as keycloak_render
from redposture_core.modules.kubeapi import actions as kube
from redposture_core.modules.nomad import actions as nomad
from redposture_core.modules.proxmox import actions as proxmox
from redposture_core.stage_runtime import LineOutputSink


def reply(status: int, data: Any, **kwargs: Any) -> HttpResponse:
    return HttpResponse(status, json.dumps(data).encode(), {"Content-Type": "application/json"}, **kwargs)


def test_h01_consul_candidates_do_not_inherit_previous_identity_access(monkeypatch: pytest.MonkeyPatch) -> None:
    state = consul.ConsulLifecycleState(
        scheme="http",
        anonymous_scopes={name: {"ok": False, "status": 403} for name in ("kv", "services", "agents")},
        anonymous_self={"ok": False, "status": 403},
    )
    ctx = NS(host="h", port=8500, target=None, args=NS(timeout=0.1, retries=0), lifecycle_state=state, debug_emit=None)

    def request(_host: str, _port: int, path: str, _timeout: float, **kwargs: Any) -> Any:
        accepted = kwargs["headers"]["Authorization"] == "Basic Z29vZDpnb29k"
        if not accepted:
            return 401, "Unauthorized", None, False, False
        body = {"Config": {"Version": "1.21.0"}} if path == "/v1/agent/self" else {} if "services" in path else []
        return 200, body, None, False, False

    monkeypatch.setattr(consul, "_consul_get_json_any", request)
    options = _build_consul_host_stage_options(NS())
    ctx.credential = NS(username="good", password="good", token=None, source="provided")
    assert consul.authenticate_consul(ctx, {}, options)["auth_valid"] is True
    ctx.credential = NS(username="bad", password="bad", token=None, source="provided")
    assert consul.authenticate_consul(ctx, {}, options)["auth_valid"] is not True
    ctx.credential = NS(username="good", password="good", token=None, source="provided")
    assert consul.authenticate_consul(ctx, {}, options)["auth_valid"] is True


@pytest.mark.parametrize("code", [1, 2, 4, 8, 12, 13, 14])
def test_h02_grpc_transport_failure_is_not_credential_proof(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    monkeypatch.setattr(grpc, "_health_check_call", lambda *_a, **_k: {"grpc_status": code, "call": {"is_grpc": True}})
    monkeypatch.setattr(
        grpc, "_reflection_capability_call", lambda *_a, **_k: {"grpc_status": 16, "call": {"is_grpc": True}}
    )
    accepted, _candidate, attempt = grpc._try_credentials(
        "h",
        50051,
        timeout=0.1,
        use_tls=False,
        protocol_flavor="grpc",
        candidates=[{"type": "basic", "username": "u", "password": "p"}],
        health_access="auth_required",
        reflection_access="auth_required",
        required_capability="health",
    )
    assert accepted is False
    assert attempt is not None and attempt["attempts"][0]["verdict"] == "unverified"


def test_h02_grpc_denied_invoke_preserves_verified_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    state = grpc.GrpcLifecycleState()
    monkeypatch.setattr(state, "session_for", lambda *_a, **_k: None)
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_a, **_k: {"grpc_status": 0, "health_supported": True, "call": {"is_grpc": True}},
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_capability_call",
        lambda *_a, **_k: {"grpc_status": 12, "reflection_enabled": False, "call": {"is_grpc": True}},
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_list_services_call",
        lambda *_a, **_k: {"grpc_status": 12, "reflection_enabled": False, "services": []},
    )
    monkeypatch.setattr(grpc, "_invoke_unary_method", lambda *_a, **_k: {"status": "grpc_error", "grpc_status": 7})
    result = grpc._audit_grpc_host(
        "h",
        50051,
        0.1,
        0,
        token="accepted",
        username=None,
        password=None,
        defcreds=False,
        preferred_scheme="http",
        run_deep_checks=True,
        invoke_path="/demo.Service/Denied",
        _lifecycle_detect_result={
            "is_grpc": True,
            "transport_mode": "plaintext",
            "health_access": "auth_required",
            "reflection_access": "unsupported",
        },
        _session_state=state,
    )
    assert result["provided_credentials_ok"] is True
    assert result["status"] == "valid_credentials"
    assert result["invoke_access"] == "auth_required" and result["action_access_satisfied"] is False


@pytest.mark.parametrize("protocol", ["grpc", "grpc-web"])
def test_h02_grpc_deep_permission_denial_does_not_reject_credential(
    monkeypatch: pytest.MonkeyPatch, protocol: str
) -> None:
    state = grpc.GrpcLifecycleState(reflection_deep_auth_required=True, health_deep_auth_required=True)
    monkeypatch.setattr(state, "session_for", lambda *_a, **_k: None)
    calls = 0

    def health(*_a: Any, **_k: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {
            "grpc_status": 7 if protocol == "grpc-web" and calls > 1 else 0,
            "health_supported": True,
            "call": {"is_grpc": True},
        }

    monkeypatch.setattr(grpc, "_health_check_call", health)
    monkeypatch.setattr(grpc, "_grpc_web_health_check_call", health)
    monkeypatch.setattr(
        grpc, "_reflection_capability_call", lambda *_a, **_k: {"grpc_status": 12, "call": {"is_grpc": True}}
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_list_services_call",
        lambda *_a, **_k: {"grpc_status": 7, "reflection_enabled": True, "services": []},
    )
    result = grpc._audit_grpc_host(
        "h",
        50051,
        0.1,
        0,
        token="accepted",
        username=None,
        password=None,
        defcreds=False,
        preferred_scheme="http",
        run_deep_checks=True,
        _lifecycle_detect_result={
            "is_grpc": True,
            "transport_mode": "plaintext",
            "protocol_flavor": protocol,
            "health_access": "auth_required",
            "reflection_access": "anonymous",
        },
        _session_state=state,
    )
    assert result["provided_credentials_ok"] is True
    assert result["status"] == "valid_credentials"
    assert result["action_access_satisfied"] is False


@pytest.mark.parametrize("resource", ["pods", "secrets", "configmaps"])
def test_h03_kube_namespace_denial_does_not_hide_later_resources(
    monkeypatch: pytest.MonkeyPatch, resource: str
) -> None:
    def request(_host: str, _port: int, path: str, _timeout: float, **_kwargs: Any) -> Any:
        if "/blocked/" in path:
            return kube.KubeListResult(None, 403, "Forbidden", False, False)
        return kube.KubeListResult(
            [{"metadata": {"name": "readable"}, "data": {"value": "c2VjcmV0"}}], 200, None, True, True
        )

    monkeypatch.setattr(kube, "_invoke_kube_list_items", request)
    kwargs = dict(use_https=False, insecure=True, ca_file=None, namespaces=["blocked", "allowed"])
    result = (
        kube._list_pods("h", 6443, 0.1, **kwargs)
        if resource == "pods"
        else kube._list_secrets("h", 6443, 0.1, resource=resource, **kwargs)
    )
    assert result.items and result.items[0]["name"] == "readable"
    assert result.access_confirmed and not result.complete and "blocked" in str(result.error)


def test_h04_proxmox_does_not_replay_ambiguous_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = []

    def request(*_args: Any, **_kwargs: Any) -> Any:
        attempts.append("created")
        return 0, b"", {}, "connection timeout after request was sent"

    monkeypatch.setattr(proxmox, "_proxmox_request_once", request)
    monkeypatch.setattr(proxmox.time, "sleep", lambda _delay: None)
    _status, _body, _headers, error = proxmox._proxmox_request(
        "h",
        8006,
        "/access/users",
        0.1,
        2,
        pve_api_token="",
        use_https=False,
        insecure=True,
        proxy=None,
        method="POST",
        form={"userid": "created@pve"},
    )
    assert attempts == ["created"]
    assert "uncertain" in str(error).lower() or "retry suppressed" in str(error).lower()


def test_h05_consul_dump_limit_reaches_actual_data_collector(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consul, "_probe_consul_scheme", lambda *_a, **_k: (True, "http", False, False, "h:8300", None))
    monkeypatch.setattr(
        consul,
        "_consul_access_matrix",
        lambda *_a, **_k: {n: {"ok": True, "count": 5} for n in ("kv", "services", "agents")},
    )
    monkeypatch.setattr(consul, "_agent_self_probe", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(
        consul,
        "_consul_get_json_any",
        lambda *_a, **_k: (200, [{"Key": f"k{i}", "Value": "eA=="} for i in range(5)], None, False, False),
    )
    options = {**_build_consul_host_stage_options(NS()), "show_keys": True, "dump_requested": True, "dump_limit": 2}
    result = consul._audit_consul_host(
        "h", 8500, 0.1, 0, token=None, username=None, password=None, run_deep_checks=True, **options
    )
    assert len(result["kv_dump_items"]) == 2


@pytest.mark.parametrize("failure", ["http", "truncated", "repeated"])
def test_h06_keycloak_later_page_failure_is_visible(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    page = [{"clientId": f"c{i}"} for i in range(100)]

    class Client:
        def get(self, url: str, **_kwargs: Any) -> HttpResponse:
            if parse_qs(urlsplit(url).query)["first"] == ["0"] or failure == "repeated":
                return reply(200, page)
            return reply(503, {}) if failure == "http" else reply(200, page, truncated=True)

    monkeypatch.setattr(keycloak, "_client", lambda _ctx: Client())
    ctx = NS(args=NS(show_clients=True, realm=["master"]), target=NS(path=""))
    result = keycloak.data_record(ctx, {"api_endpoint": "http://h", "provided_credentials_ok": True})
    assert len(result["visible_clients"]) == 100
    assert result.get("clients_partial") is True
    assert any("partial" in line.lower() for line in keycloak_render._format_inventory_records(result, "txt"))


def test_h07_airflow_ipv6_request_has_valid_authority() -> None:
    class Pool:
        def request(self, _method: str, url: str, **_kwargs: Any) -> HttpResponse:
            parsed = urlsplit(url)
            assert parsed.hostname == "::1" and parsed.port == 8080
            return reply(200, {"version": "3.0.0"})

    result = AirflowClient(Pool(), scheme="http", host="::1", port=8080).get("/api/v2/version")
    assert result.transport_error is None and result.http_status == 200


@pytest.mark.parametrize("baseline", ["proxy", "anonymous"])
def test_h08_jenkins_requires_new_identity_proof_without_literal_username_match(
    monkeypatch: pytest.MonkeyPatch, baseline: str
) -> None:
    def get(_client: Any, _base: str, path: str, basic: str | None = None) -> HttpResponse:
        if path.startswith("/api/json"):
            return reply(200, {"jobs": []})
        if basic is None and baseline == "anonymous":
            return reply(401, {})
        return reply(200, {"authenticated": True, "name": "canonical-user", "authorities": ["authenticated"]})

    monkeypatch.setattr(jenkins, "_client", lambda _ctx: object())
    monkeypatch.setattr(jenkins, "_get", get)
    ctx = NS(credential=NS(username="alias", password="secret", source="provided"))
    result = jenkins.auth_record(ctx, {"api_endpoint": "http://h"})
    assert result["provided_credentials_ok"] is (True if baseline == "anonymous" else None)
    assert result.get("authenticated_identity") == "canonical-user"


@pytest.mark.parametrize("kind", ["basic", "token", "scoped-token"])
@pytest.mark.parametrize("baseline", ["proxy", "denied"])
def test_h08_grafana_baselines_identity_and_scoped_capability(
    monkeypatch: pytest.MonkeyPatch, kind: str, baseline: str
) -> None:
    def request(_h: str, _p: int, path: str, _t: float, **kwargs: Any) -> Any:
        auth = bool((kwargs.get("headers") or {}).get("Authorization"))
        if not auth and baseline == "denied":
            return 401, "{}", {}
        if kind == "scoped-token" and path == "/api/user":
            return 401, "{}", {}
        return (
            (200, "[]", {}) if path == "/api/datasources" else (200, '{"id":7,"login":"canonical-user","orgId":1}', {})
        )

    monkeypatch.setattr(grafana, "_http_request", request)
    monkeypatch.setattr(grafana._THREAD_LOCAL_HTTP, "state", None, raising=False)
    result = (
        grafana._verify_credentials("h", 3000, 0.1, "alias", "secret")
        if kind == "basic"
        else grafana._verify_apitoken("h", 3000, 0.1, "token")
    )
    assert result[0] is (True if baseline == "denied" else None)


def test_h08_kube_public_list_does_not_validate_ignored_token(monkeypatch: pytest.MonkeyPatch) -> None:
    state = kube.KubeApiLifecycleState(anonymous_access="open", anonymous_namespaces=[])
    ctx = NS(
        host="h",
        port=6443,
        args=NS(timeout=0.1, retries=0),
        credential=NS(token="ignored", username=None, password=None, source="provided"),
        lifecycle_state=state,
    )
    monkeypatch.setattr(kube, "_probe_namespace_access", lambda *_a, **_k: (True, 200, None))
    monkeypatch.setattr(kube, "_verify_self_subject_review", lambda *_a, **_k: (True, "front-end-user", None))
    result = kube.authenticate_kubeapi(ctx, {"status": "open_no_auth"}, {})
    assert result["auth_valid"] is None


@pytest.mark.parametrize("baseline", ["anonymous", "different", "denied"])
def test_h08_kube_can_verify_token_identity_on_public_list(monkeypatch: pytest.MonkeyPatch, baseline: str) -> None:
    state = kube.KubeApiLifecycleState(anonymous_access="open", anonymous_namespaces=[])
    ctx = NS(
        host="h",
        port=6443,
        args=NS(timeout=0.1, retries=0),
        credential=NS(token="valid", username=None, password=None, source="provided"),
        lifecycle_state=state,
    )
    monkeypatch.setattr(kube, "_probe_namespace_access", lambda *_a, **_k: (True, 200, None))

    def review(_ctx: Any, _state: Any, token: str | None, **_kwargs: Any) -> Any:
        if token:
            return True, "system:serviceaccount:default:admin", None
        return {
            "anonymous": (False, "system:anonymous", "credential resolved to an anonymous identity"),
            "different": (True, "proxy-user", None),
            "denied": (None, None, "Forbidden"),
        }[baseline]

    monkeypatch.setattr(kube, "_verify_self_subject_review", review)
    result = kube.authenticate_kubeapi(ctx, {"status": "open_no_auth"}, {})
    assert result["auth_valid"] is True
    assert result["auth_verified_identity"] == "system:serviceaccount:default:admin"


@pytest.mark.parametrize("payload", ["<html>login</html>", {"unexpected": "json"}, 17])
def test_h09_consul_scope_requires_resource_shape(monkeypatch: pytest.MonkeyPatch, payload: Any) -> None:
    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (200, payload, None, False, False))
    result = consul._scope_probe(
        "h", 8500, "/v1/kv/", 0.1, scheme="http", insecure=True, count_fn=consul._count_kv_keys
    )
    assert result["ok"] is None and result["error"]


@pytest.mark.parametrize("resource", ["namespaces", "pods", "secrets"])
def test_h10_kube_nonempty_partial_inventory_renders_coverage(resource: str) -> None:
    rows = ["default"] if resource == "namespaces" else [{"namespace": "default", "name": "first", "data": {}}]
    record = {
        "host": "h",
        "port": 6443,
        "status": "open_no_auth",
        "auth_mode": "none",
        f"show_{resource}": True,
        resource: rows,
        f"{resource}_partial": True,
        f"{resource}_error": "partial: pagination limit exceeded",
    }
    text = "\n".join(kube._format_detail_records(record, "txt"))
    assert "partial" in text.lower() and "pagination" in text.lower() and "\x1b" not in text


def test_h11_nomad_preserves_access_and_marks_later_page_failure() -> None:
    class Pool:
        def request(self, _method: str, url: str, **_kwargs: Any) -> HttpResponse:
            return (
                reply(503, {})
                if "next_token" in url
                else HttpResponse(200, b'[{"ID":"first"}]', {"X-Nomad-NextToken": "page2"})
            )

    ctx = NS(args=NS(show_jobs=True), credential=None, lifecycle_state=NS(http=Pool()))
    result = nomad.data_record(ctx, {"api_endpoint": "http://h"})
    assert len(result["jobs"]) == 1 and result["jobs_access"] == "allowed"
    assert result["inventory_status"] == "partial" and result["job_discovery_partial"] is True


def test_h12_kube_pool_response_cap_matches_direct_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = HttpSessionPool(timeout=0.1)

    def request(_method: str, _url: str, **kwargs: Any) -> HttpResponse:
        body = b"x" * 300_000
        cap = kwargs.get("response_size_cap", 10 * 1024 * 1024)
        return HttpResponse(200, body[:cap], {}, truncated=len(body) > cap)

    monkeypatch.setattr(pool, "request", request)
    try:
        _status, body, _headers, error = kube._http_request(
            "h",
            6443,
            "GET",
            "/version",
            0.1,
            use_https=False,
            insecure=True,
            ca_file=None,
            client=pool,
            response_size_cap=262144,
        )
        assert body == b"" and "262144" in str(error)
    finally:
        pool.close()


def test_h13_unknown_txt_preserves_negative_marker_and_explains_uncertainty() -> None:
    lines = grafana._format_auth_attempt_detail_records(
        {
            "host": "h",
            "port": 3000,
            "auth_attempts": [{"username": "u", "password": "p", "ok": None, "error": "backend timeout"}],
        },
        "txt",
    )
    other = consul._auth_summary_line({"auth_mode": "token", "auth_valid": None, "auth_error": "backend timeout"})
    for line in [*lines, other]:
        assert line and "[-]" in line and "unverified" in line.lower() and "backend timeout" in line
        assert "\x1b" not in line


def test_h13_consul_missing_proof_has_default_reason() -> None:
    line = consul._auth_summary_line({"auth_mode": "basic", "auth_valid": None})
    assert line and "unverified" in line and "credential proof unavailable" in line


class RecordingConsole:
    def __init__(self) -> None:
        self.paints: list[tuple[str, str]] = []

    def _paint(self, text: str, color: str, _stream: Any) -> str:
        self.paints.append((text, color))
        return text

    def plain(self, _text: str) -> None:
        pass


@pytest.mark.parametrize("module", ["grafana", "consul"])
def test_h13_uncertainty_color_keeps_negative_marker(module: str) -> None:
    record = {
        "host": "h",
        "port": 1234,
        "auth_mode": "basic",
        "auth_valid": None,
        "auth_error": "backend timeout",
        "auth_attempts": [{"username": "u", "password": "p", "ok": None, "error": "backend timeout"}],
    }
    line = (
        grafana._format_auth_attempt_detail_records(record, "txt")[0]
        if module == "grafana"
        else "CONSUL\th\t8500\t " + str(consul._auth_summary_line(record))
    )
    colorize = getattr(
        importlib.import_module(f"redposture_core.modules.{module}.render"), f"_render_colored_{module}_line"
    )
    console = RecordingConsole()
    assert colorize(console, line)
    assert ("[-]", "true_red") in console.paints
    assert any(
        ("u:p" if module == "grafana" else "basic auth") in text and color == "white" for text, color in console.paints
    )
    assert any(
        "unverified" in text and "backend timeout" in text and color == "orange" for text, color in console.paints
    )


@pytest.mark.parametrize("module", ["keycloak", "kubeapi", "nomad"])
def test_partial_inventory_colors_and_saved_no_color_contract(
    module: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    render = importlib.import_module(f"redposture_core.modules.{module}.render")
    record: dict[str, Any] = {"host": "h", "port": 1234}
    if module == "keycloak":
        record.update(provided_credentials_ok=True, clients_partial=True, clients_errors={"master": "HTTP 503"})
        lines = render._format_inventory_records(record, "txt")
    elif module == "kubeapi":
        record.update(
            status="open_no_auth",
            auth_mode="none",
            show_pods=True,
            pods=[{"name": "retained", "namespace": "default", "containers": 1}],
            pods_partial=True,
            pods_error="pagination limit",
        )
        lines = render._format_detail_records(record, "txt")
    else:
        record.update(
            inventory_requested=["jobs"],
            jobs=[{"ID": "retained"}],
            jobs_access="allowed",
            jobs_partial=True,
            jobs_error="HTTP 503",
        )
        lines = render._format_inventory_records(record, "txt")
    colorize = getattr(render, f"_render_colored_{module}_line")
    console = RecordingConsole()
    for line in lines:
        assert colorize(console, line)
    assert any("partial" in text and color == "orange" for text, color in console.paints)
    if module == "keycloak":
        assert any('Realm="master"' in text and color == "orange" for text, color in console.paints)
    if module != "kubeapi":
        title = "Clients" if module == "keycloak" else "Jobs coverage"
        assert any(title in text and color == "white" for text, color in console.paints)
    plain = Console(no_color=True)
    path = tmp_path / f"{module}.txt"
    sink = LineOutputSink(str(path), lambda line: colorize(plain, line))
    try:
        sink.emit_many(lines)
    finally:
        sink.close()
    assert "partial" in path.read_text() and "\x1b" not in path.read_text()
    assert "\x1b" not in capsys.readouterr().out
    json_path = tmp_path / f"{module}.json"
    sink = LineOutputSink(str(json_path), plain.plain)
    try:
        sink.emit_many([json.dumps(record)])
    finally:
        sink.close()
    assert json.loads(json_path.read_text()) == record
    assert "\x1b" not in json_path.read_text() and "\x1b" not in capsys.readouterr().out
