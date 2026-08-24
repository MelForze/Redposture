from __future__ import annotations

import urllib.error
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.modules.consul import actions as consul
from redposture_core.modules.gitlab import actions as gitlab
from redposture_core.modules.grafana import actions as grafana
from redposture_core.modules.grpc import actions as grpc
from redposture_core.modules.kubeapi import actions as kubeapi
from redposture_core.modules.qdrant import actions as qdrant
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


def _ctx(
    state: Any,
    *,
    credential: AuditCredentialRun | None = None,
    port: int = 443,
    retries: int = 0,
    target_scheme: str | None = None,
    **arg_overrides: Any,
) -> AuditHookContext:
    args_data = {
        "timeout": 0.1,
        "retries": retries,
        "debug": False,
        "https": True,
        "insecure": False,
        "ca_file": None,
        "tls_ca": None,
        "workers": 2,
        "ssrf_capture": None,
    }
    args_data.update(arg_overrides)
    target = SimpleNamespace(scheme=target_scheme) if target_scheme is not None else None
    return AuditHookContext(
        args=SimpleNamespace(**args_data),
        logger=SimpleNamespace(),
        host="service.example",
        port=port,
        credential=credential or AuditCredentialRun(source="anonymous"),
        target=target,
        lifecycle_state=state,
    )


def _consul_options() -> dict[str, Any]:
    return {
        "do_ssrf": False,
        "ssrf_urls": [],
        "show_keys": False,
        "kv_key": None,
        "dump_requested": False,
        "dump_all_requested": False,
        "show_services": False,
        "show_agents": False,
        "show_checks": False,
        "check_dump_id": None,
        "show_nodes": False,
        "service_name": None,
        "service_dump_name": None,
        "agent_dump_name": None,
        "node_dump_name": None,
        "delete_service": False,
        "service_args": None,
        "revshell_enabled": False,
        "delete_revshell": False,
        "revshell_listen": False,
        "revshell_host": None,
        "revshell_port": None,
        "revshell_payload": None,
        "revshell_check_id": None,
        "dump_limit": None,
    }


def _grafana_options(*, check_urls: list[str] | None = None) -> dict[str, Any]:
    return {"show_datasources": True, "check_urls": list(check_urls or [])}


def _gitlab_options(
    *,
    project_filters: list[str] | None = None,
    clone: bool = False,
) -> dict[str, Any]:
    return {
        "project_filters": list(project_filters or []),
        "clone": clone,
        "clone_dir": "/tmp/gitlab-clones",
    }


def _kube_options(
    *,
    show_namespaces: bool = False,
    show_pods: bool = False,
    show_secrets: bool = False,
    namespace_filters: list[str] | None = None,
    exec_pod: str | None = None,
    exec_command: str | None = None,
) -> dict[str, Any]:
    return {
        "show_namespaces": show_namespaces,
        "show_pods": show_pods,
        "show_secrets": show_secrets,
        "namespace_filters": list(namespace_filters or []),
        "exec_pod": exec_pod,
        "exec_command": exec_command,
    }


def _qdrant_options(
    *,
    dump_requested: bool = False,
    dump_limit: int | None = None,
    collection_name: str | None = None,
    ssrf_urls: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "show_collections": True,
        "dump_requested": dump_requested,
        "dump_limit": dump_limit,
        "collection_name": collection_name,
        "ssrf_urls": list(ssrf_urls or []),
    }


def _grpc_options() -> dict[str, Any]:
    return {
        "analyze": False,
        "schema_descriptor_bytes": [],
        "invoke_path": None,
        "invoke_request_json": None,
        "metadata": [],
    }


def test_consul_detect_retries_transient_error_and_preserves_tls_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcomes = iter(
        [
            (False, None, False, False, None, "connection refused"),
            (True, "https", True, True, "10.0.0.1:8300", None),
        ]
    )
    sleeps: list[float] = []

    monkeypatch.setattr(consul, "_probe_consul_scheme", lambda *_args, **_kwargs: next(outcomes))
    monkeypatch.setattr(consul.time, "sleep", sleeps.append)
    monkeypatch.setattr(consul, "_consul_access_matrix", lambda *_args, **_kwargs: {"kv": {"ok": False}})
    monkeypatch.setattr(consul, "_agent_self_probe", lambda *_args, **_kwargs: {"ok": False})
    monkeypatch.setattr(
        consul,
        "_consul_lifecycle_call",
        lambda _ctx, _options, *, run_deep_checks: {
            "is_consul": True,
            "status": "auth_required",
            "deep": run_deep_checks,
        },
    )
    state = consul.ConsulLifecycleState()

    record = consul.detect_consul(
        _ctx(state, retries=1, target_scheme="https", port=8501),
        _consul_options(),
    )

    assert record["status"] == "auth_required"
    assert record["deep"] is False
    assert sleeps
    assert (state.scheme, state.insecure, state.tls_auto_insecure, state.leader) == (
        "https",
        True,
        True,
        "10.0.0.1:8300",
    )


def test_consul_non_service_stops_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    probes = 0

    def fake_probe(*_args: Any, **_kwargs: Any) -> tuple[bool, None, bool, bool, None, None]:
        nonlocal probes
        probes += 1
        return False, None, False, False, None, None

    monkeypatch.setattr(consul, "_probe_consul_scheme", fake_probe)
    state = consul.ConsulLifecycleState()

    record = consul.detect_consul(_ctx(state, retries=3, port=8500), _consul_options())

    assert probes == 1
    assert record["status"] == "not_consul"
    assert record["error"] == "not a Consul API"


def test_consul_anonymous_auth_and_data_are_replayed_once_then_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bool] = []

    def fake_lifecycle(_ctx: Any, _options: dict[str, Any], *, run_deep_checks: bool) -> dict[str, Any]:
        calls.append(run_deep_checks)
        return {"is_consul": True, "status": "open_no_auth", "deep": run_deep_checks}

    monkeypatch.setattr(consul, "_consul_lifecycle_call", fake_lifecycle)
    state = consul.ConsulLifecycleState(scheme="http")
    ctx = _ctx(state, port=8500)

    auth_record = consul.authenticate_consul(ctx, {}, _consul_options())
    first = consul.collect_consul_data(ctx, auth_record, _consul_options())
    second = consul.collect_consul_data(ctx, auth_record, _consul_options())

    assert calls == [False, True]
    assert first is second
    assert first["deep"] is True


def test_grafana_detect_distinguishes_non_service(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_http(_host: str, _port: int, path: str, _timeout: float, **_kwargs: Any):
        if path == "/api/health":
            return 200, '{"status":"ok"}', {}
        return 200, "<html>unrelated login</html>", {}

    monkeypatch.setattr(grafana, "_http_request", fake_http)

    record = grafana.detect_grafana(
        _ctx(grafana.GrafanaLifecycleState(), port=3000),
        _grafana_options(),
    )

    assert record["is_grafana"] is False
    assert record["status"] == "not_grafana"
    assert record["error"] == "service is not grafana"


def test_grafana_detect_retries_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = 0
    sleeps: list[float] = []

    def fail_http(*_args: Any, **_kwargs: Any):
        nonlocal requests
        requests += 1
        raise urllib.error.URLError("temporary outage")

    monkeypatch.setattr(grafana, "_http_request", fail_http)
    monkeypatch.setattr(grafana.time, "sleep", sleeps.append)

    record = grafana.detect_grafana(
        _ctx(grafana.GrafanaLifecycleState(), retries=1, port=3000),
        _grafana_options(),
    )

    assert requests == 2
    assert len(sleeps) == 1
    assert record["status"] == "fail"
    assert "temporary outage" in str(record["error"])


def test_grafana_invalid_token_keeps_anonymous_access_and_data_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = grafana.GrafanaLifecycleState()
    ctx = _ctx(
        state,
        port=3000,
        credential=AuditCredentialRun(token="bad-token", source="anonymous"),
    )
    datasource_calls = 0
    check_calls: list[str] = []

    monkeypatch.setattr(grafana, "_verify_apitoken", lambda *_args: (False, "denied"))

    def fake_datasources(*_args: Any, **_kwargs: Any):
        nonlocal datasource_calls
        datasource_calls += 1
        return None, "datasources forbidden", 403

    monkeypatch.setattr(grafana, "_fetch_datasources", fake_datasources)
    monkeypatch.setattr(
        grafana,
        "_run_temp_prometheus_check",
        lambda *_args: check_calls.append(str(_args[-1])) or {"probe_ok": False},
    )

    auth_record = grafana.authenticate_grafana(
        ctx,
        {"is_grafana": True, "status": "open_no_auth", "auth_required": False},
        _grafana_options(),
    )
    first = grafana.collect_grafana_data(
        ctx,
        auth_record,
        _grafana_options(check_urls=["http://internal.example/ready"]),
    )
    second = grafana.collect_grafana_data(
        ctx,
        auth_record,
        _grafana_options(check_urls=["http://ignored.example"]),
    )

    assert auth_record["status"] == "invalid_credentials_anonymous"
    assert auth_record["provided_credentials"] is True
    assert auth_record["error"] is None
    assert first is second
    assert datasource_calls == 1
    assert check_calls == ["http://internal.example/ready"]
    assert first["status"] == "auth_required"
    assert first["error"] == "datasources forbidden"


def test_grafana_failed_default_basic_auth_remains_auth_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grafana, "_verify_credentials", lambda *_args: (False, "invalid password"))
    state = grafana.GrafanaLifecycleState()
    ctx = _ctx(
        state,
        port=3000,
        credential=AuditCredentialRun(password="wrong", source="default"),
    )

    record = grafana.authenticate_grafana(
        ctx,
        {"is_grafana": True, "status": "auth_required", "auth_required": True},
        _grafana_options(),
    )

    assert record["status"] == "auth_required"
    assert record["provided_credentials"] is False
    assert record["provided_credentials_ok"] is None
    assert record["defcreds_enabled"] is True
    assert record["error"] == "invalid password"
    assert state.auth_header is None


def test_grafana_successful_default_basic_auth_is_weak_default_creds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grafana, "_verify_credentials", lambda *_args: (True, None))
    state = grafana.GrafanaLifecycleState()
    ctx = _ctx(
        state,
        port=3000,
        credential=AuditCredentialRun(username="admin", password="admin", source="default"),
    )

    record = grafana.authenticate_grafana(
        ctx,
        {"is_grafana": True, "status": "auth_required", "auth_required": True},
        _grafana_options(),
    )

    assert record["status"] == "weak_default_creds"
    assert record["credentials_source"] == "default"
    assert record["default_credentials"] is True
    assert record["provided_credentials"] is False
    assert record["provided_credentials_ok"] is None
    assert state.credentials_source == "default"


def test_gitlab_detect_handles_malformed_version_json_via_login_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_http(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: Any):
        if path == "/users/sign_in":
            return 200, b"<title>GitLab</title> Sign in", {}, None
        return 200, b"{malformed", {}, None

    monkeypatch.setattr(gitlab, "_http_request", fake_http)

    record = gitlab.detect_gitlab(
        _ctx(gitlab.GitLabLifecycleState(), port=443, target_scheme="https"),
        _gitlab_options(),
    )

    assert record["is_gitlab"] is True
    assert record["https"] is True
    assert record["login_page"] is True
    assert record["version"] is None


def test_gitlab_detect_non_service_and_retryable_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unrelated(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: Any):
        payload = b"<html>other product</html>" if path == "/users/sign_in" else b"{}"
        return 200, payload, {}, None

    monkeypatch.setattr(gitlab, "_http_request", unrelated)
    not_gitlab = gitlab.detect_gitlab(
        _ctx(gitlab.GitLabLifecycleState(), retries=2, port=80, target_scheme="http"),
        _gitlab_options(),
    )
    assert not_gitlab["status"] == "not_gitlab"

    sleeps: list[float] = []
    request_count = 0

    def unavailable(*_args: Any, **_kwargs: Any):
        nonlocal request_count
        request_count += 1
        return 0, b"", {}, "connection refused"

    monkeypatch.setattr(gitlab, "_http_request", unavailable)
    monkeypatch.setattr(gitlab.time, "sleep", sleeps.append)
    failed = gitlab.detect_gitlab(
        _ctx(gitlab.GitLabLifecycleState(), retries=1, port=80),
        _gitlab_options(),
    )

    assert request_count == 4
    assert len(sleeps) == 1
    assert failed["status"] == "fail"
    assert "connection refused" in str(failed["error"])


def test_gitlab_anonymous_data_discovers_public_endpoints_and_is_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[str] = []
    paginations = 0

    def fake_http(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: Any):
        requests.append(path)
        if path == "/-/liveness":
            return 503, b"", {}, None
        return 200, b"", {}, None

    def fake_paginate(*_args: Any, **_kwargs: Any):
        nonlocal paginations
        paginations += 1
        return [
            {"id": 1, "path_with_namespace": "public/keep"},
            {"id": 2, "path_with_namespace": "private/drop"},
        ], None

    monkeypatch.setattr(gitlab, "_http_request", fake_http)
    monkeypatch.setattr(gitlab, "_paginate_projects", fake_paginate)
    state = gitlab.GitLabLifecycleState()
    ctx = _ctx(state, port=80)
    options = _gitlab_options(project_filters=["public/keep"])

    first = gitlab.collect_gitlab_data(
        ctx,
        {"is_gitlab": True, "status": "detected", "https": False, "version": "17.0"},
        options,
    )
    second = gitlab.collect_gitlab_data(ctx, {}, options)

    assert first is second
    assert paginations == 1
    assert requests == list(gitlab._PUBLIC_ENDPOINT_PATHS[1:])
    assert first["public_projects"] == [{"id": 1, "path_with_namespace": "public/keep"}]
    paths = {item["path"] for item in first["open_endpoints"]}
    assert "/api/v4/version" in paths
    assert "/-/liveness" not in paths
    assert "/api/v4/projects?visibility=public" in paths


def test_gitlab_valid_token_collects_capabilities_in_stable_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public = [{"id": 9, "path_with_namespace": "public/demo"}]
    token_projects = [
        {"id": 2, "path_with_namespace": "team/zeta"},
        {"id": 1, "path_with_namespace": "team/alpha"},
    ]
    paginated_tokens: list[str | None] = []

    def fake_paginate(*_args: Any, token: str | None, **_kwargs: Any):
        paginated_tokens.append(token)
        return (token_projects, None) if token else (public, None)

    monkeypatch.setattr(gitlab, "_paginate_projects", fake_paginate)
    monkeypatch.setattr(
        gitlab,
        "_probe_project_capabilities",
        lambda *_args, project, **_kwargs: {
            "path_with_namespace": project["path_with_namespace"],
            "repo_read": True,
        },
    )
    state = gitlab.GitLabLifecycleState(token_valid=True)
    ctx = _ctx(
        state,
        port=443,
        credential=AuditCredentialRun(token="valid", source="provided"),
        workers=2,
    )

    record = gitlab.collect_gitlab_data(
        ctx,
        {"is_gitlab": True, "status": "valid_credentials", "https": True},
        _gitlab_options(),
    )

    assert paginated_tokens == [None, "valid"]
    assert record["token_projects"] == token_projects
    assert [item["path_with_namespace"] for item in record["token_access"]] == [
        "team/alpha",
        "team/zeta",
    ]


def test_gitlab_public_clone_resolves_filters_and_records_lookup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gitlab, "_paginate_projects", lambda *_args, **_kwargs: ([], None))

    def fake_fetch(*_args: Any, project_ref: str, **_kwargs: Any):
        if project_ref == "team/found":
            return {"id": 7, "path_with_namespace": project_ref}, None
        return None, "project not found"

    monkeypatch.setattr(gitlab, "_fetch_project_by_ref", fake_fetch)
    monkeypatch.setattr(
        gitlab,
        "_clone_project",
        lambda project, *_args, **_kwargs: {
            "project": project["path_with_namespace"],
            "status": "cloned",
        },
    )
    state = gitlab.GitLabLifecycleState(token_valid=False, token_error="invalid token")
    ctx = _ctx(
        state,
        port=80,
        credential=AuditCredentialRun(token="bad", source="provided"),
    )

    record = gitlab.collect_gitlab_data(
        ctx,
        {"is_gitlab": True, "status": "invalid_credentials", "https": False},
        _gitlab_options(project_filters=["team/found", "team/missing"], clone=True),
    )

    assert record["clone_scope"] == "public"
    assert {item["project"]: item["status"] for item in record["clone_results"]} == {
        "team/found": "cloned",
        "team/missing": "failed",
    }


def test_kubeapi_detect_retries_with_insecure_tls_after_verify_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, bool]] = []

    def fake_api(_host: str, _port: int, path: str, _timeout: float, *, insecure: bool, **_kwargs: Any):
        calls.append((path, insecure))
        if not insecure:
            return 0, None, {}, "certificate verify failed: self signed certificate"
        if path == "/version":
            return 200, {"major": "1", "minor": "31", "gitVersion": "v1.31.0"}, {}, None
        return 200, {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]}, {}, None

    monkeypatch.setattr(kubeapi, "_api_get_json", fake_api)
    monkeypatch.setattr(kubeapi, "_list_namespaces", lambda *_args, **_kwargs: (None, 403, "Forbidden"))
    state = kubeapi.KubeApiLifecycleState()

    record = kubeapi.detect_kubeapi(
        _ctx(state, port=6443, target_scheme="https", ca_file="/tmp/ca.pem"),
        _kube_options(show_namespaces=True),
    )

    assert calls == [("/version", False), ("/version", True)]
    assert record["status"] == "anonymous_limited"
    assert record["anonymous_access"] == "limited"
    assert record["version"] == "v1.31.0"
    assert record["tls_auto_insecure"] is True
    assert record["insecure_effective"] is True
    assert state.ca_file == "/tmp/ca.pem"


def test_kubeapi_transient_failure_retries_then_classifies_non_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    sleeps: list[float] = []

    def fake_api(*_args: Any, **_kwargs: Any):
        nonlocal calls
        calls += 1
        if calls <= 2:
            return 0, None, {}, "connection refused"
        return 200, {"product": "unrelated"}, {}, None

    monkeypatch.setattr(kubeapi, "_api_get_json", fake_api)
    monkeypatch.setattr(kubeapi.time, "sleep", sleeps.append)

    record = kubeapi.detect_kubeapi(
        _ctx(kubeapi.KubeApiLifecycleState(), retries=1, port=8080, target_scheme="http"),
        _kube_options(),
    )

    # /version consumes its two transport attempts, then /api is still
    # checked once because an endpoint-local failure is not a service verdict.
    assert calls == 3
    assert len(sleeps) == 1
    assert record["status"] == "fail"
    assert record["error"] == "connection refused"


@pytest.mark.parametrize(
    ("version_status", "version_payload", "api_payload"),
    [
        (
            404,
            {"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404},
            {"versions": ["2024-01"]},
        ),
        (200, {"gitVersion": "v1.31.0"}, {"kind": "APIGroupList", "apiVersion": "v1"}),
        (200, {"apiVersion": "v1beta1"}, {"kind": "NamespaceList", "apiVersion": "v1"}),
    ],
)
def test_kubeapi_rejects_generic_kubernetes_looking_payloads(
    monkeypatch: pytest.MonkeyPatch,
    version_status: int,
    version_payload: dict[str, Any],
    api_payload: dict[str, Any],
) -> None:
    calls: list[str] = []

    def fake_api(_host: str, _port: int, path: str, _timeout: float, **_kwargs: Any):
        calls.append(path)
        return (version_status, version_payload, {}, None) if path == "/version" else (200, api_payload, {}, None)

    monkeypatch.setattr(kubeapi, "_api_get_json", fake_api)
    monkeypatch.setattr(
        kubeapi,
        "_probe_namespace_access",
        lambda *_args, **_kwargs: pytest.fail("false positive must not reach auth probe"),
    )

    record = kubeapi.detect_kubeapi(
        _ctx(kubeapi.KubeApiLifecycleState(), port=8080, target_scheme="http"),
        _kube_options(),
    )

    assert calls == ["/version", "/api"]
    assert record["status"] == "not_kubeapi"
    assert record["is_kubeapi"] is False


def test_kubeapi_correlated_auth_status_confirms_service_without_deep_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_api(_host: str, _port: int, path: str, _timeout: float, **_kwargs: Any):
        calls.append(path)
        status = 401
        reason = "Unauthorized"
        return (
            status,
            {
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Failure",
                "reason": reason,
                "code": status,
            },
            {},
            None,
        )

    monkeypatch.setattr(kubeapi, "_api_get_json", fake_api)
    monkeypatch.setattr(
        kubeapi,
        "_probe_namespace_access",
        lambda *_args, **_kwargs: pytest.fail("correlated auth status already classified access"),
    )

    record = kubeapi.detect_kubeapi(
        _ctx(kubeapi.KubeApiLifecycleState(), port=6443, target_scheme="https", insecure=True),
        _kube_options(show_namespaces=True, show_pods=True),
    )

    assert calls == ["/version", "/api"]
    assert record["status"] == "auth_required"
    assert record["auth_required"] is True


def test_kubeapi_mixed_auth_status_pair_is_a_service_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_api(_host: str, _port: int, path: str, _timeout: float, **_kwargs: Any):
        status = 401 if path == "/version" else 403
        reason = "Unauthorized" if status == 401 else "Forbidden"
        return (
            status,
            {
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Failure",
                "reason": reason,
                "code": status,
            },
            {},
            None,
        )

    monkeypatch.setattr(kubeapi, "_api_get_json", fake_api)
    record = kubeapi.detect_kubeapi(
        _ctx(kubeapi.KubeApiLifecycleState(), port=6443, target_scheme="https", insecure=True),
        _kube_options(),
    )

    assert record["is_kubeapi"] is True
    assert record["status"] == "anonymous_limited"


def test_kubeapi_namespace_probe_is_one_bounded_page_and_clients_are_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths: list[str] = []

    def fake_api(_host: str, _port: int, path: str, _timeout: float, **_kwargs: Any):
        paths.append(path)
        return (
            200,
            {
                "items": [{"metadata": {"name": "default"}}],
                "metadata": {"continue": "next-page"},
            },
            {},
            None,
        )

    monkeypatch.setattr(kubeapi, "_api_get_json", fake_api)
    access, status, error = kubeapi._probe_namespace_access(
        "127.0.0.1",
        6443,
        0.1,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert access is True
    assert status == 200
    assert error is None
    assert paths == ["/api/v1/namespaces?limit=1"]

    state = kubeapi.KubeApiLifecycleState(use_https=False)
    state.configure_transport("127.0.0.1", 6443, 0.1)
    assert state.http_client(response_size_cap=1024) is state.http_client(response_size_cap=1024)
    assert state.http_client(response_size_cap=1024) is state.http_client(response_size_cap=2048)


def test_kubeapi_invalid_token_falls_back_to_anonymous_data_and_caches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = kubeapi.KubeApiLifecycleState(
        use_https=True,
        anonymous_namespaces=["public"],
        access_namespaces=["public"],
    )
    ctx = _ctx(
        state,
        port=6443,
        credential=AuditCredentialRun(token="bad-token", source="provided"),
    )
    auth_seen: list[tuple[str | None, str | None, str | None]] = []

    def fake_namespaces(*_args: Any, token=None, **_kwargs: Any):
        if token:
            return None, 403, "Forbidden"
        return ["public"], 200, None

    monkeypatch.setattr(kubeapi, "_list_namespaces", fake_namespaces)
    monkeypatch.setattr(
        kubeapi,
        "_verify_self_subject_review",
        lambda *_args, **_kwargs: (None, None, "verification unavailable"),
    )

    def fake_pods(*_args: Any, token=None, username=None, password=None, **_kwargs: Any):
        auth_seen.append((token, username, password))
        return [{"namespace": "public", "name": "pod-a"}], None

    def fake_secrets(*_args: Any, token=None, username=None, password=None, **_kwargs: Any):
        auth_seen.append((token, username, password))
        return [{"namespace": "public", "name": "secret-a"}], None

    monkeypatch.setattr(kubeapi, "_list_pods", fake_pods)
    monkeypatch.setattr(kubeapi, "_list_secrets", fake_secrets)
    monkeypatch.setattr(
        kubeapi,
        "_resolve_exec_pod_target",
        lambda *_args: (None, None, "pod selector is ambiguous"),
    )
    options = _kube_options(
        show_namespaces=True,
        show_pods=True,
        show_secrets=True,
        exec_pod="pod-a",
        exec_command="id",
    )

    auth_record = kubeapi.authenticate_kubeapi(
        ctx,
        {"is_kubeapi": True, "status": "open_no_auth", "auth_required": False},
        options,
    )
    first = kubeapi.collect_kubeapi_data(ctx, auth_record, options)
    second = kubeapi.collect_kubeapi_data(ctx, auth_record, options)

    assert auth_record["status"] == "auth_unverified_anonymous"
    assert auth_seen == [(None, None, None), (None, None, None)]
    assert first is second
    assert first["namespaces"] == ["public"]
    assert first["can_list_pods"] is True
    assert first["can_list_secrets"] is True
    assert first["can_exec_pod"] is False
    assert first["exec_result"]["error"] == "pod selector is ambiguous"


def test_kubeapi_exec_uses_selected_authenticated_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = kubeapi.KubeApiLifecycleState(
        use_https=True,
        insecure=True,
        ca_file="/tmp/ca.pem",
        access_namespaces=["team"],
        token="valid",
    )
    ctx = _ctx(
        state,
        port=6443,
        credential=AuditCredentialRun(token="valid", source="provided"),
    )
    exec_kwargs: dict[str, Any] = {}

    monkeypatch.setattr(kubeapi, "_resolve_exec_pod_target", lambda *_args: ("team", "api-0", None))

    def fake_exec(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        exec_kwargs.update(kwargs)
        return {"ok": True, "stdout": "uid=0", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(kubeapi, "_kube_exec_ws", fake_exec)
    record = kubeapi.collect_kubeapi_data(
        ctx,
        {"is_kubeapi": True, "status": "auth_valid"},
        _kube_options(
            namespace_filters=["team"],
            exec_pod="api-0",
            exec_command="id",
        ),
    )

    assert record["can_exec_pod"] is True
    assert record["exec_result"]["stdout"] == "uid=0"
    assert exec_kwargs == {
        "use_https": True,
        "insecure": True,
        "ca_file": "/tmp/ca.pem",
        "token": "valid",
        "username": None,
        "password": None,
        "retries": 0,
    }


def test_qdrant_detect_retries_then_rejects_unrelated_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_calls = 0
    collection_calls = 0
    sleeps: list[float] = []

    def fake_root(*_args: Any, **_kwargs: Any):
        nonlocal root_calls
        root_calls += 1
        if root_calls == 1:
            return 0, None, "connection refused"
        return 200, {"product": "other"}, None

    def fake_collections(*_args: Any, **_kwargs: Any):
        nonlocal collection_calls
        collection_calls += 1
        if collection_calls == 1:
            return 0, None, "connection refused"
        return 200, {"items": []}, None

    monkeypatch.setattr(qdrant, "_qdrant_get_root_info", fake_root)
    monkeypatch.setattr(qdrant, "_qdrant_get_collections", fake_collections)
    monkeypatch.setattr(qdrant.time, "sleep", sleeps.append)
    state = qdrant.QdrantLifecycleState()

    record = qdrant.detect_qdrant(
        _ctx(state, retries=1, port=6333),
        _qdrant_options(),
    )

    assert (root_calls, collection_calls, len(sleeps)) == (2, 2, 1)
    assert record["is_qdrant"] is False
    assert record["error"] == "service is not qdrant"
    assert state.detect_record == record


def test_qdrant_detect_represents_uncertain_auth_without_false_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        qdrant,
        "_qdrant_get_root_info",
        lambda *_args, **_kwargs: (200, {"title": "qdrant", "version": "1.14.0"}, None),
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_get_collections",
        lambda *_args, **_kwargs: (500, {"status": {"error": "temporary failure"}}, None),
    )

    record = qdrant.detect_qdrant(
        _ctx(qdrant.QdrantLifecycleState(), port=6333),
        _qdrant_options(),
    )

    assert record["is_qdrant"] is True
    assert record["status"] == "unknown_auth"
    assert record["anonymous_access"] is None
    assert "temporary failure" in str(record["collections_list_error"])


@pytest.mark.parametrize(
    ("anonymous_access", "expected_status"),
    [(False, "auth_required"), (True, "open_no_auth")],
)
def test_qdrant_invalid_api_key_does_not_erase_public_access(
    monkeypatch: pytest.MonkeyPatch,
    anonymous_access: bool,
    expected_status: str,
) -> None:
    monkeypatch.setattr(
        qdrant,
        "_qdrant_get_collections",
        lambda *_args, **_kwargs: (403, {"status": {"error": "forbidden"}}, None),
    )
    state = qdrant.QdrantLifecycleState(action_source="anonymous" if anonymous_access else None)
    ctx = _ctx(
        state,
        port=6333,
        credential=AuditCredentialRun(token="invalid", source="provided"),
    )

    record = qdrant.authenticate_qdrant(
        ctx,
        {
            "is_qdrant": True,
            "status": "open_no_auth" if anonymous_access else "auth_required",
            "anonymous_access": anonymous_access,
        },
        _qdrant_options(),
    )

    assert record["status"] == expected_status
    assert record["api_key_access"] is False
    assert state.action_headers is None


def test_qdrant_missing_collection_reports_dump_and_ssrf_errors_with_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = qdrant.QdrantLifecycleState()
    capture = {"started": True, "hits": [{"method": "GET", "path": "/snapshot"}, "ignored"]}
    ctx = _ctx(
        state,
        port=6333,
        credential=AuditCredentialRun(token="invalid", source="provided"),
        ssrf_capture=capture,
    )
    logger_calls = 0

    def fake_logger(*_args: Any, **_kwargs: Any):
        nonlocal logger_calls
        logger_calls += 1
        return {"ok": False, "status": 404, "error": None}

    monkeypatch.setattr(qdrant, "_qdrant_logger_endpoint_probe", fake_logger)
    options = _qdrant_options(
        dump_requested=True,
        collection_name=None,
        ssrf_urls=["http://listener.example/snapshot"],
    )

    first = qdrant.collect_qdrant_data(
        ctx,
        {"is_qdrant": True, "status": "auth_required", "collections": None},
        options,
    )
    second = qdrant.collect_qdrant_data(ctx, {}, options)

    assert first is second
    assert logger_calls == 1
    assert first["collection_dump_items"] == []
    assert first["collection_dump_error"] == "authentication required for collection dump"
    assert first["ssrf_error"].startswith("--collection is required")
    assert first["ssrf_listener_started"] is True
    assert first["ssrf_hit_count"] == 1
    assert first["ssrf_hits"] == [{"method": "GET", "path": "/snapshot"}]


def test_qdrant_deep_actions_use_selected_key_and_limit_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = {"api-key": "valid"}
    state = qdrant.QdrantLifecycleState(action_headers=headers, action_source="api_key")
    ctx = _ctx(
        state,
        port=6333,
        credential=AuditCredentialRun(token="valid", source="provided"),
    )
    info_calls: list[tuple[str, dict[str, str] | None]] = []

    def fake_info(_host: str, _port: int, _timeout: float, name: str, *, headers=None):
        info_calls.append((name, headers))
        return 500, {"status": {"error": "collection unavailable"}}, None

    monkeypatch.setattr(qdrant, "_qdrant_get_collection_info", fake_info)
    monkeypatch.setattr(qdrant, "_qdrant_edit_probe_empty_patch", lambda *_args, **_kwargs: {"ok": True})
    monkeypatch.setattr(
        qdrant,
        "_qdrant_logger_endpoint_probe",
        lambda *_args, **_kwargs: {"ok": False, "status": 404, "error": None},
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_ssrf_snapshot_recover_probe",
        lambda *_args, **_kwargs: {"ok": True, "status": 200},
    )

    record = qdrant.collect_qdrant_data(
        ctx,
        {
            "is_qdrant": True,
            "status": "open_auth",
            "version": "1.14.0",
            "collections": ["alpha", "beta"],
        },
        _qdrant_options(
            dump_requested=True,
            dump_limit=1,
            collection_name="alpha",
            ssrf_urls=["http://listener.example/snapshot"],
        ),
    )

    assert info_calls == [("alpha", headers)]
    assert record["collection_dump_items"][0]["ok"] is False
    assert "collection unavailable" in str(record["collection_dump_items"][0]["error"])
    assert record["edit_probe"]["source"] == "api_key"
    assert record["ssrf_results"] == [{"ok": True, "status": 200}]


def test_grpc_detect_retries_retryable_failure_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcomes = iter(
        [
            {"status": "fail", "is_grpc": False, "detect_error": "connection refused"},
            {
                "status": "detected",
                "is_grpc": True,
                "detect_error": None,
                "transport_mode": "tls",
            },
        ]
    )
    sleeps: list[float] = []

    monkeypatch.setattr(grpc, "_detect_grpc_target", lambda *_args, **_kwargs: next(outcomes))
    monkeypatch.setattr(grpc.time, "sleep", sleeps.append)
    monkeypatch.setattr(
        grpc,
        "_grpc_lifecycle_audit",
        lambda ctx, _options, *, run_deep_checks: {
            "status": ctx.lifecycle_state.detect_result["status"],
            "deep": run_deep_checks,
        },
    )
    state = grpc.GrpcLifecycleState()

    record = grpc.detect_grpc(
        _ctx(state, retries=1, port=50051, target_scheme="https"),
        _grpc_options(),
    )

    assert len(sleeps) == 1
    assert state.detect_result["transport_mode"] == "tls"
    assert record == {"status": "detected", "deep": False}


def test_grpc_lifecycle_reuses_one_native_h2_session_and_closes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_sessions: list[Any] = []

    def remember(session: Any) -> None:
        assert session is not None
        observed_sessions.append(session)

    def fake_health(*_args: Any, session: Any = None, service_name: str = "", **_kwargs: Any) -> dict[str, Any]:
        remember(session)
        return {
            "call": {"is_grpc": True, "transport_ok": True, "http_status": 200},
            "grpc_status": 0,
            "grpc_status_name": "OK",
            "serving_status": "SERVING",
            "health_supported": True,
            "service": service_name,
            "error": None,
        }

    def fake_capability(*_args: Any, session: Any = None, **_kwargs: Any) -> dict[str, Any]:
        remember(session)
        return {
            "call": {"is_grpc": True, "transport_ok": True, "http_status": 200},
            "grpc_status": 0,
            "reflection_enabled": True,
            "reflection_version": "v1",
            "error": None,
        }

    def fake_list(*_args: Any, session: Any = None, **_kwargs: Any) -> dict[str, Any]:
        remember(session)
        return {
            "call": {"is_grpc": True},
            "grpc_status": 0,
            "reflection_enabled": True,
            "reflection_version": "v1",
            "services": ["grpc.health.v1.Health"],
            "error": None,
        }

    def fake_descriptors(*_args: Any, session: Any = None, **_kwargs: Any) -> dict[str, Any]:
        remember(session)
        return {
            "call": {"is_grpc": True},
            "grpc_status": 0,
            "descriptor_bytes": [grpc.grpc_health_pb2.DESCRIPTOR.serialized_pb],
            "error": None,
        }

    def fake_invoke(*_args: Any, session: Any = None, **_kwargs: Any) -> dict[str, Any]:
        remember(session)
        return {"status": "ok", "grpc_status": 0, "grpc_status_name": "OK"}

    monkeypatch.setattr(grpc, "_health_check_call", fake_health)
    monkeypatch.setattr(grpc, "_reflection_capability_call", fake_capability)
    monkeypatch.setattr(grpc, "_reflection_list_services_call", fake_list)
    monkeypatch.setattr(grpc, "_reflection_file_descriptors_call", fake_descriptors)
    monkeypatch.setattr(grpc, "_invoke_unary_method", fake_invoke)

    state = grpc.GrpcLifecycleState()
    detected = grpc._detect_grpc_target(
        "service.example",
        50051,
        timeout=0.1,
        preferred_scheme="http",
        _session_state=state,
    )
    record = grpc._audit_grpc_host(
        "service.example",
        50051,
        0.1,
        0,
        token=None,
        username=None,
        password=None,
        defcreds=False,
        preferred_scheme="http",
        run_deep_checks=True,
        analyze=True,
        invoke_path="/grpc.health.v1.Health/Check",
        invoke_request_json={"service": ""},
        _lifecycle_detect_result=detected,
        _session_state=state,
    )

    assert record["invoke_access"] == "anonymous"
    assert len(observed_sessions) >= 6
    assert all(session is observed_sessions[0] for session in observed_sessions)
    selected_session = observed_sessions[0]
    state.close()
    assert state.sessions == {}
    assert selected_session._closed is True


@pytest.mark.parametrize("credential_source", ["default", "defcreds"])
def test_grpc_default_credential_relabels_auth_source_and_status(
    monkeypatch: pytest.MonkeyPatch,
    credential_source: str,
) -> None:
    captured: dict[str, Any] = {}

    def fake_audit(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"status": "valid_credentials", "auth_used": {"source": "provided"}}

    monkeypatch.setattr(grpc, "_audit_grpc_host", fake_audit)
    state = grpc.GrpcLifecycleState(detect_result={"status": "detected", "is_grpc": True})
    ctx = _ctx(
        state,
        port=50051,
        target_scheme="https",
        credential=AuditCredentialRun(token="default-token", source=credential_source),
    )

    record = grpc._grpc_lifecycle_audit(ctx, _grpc_options(), run_deep_checks=True)

    assert captured["defcreds"] is False
    assert captured["preferred_scheme"] == "https"
    assert captured["_lifecycle_detect_result"] is state.detect_result
    assert captured["_session_state"] is state
    assert record["status"] == "weak_default_creds"
    assert record["defcreds_used"] is True
    assert record["auth_used"]["source"] == "defcreds"


def test_grpc_auth_result_is_cached_per_credential_and_data_has_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str | None, bool]] = []

    def fake_audit(ctx: Any, _options: dict[str, Any], *, run_deep_checks: bool) -> dict[str, Any]:
        calls.append((ctx.credential.token, run_deep_checks))
        return {"status": "valid_credentials", "token": ctx.credential.token}

    monkeypatch.setattr(grpc, "_grpc_lifecycle_audit", fake_audit)
    state = grpc.GrpcLifecycleState(detect_result={"status": "detected", "is_grpc": True})
    first_ctx = _ctx(
        state,
        port=50051,
        credential=AuditCredentialRun(token="first", source="provided"),
    )
    second_ctx = _ctx(
        state,
        port=50051,
        credential=AuditCredentialRun(token="second", source="provided"),
    )

    auth_record = grpc.authenticate_grpc(first_ctx, {}, _grpc_options())
    cached = grpc.collect_grpc_data(first_ctx, {}, _grpc_options())
    fallback = grpc.collect_grpc_data(second_ctx, {}, _grpc_options())

    assert cached is auth_record
    assert fallback["token"] == "second"
    assert calls == [("first", False), ("second", False)]
