from __future__ import annotations

from typing import Any

import pytest

import redposture_core.stage_consul as consul
import redposture_core.stage_gitlab as gitlab
import redposture_core.stage_grafana as grafana
import redposture_core.stage_grpc as grpc
import redposture_core.stage_kubeapi as kubeapi
import redposture_core.stage_qdrant as qdrant
from redposture_core.cli_args import parse_args
from redposture_core.stage_runtime import AuditCommandRunner


def _run(module: Any, name: str, args: Any):
    runner = AuditCommandRunner(
        args=args,
        spec=getattr(module, f"build_{name}_spec")(args),
        emit_line=lambda _line: None,
    )
    return runner.run_plan(getattr(module, f"build_{name}_plan")(args))


def test_grafana_credential_file_classifies_anonymously_then_stops_on_first_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    credentials = tmp_path / "grafana.creds"
    credentials.write_text("bad:bad\ngood:good\n", encoding="utf-8")
    events: list[tuple[str, str | None]] = []

    def fake_http(_host, _port, path, _timeout, *, headers=None, method="GET", data=None):
        _ = (method, data)
        authorization = (headers or {}).get("Authorization")
        events.append((path, authorization))
        if path == "/api/health":
            return 401, "", {}
        if path == "/login":
            return 200, "<title>Grafana</title>", {}
        if path == "/api/user":
            return (200, "{}", {}) if authorization == grafana._auth_header("good", "good") else (401, "", {})
        if path == "/api/datasources":
            return 200, "[]", {}
        raise AssertionError(path)

    monkeypatch.setattr(grafana, "_http_request", fake_http)
    args = parse_args(["grafana", "-t", "127.0.0.1", "--port", "3000", "-u", str(credentials), "--format", "json"])
    result = _run(grafana, "grafana", args)

    assert events == [
        ("/api/health", None),
        ("/login", None),
        ("/api/user", grafana._auth_header("bad", "bad")),
        ("/api/user", grafana._auth_header("good", "good")),
        ("/api/datasources", grafana._auth_header("good", "good")),
    ]
    assert result.records[0]["status"] == "valid_credentials"


def test_grafana_defcreds_are_explicit_ordered_runs_not_an_internal_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_headers: list[str] = []

    def fake_http(_host, _port, path, _timeout, *, headers=None, **_kwargs):
        authorization = (headers or {}).get("Authorization")
        if path == "/api/health":
            return 401, "", {}
        if path == "/login":
            return 200, "Grafana login", {}
        if path == "/api/user":
            auth_headers.append(authorization)
            return (200, "{}", {}) if authorization == grafana._auth_header("admin", "admin") else (401, "", {})
        if path == "/api/datasources":
            return 200, "[]", {}
        raise AssertionError(path)

    monkeypatch.setattr(grafana, "_http_request", fake_http)
    args = parse_args(
        [
            "grafana",
            "-t",
            "127.0.0.1",
            "--port",
            "3000",
            "-u",
            "operator",
            "-p",
            "wrong",
            "--defcreds",
            "--format",
            "json",
        ]
    )
    plan = grafana.build_grafana_plan(args)
    runner = AuditCommandRunner(args=args, spec=grafana.build_grafana_spec(args), emit_line=lambda _line: None)
    result = runner.run_plan(plan)

    assert [run.source for run in plan.credential_runs] == ["provided", "default"]
    assert auth_headers == [
        grafana._auth_header("operator", "wrong"),
        grafana._auth_header("admin", "admin"),
    ]
    assert result.records[0]["credentials_source"] == "default"
    assert result.records[0]["datasource_count"] == 0


def test_kubeapi_credential_file_reuses_anonymous_classification_and_selected_namespace_probe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    credentials = tmp_path / "kube.creds"
    credentials.write_text("bad:bad\ngood:good\n", encoding="utf-8")
    classification: list[str] = []
    namespace_auth: list[tuple[str | None, str | None, str | None]] = []

    def fake_api(_host, _port, path, _timeout, **_kwargs):
        classification.append(path)
        if path == "/version":
            return 200, {"gitVersion": "v1.30.0"}, {}, None
        return 200, {"versions": ["v1"]}, {}, None

    def fake_namespaces(
        _host,
        _port,
        _timeout,
        *,
        token=None,
        username=None,
        password=None,
        **_kwargs,
    ):
        namespace_auth.append((token, username, password))
        if username == "good":
            return ["default"], 200, None
        return None, 403, "Forbidden"

    monkeypatch.setattr(kubeapi, "_api_get_json", fake_api)
    monkeypatch.setattr(kubeapi, "_list_namespaces", fake_namespaces)
    args = parse_args(
        [
            "kubeapi",
            "-t",
            "127.0.0.1",
            "--port",
            "6443",
            "-u",
            str(credentials),
            "--namespaces",
            "--format",
            "json",
        ]
    )
    result = _run(kubeapi, "kubeapi", args)

    assert classification == ["/version", "/api"]
    assert namespace_auth == [(None, None, None), (None, "bad", "bad"), (None, "good", "good")]
    assert result.records[0]["status"] == "auth_valid"
    assert result.records[0]["namespaces"] == ["default"]


def test_gitlab_invalid_token_runs_public_data_once_without_reclassification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, str | None]] = []
    paginations: list[str | None] = []

    def fake_http(_host, _port, _method, path, _timeout, *, headers=None, **_kwargs):
        token = (headers or {}).get("PRIVATE-TOKEN")
        requests.append((path, token))
        if path == "/users/sign_in":
            return 200, b"GitLab users/sign_in", {}, None
        if path == "/api/v4/version":
            return 200, b'{"version":"17.0.0"}', {}, None
        if path == "/api/v4/user":
            return 401, b"", {}, None
        return 200, b"", {}, None

    def fake_paginate(_host, _port, _timeout, *, token, **_kwargs):
        paginations.append(token)
        return ([{"id": 1, "path_with_namespace": "public/demo"}], None) if token is None else ([], None)

    monkeypatch.setattr(gitlab, "_http_request", fake_http)
    monkeypatch.setattr(gitlab, "_paginate_projects", fake_paginate)
    args = parse_args(["gitlab", "-t", "127.0.0.1", "--port", "80", "--token", "invalid", "--format", "json"])
    result = _run(gitlab, "gitlab", args)

    assert [path for path, _token in requests].count("/users/sign_in") == 1
    assert [path for path, _token in requests].count("/api/v4/version") == 1
    assert ("/api/v4/user", "invalid") in requests
    assert paginations == [None]
    assert result.records[0]["status"] == "invalid_credentials"
    assert result.records[0]["public_projects"][0]["path_with_namespace"] == "public/demo"


def test_qdrant_api_key_auth_does_not_repeat_root_or_anonymous_collections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots = 0
    collection_headers: list[dict[str, str] | None] = []
    logger_calls = 0

    def fake_root(*_args, **_kwargs):
        nonlocal roots
        roots += 1
        return 200, {"title": "qdrant", "version": "1.14.0"}, None

    def fake_collections(*_args, headers=None, **_kwargs):
        collection_headers.append(headers)
        if headers == {"api-key": "valid"}:
            return 200, {"result": {"collections": []}}, None
        return 401, {"status": {"error": "forbidden"}}, None

    def fake_logger(*_args, **_kwargs):
        nonlocal logger_calls
        logger_calls += 1
        return {"ok": False, "status": 404, "error": None}

    monkeypatch.setattr(qdrant, "_qdrant_get_root_info", fake_root)
    monkeypatch.setattr(qdrant, "_qdrant_get_collections", fake_collections)
    monkeypatch.setattr(qdrant, "_qdrant_logger_endpoint_probe", fake_logger)
    args = parse_args(["qdrant", "-t", "127.0.0.1", "--port", "6333", "--api-key", "valid", "--format", "json"])
    result = _run(qdrant, "qdrant", args)

    assert roots == 1
    assert collection_headers == [None, {"api-key": "valid"}]
    assert logger_calls == 1
    assert result.records[0]["status"] == "open_auth"


def test_consul_token_auth_replays_detection_and_runs_no_action_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probes = 0
    matrix_headers: list[dict[str, str] | None] = []
    self_headers: list[dict[str, str] | None] = []

    def fake_request(*_args, **_kwargs):
        nonlocal probes
        probes += 1
        return 200, b'"127.0.0.1:8300"', {}, None, False, False

    def fake_scope(*_args, headers=None, **_kwargs):
        matrix_headers.append(headers)
        ok = headers == {"X-Consul-Token": "valid"}
        return {"ok": ok, "count": 1 if ok else 0, "status": 200 if ok else 403, "error": None}

    def fake_self_request(*_args, headers=None, **_kwargs):
        self_headers.append(headers)
        ok = headers == {"X-Consul-Token": "valid"}
        payload = {
            "Config": {"Version": "1.18.0"},
            "DebugConfig": {"EnableLocalScriptChecks": False, "EnableRemoteScriptChecks": False},
        }
        return (200 if ok else 403), payload if ok else {}, None, False, False

    monkeypatch.setattr(consul, "_request_with_tls_fallback", fake_request)
    monkeypatch.setattr(consul, "_scope_probe", fake_scope)
    monkeypatch.setattr(consul, "_consul_get_json_any", fake_self_request)
    args = parse_args(["consul", "-t", "127.0.0.1", "--port", "8500", "--token", "valid", "--format", "json"])
    result = _run(consul, "consul", args)

    assert probes == 1
    assert matrix_headers == [None, None, None, {"X-Consul-Token": "valid"}] * 1 + [
        {"X-Consul-Token": "valid"},
        {"X-Consul-Token": "valid"},
    ]
    assert self_headers == [None, {"X-Consul-Token": "valid"}]
    assert result.records[0]["status"] == "valid_credentials"


def test_grpc_token_auth_uses_one_protocol_detection_and_one_credential_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detects = 0
    credentials = 0

    def fake_detect(*_args, **_kwargs):
        nonlocal detects
        detects += 1
        return {
            "status": "detected",
            "is_grpc": True,
            "transport_mode": "plaintext",
            "protocol_flavor": "grpc",
            "auth_required": True,
            "reflection_enabled": None,
            "health_supported": None,
            "detect_probe_trace": [],
        }

    def fake_credentials(*_args, candidates, **_kwargs):
        nonlocal credentials
        credentials += 1
        return True, candidates[0], {}

    monkeypatch.setattr(grpc, "_detect_grpc_target", fake_detect)
    monkeypatch.setattr(grpc, "_try_credentials", fake_credentials)
    monkeypatch.setattr(
        grpc,
        "_reflection_list_services_call",
        lambda *_args, **_kwargs: {"reflection_enabled": False, "services": []},
    )
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_args, **_kwargs: {
            "health_supported": False,
            "grpc_status": 12,
            "grpc_status_name": "UNIMPLEMENTED",
            "serving_status": None,
            "error": None,
        },
    )
    args = parse_args(["grpc", "-t", "127.0.0.1", "--port", "50051", "--token", "valid", "--format", "json"])
    result = _run(grpc, "grpc", args)

    assert detects == 1
    assert credentials == 1
    assert result.records[0]["status"] == "valid_credentials"


def test_grpc_defcreds_are_one_candidate_per_runtime_run_and_stop_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempted: list[dict[str, Any]] = []
    capability_calls = 0
    default_token = grpc._DEFAULT_BEARER_TOKENS[0]

    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_args, **_kwargs: {
            "status": "detected",
            "is_grpc": True,
            "transport_mode": "plaintext",
            "protocol_flavor": "grpc",
            "auth_required": True,
            "reflection_enabled": None,
            "health_supported": None,
            "detect_probe_trace": [],
        },
    )

    def fake_credentials(*_args, candidates, **_kwargs):
        assert len(candidates) == 1
        attempted.append(dict(candidates[0]))
        ok = candidates[0].get("token") == default_token
        return ok, candidates[0] if ok else None, {}

    def fake_reflection(*_args, **_kwargs):
        nonlocal capability_calls
        capability_calls += 1
        return {"reflection_enabled": False, "services": []}

    monkeypatch.setattr(grpc, "_try_credentials", fake_credentials)
    monkeypatch.setattr(grpc, "_reflection_list_services_call", fake_reflection)
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_args, **_kwargs: {
            "health_supported": False,
            "grpc_status": 12,
            "grpc_status_name": "UNIMPLEMENTED",
            "serving_status": None,
            "error": None,
        },
    )
    args = parse_args(
        [
            "grpc",
            "-t",
            "127.0.0.1",
            "--port",
            "50051",
            "--token",
            "bad",
            "--defcreds",
            "--analyze",
            "--format",
            "json",
        ]
    )
    plan = grpc.build_grpc_plan(args)
    runner = AuditCommandRunner(args=args, spec=grpc.build_grpc_spec(args), emit_line=lambda _line: None)
    result = runner.run_plan(plan)

    assert [run.source for run in plan.credential_runs[:2]] == ["provided", "default"]
    assert [item.get("token") for item in attempted] == ["bad", default_token]
    assert capability_calls == 1
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["defcreds_used"] is True


def test_grpc_analyze_continues_until_reflection_credential_and_reuses_health_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    health_headers: list[str | None] = []
    reflection_probe_headers: list[str | None] = []
    reflection_inventory_headers: list[str | None] = []
    descriptor_headers: list[str | None] = []

    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_args, **_kwargs: {
            "status": "detected",
            "is_grpc": True,
            "transport_mode": "plaintext",
            "protocol_flavor": "grpc",
            "auth_required": None,
            "health_access": "auth_required",
            "reflection_access": "auth_required",
            "invoke_access": "not_tested",
            "reflection_enabled": None,
            "health_supported": None,
            "detect_probe_trace": [],
        },
    )

    def fake_health(*_args, authorization=None, **_kwargs):
        health_headers.append(authorization)
        accepted = authorization == "Bearer health-only"
        return {
            "call": {"is_grpc": True},
            "health_supported": True,
            "grpc_status": 0 if accepted else 16,
            "grpc_status_name": "OK" if accepted else "UNAUTHENTICATED",
            "serving_status": "SERVING" if accepted else None,
            "error": None,
        }

    def fake_reflection_probe(*_args, authorization=None, **_kwargs):
        reflection_probe_headers.append(authorization)
        accepted = authorization == "Bearer admin"
        return {
            "call": {"is_grpc": True},
            "reflection_enabled": True if accepted else None,
            "grpc_status": 0 if accepted else 16,
            "error": None,
        }

    def fake_reflection_inventory(*_args, authorization=None, **_kwargs):
        reflection_inventory_headers.append(authorization)
        assert authorization == "Bearer admin"
        return {
            "call": {"is_grpc": True},
            "reflection_enabled": True,
            "reflection_version": "v1",
            "grpc_status": 0,
            "services": ["demo.Service"],
            "error": None,
        }

    def fake_descriptors(*_args, authorization=None, **_kwargs):
        descriptor_headers.append(authorization)
        assert authorization == "Bearer admin"
        return {
            "call": {"is_grpc": True},
            "grpc_status": 0,
            "descriptor_bytes": [],
            "error": None,
        }

    monkeypatch.setattr(grpc, "_health_check_call", fake_health)
    monkeypatch.setattr(grpc, "_reflection_capability_call", fake_reflection_probe)
    monkeypatch.setattr(grpc, "_reflection_list_services_call", fake_reflection_inventory)
    monkeypatch.setattr(grpc, "_reflection_file_descriptors_call", fake_descriptors)

    args = parse_args(
        [
            "grpc",
            "-t",
            "127.0.0.1",
            "--port",
            "50051",
            "--token",
            "health-only",
            "--defcreds",
            "--analyze",
            "--format",
            "json",
        ]
    )
    plan = grpc.build_grpc_plan(args)
    runner = AuditCommandRunner(args=args, spec=grpc.build_grpc_spec(args), emit_line=lambda _line: None)
    result = runner.run_plan(plan)

    assert reflection_probe_headers == ["Bearer health-only", "Bearer admin"]
    assert reflection_inventory_headers == ["Bearer admin"]
    assert descriptor_headers == ["Bearer admin"]
    assert health_headers == [
        "Bearer health-only",
        "Bearer admin",
        "Bearer health-only",
        "Bearer health-only",
    ]
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["health_access"] == "authenticated"
    assert result.records[0]["reflection_access"] == "authenticated"
    assert result.records[0]["auth_required"] is None
    assert result.records[0]["action_access_satisfied"] is True
    assert result.records[0]["provided_credential_source"] == "default"


def test_grpc_invoke_continues_candidates_until_the_requested_method_is_accessible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoke_headers: list[str | None] = []

    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_args, **_kwargs: {
            "status": "detected",
            "is_grpc": True,
            "transport_mode": "plaintext",
            "protocol_flavor": "grpc",
            "auth_required": None,
            "health_access": "anonymous",
            "reflection_access": "anonymous",
            "invoke_access": "not_tested",
            "reflection_enabled": False,
            "health_supported": True,
            "detect_probe_trace": [],
        },
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_list_services_call",
        lambda *_args, **_kwargs: {
            "call": {"is_grpc": True},
            "reflection_enabled": False,
            "grpc_status": 12,
            "services": [],
            "error": None,
        },
    )
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_args, **_kwargs: {
            "call": {"is_grpc": True},
            "health_supported": True,
            "grpc_status": 0,
            "grpc_status_name": "OK",
            "serving_status": "SERVING",
            "error": None,
        },
    )

    def fake_invoke(*_args, authorization=None, **_kwargs):
        invoke_headers.append(authorization)
        accepted = authorization == "Bearer admin"
        return {
            "path": "/demo.Service/Get",
            "status": "ok" if accepted else "grpc_error",
            "grpc_status": 0 if accepted else 16,
            "grpc_status_name": "OK" if accepted else "UNAUTHENTICATED",
        }

    monkeypatch.setattr(grpc, "_invoke_unary_method", fake_invoke)
    args = parse_args(
        [
            "grpc",
            "-t",
            "127.0.0.1",
            "--port",
            "50051",
            "--token",
            "bad",
            "--defcreds",
            "--invoke",
            "/demo.Service/Get",
            "--format",
            "json",
        ]
    )
    plan = grpc.build_grpc_plan(args)
    runner = AuditCommandRunner(args=args, spec=grpc.build_grpc_spec(args), emit_line=lambda _line: None)
    result = runner.run_plan(plan)

    assert invoke_headers == ["Bearer bad", "Bearer admin"]
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["invoke_access"] == "authenticated"
    assert result.records[0]["auth_required"] is None
    assert result.records[0]["action_access_satisfied"] is True
    assert result.records[0]["provided_credential_source"] == "default"


@pytest.mark.parametrize(
    ("token", "use_defcreds", "expected_headers", "expected_source"),
    [
        ("admin", False, [None, "Bearer admin"], "provided"),
        ("bad", True, [None, "Bearer bad", "Bearer admin"], "default"),
    ],
)
def test_grpc_public_reflection_probe_retries_deep_descriptors_with_credentials(
    monkeypatch: pytest.MonkeyPatch,
    token: str,
    use_defcreds: bool,
    expected_headers: list[str | None],
    expected_source: str,
) -> None:
    list_headers: list[str | None] = []
    descriptor_headers: list[str | None] = []

    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_args, **_kwargs: {
            "status": "detected",
            "is_grpc": True,
            "transport_mode": "plaintext",
            "protocol_flavor": "grpc",
            "auth_required": None,
            "health_access": "anonymous",
            "reflection_access": "anonymous",
            "invoke_access": "not_tested",
            "reflection_enabled": True,
            "health_supported": True,
            "detect_probe_trace": [],
        },
    )

    def fake_reflection_inventory(*_args, authorization=None, **_kwargs):
        list_headers.append(authorization)
        return {
            "call": {"is_grpc": True},
            "reflection_enabled": True,
            "reflection_version": "v1",
            "grpc_status": 0,
            "services": ["demo.Service"],
            "error": None,
        }

    def fake_descriptors(*_args, authorization=None, **_kwargs):
        descriptor_headers.append(authorization)
        accepted = authorization == "Bearer admin"
        return {
            "call": {"is_grpc": True},
            "grpc_status": 0 if accepted else 16,
            "descriptor_bytes": [],
            "error": None,
        }

    monkeypatch.setattr(grpc, "_reflection_list_services_call", fake_reflection_inventory)
    monkeypatch.setattr(grpc, "_reflection_file_descriptors_call", fake_descriptors)
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_args, **_kwargs: {
            "call": {"is_grpc": True},
            "health_supported": True,
            "grpc_status": 0,
            "grpc_status_name": "OK",
            "serving_status": "SERVING",
            "error": None,
        },
    )

    argv = [
        "grpc",
        "-t",
        "127.0.0.1",
        "--port",
        "50051",
        "--token",
        token,
        "--analyze",
        "--format",
        "json",
    ]
    if use_defcreds:
        argv.append("--defcreds")
    args = parse_args(argv)
    plan = grpc.build_grpc_plan(args)
    runner = AuditCommandRunner(args=args, spec=grpc.build_grpc_spec(args), emit_line=lambda _line: None)
    result = runner.run_plan(plan)

    assert list_headers == expected_headers
    assert descriptor_headers == expected_headers
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["reflection_access"] == "mixed"
    assert result.records[0]["action_access_satisfied"] is True
    assert result.records[0]["auth_used"]["token"] == "admin"
    assert result.records[0]["provided_credential_source"] == expected_source


def test_grpc_public_deep_reflection_does_not_falsely_validate_explicit_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    list_headers: list[str | None] = []

    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_args, **_kwargs: {
            "status": "detected",
            "is_grpc": True,
            "transport_mode": "plaintext",
            "protocol_flavor": "grpc",
            "auth_required": None,
            "health_access": "anonymous",
            "reflection_access": "anonymous",
            "invoke_access": "not_tested",
            "reflection_enabled": True,
            "health_supported": True,
            "detect_probe_trace": [],
        },
    )

    def fake_reflection_inventory(*_args, authorization=None, **_kwargs):
        list_headers.append(authorization)
        return {
            "call": {"is_grpc": True},
            "reflection_enabled": True,
            "reflection_version": "v1",
            "grpc_status": 0,
            "services": [],
            "error": None,
        }

    monkeypatch.setattr(grpc, "_reflection_list_services_call", fake_reflection_inventory)
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_args, **_kwargs: {
            "call": {"is_grpc": True},
            "health_supported": True,
            "grpc_status": 0,
            "grpc_status_name": "OK",
            "serving_status": "SERVING",
            "error": None,
        },
    )

    args = parse_args(
        [
            "grpc",
            "-t",
            "127.0.0.1",
            "--port",
            "50051",
            "--token",
            "admin",
            "--analyze",
            "--format",
            "json",
        ]
    )
    result = _run(grpc, "grpc", args)

    assert list_headers == [None]
    assert result.records[0]["status"] == "detected"
    assert result.records[0]["provided_credentials_ok"] is None
    assert result.records[0]["auth_used"] is None
    assert result.records[0]["action_access_satisfied"] is True
    assert result.records[0]["provided_credential_source"] == "provided"


def test_grpc_web_public_overall_health_retries_protected_service_health_with_next_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    health_calls: list[tuple[str, str | None]] = []

    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_args, **_kwargs: {
            "status": "detected",
            "is_grpc": True,
            "transport_mode": "plaintext",
            "protocol_flavor": "grpc-web",
            "auth_required": None,
            "health_access": "anonymous",
            "reflection_access": "not_tested",
            "invoke_access": "not_tested",
            "reflection_enabled": None,
            "health_supported": True,
            "detect_probe_trace": [],
        },
    )

    def fake_web_health(*_args, authorization=None, service_name="", **_kwargs):
        health_calls.append((service_name, authorization))
        accepted = service_name == "" or authorization == "Bearer admin"
        return {
            "call": {"is_grpc": True},
            "health_supported": True,
            "grpc_status": 0 if accepted else 16,
            "grpc_status_name": "OK" if accepted else "UNAUTHENTICATED",
            "serving_status": "SERVING" if accepted else None,
            "error": None,
        }

    monkeypatch.setattr(grpc, "_grpc_web_health_check_call", fake_web_health)
    monkeypatch.setattr(
        grpc,
        "_extract_descriptors",
        lambda _blobs: ([{"service": "demo.Service", "method": "Get"}], []),
    )

    args = parse_args(
        [
            "grpc",
            "-t",
            "127.0.0.1",
            "--port",
            "50051",
            "--token",
            "bad",
            "--defcreds",
            "--analyze",
            "--format",
            "json",
        ]
    )
    plan = grpc.build_grpc_plan(args)
    runner = AuditCommandRunner(args=args, spec=grpc.build_grpc_spec(args), emit_line=lambda _line: None)
    result = runner.run_plan(plan)

    assert health_calls == [
        ("", None),
        ("demo.Service", None),
        ("", "Bearer bad"),
        ("demo.Service", "Bearer bad"),
        ("", "Bearer admin"),
        ("demo.Service", "Bearer admin"),
    ]
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["health_access"] == "mixed"
    assert result.records[0]["action_access_satisfied"] is True
    assert result.records[0]["auth_used"]["token"] == "admin"
    assert result.records[0]["provided_credential_source"] == "default"
