from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.modules.elastic import actions
from redposture_core.modules.elastic import stage as elastic_stage
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandResult,
    AuditCommandRunner,
    AuditCredentialRun,
)


def _elastic_args(*, debug: bool = False, defcreds: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        timeout=1.0,
        retries=0,
        workers=1,
        debug=debug,
        defcreds=defcreds,
        ca_file=None,
        endpoints=False,
        plugins=False,
        cluster=False,
        user=False,
        discover=False,
    )


def _detected_record(
    *,
    status: str = "open_no_auth",
    auth_required: bool | None = False,
    vendor: str = "elasticsearch",
) -> dict[str, Any]:
    return {
        "host": "127.0.0.1",
        "port": 9200,
        "service": "elastic",
        "module": "elastic",
        "status": status,
        "is_elastic": True,
        "auth_required": auth_required,
        "server_version": "8.17.3",
        "vendor": vendor,
        "scheme": "http",
        "insecure_effective": False,
        "tls_auto_plain": True,
        "error": None,
    }


def _auth_context(
    *,
    username: str,
    password: str,
    source: str = "provided",
) -> SimpleNamespace:
    return SimpleNamespace(
        lifecycle_state=actions.ElasticLifecycleState(),
        host="127.0.0.1",
        port=9200,
        target=None,
        args=_elastic_args(),
        credential=AuditCredentialRun(
            username=username,
            password=password,
            source=source,
        ),
    )


def _run_fake_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    *,
    auth_statuses: list[str],
) -> tuple[list[str], AuditCommandResult, list[str], list[str]]:
    args = _elastic_args(defcreds=True)
    auth_calls: list[str] = []
    data_sources: list[str] = []

    def fake_detect(_ctx: Any, _options: Any) -> dict[str, Any]:
        return _detected_record()

    def fake_auth(ctx: Any, detect_record: Any, _options: Any) -> dict[str, Any]:
        payload = dict(detect_record.to_dict())
        username = str(ctx.credential.username)
        password = str(ctx.credential.password)
        auth_calls.append(f"{username}:{password}")
        status = auth_statuses[len(auth_calls) - 1]
        success = status == "weak_default_creds"
        payload.update(
            {
                "status": status,
                "auth_valid": success,
                "provided_credentials": True,
                "provided_username": username,
                "provided_password": password,
                "effective_username": username if success else None,
                "credentials_source": "default",
                "error": None if success else "authentication failed",
            }
        )
        return payload

    def fake_data(ctx: Any, record: Any, _options: Any) -> dict[str, Any]:
        data_sources.append("anonymous" if ctx.credential.source == "anonymous" else str(ctx.credential.password))
        return dict(record.to_dict())

    monkeypatch.setattr(actions, "detect_elastic", fake_detect)
    monkeypatch.setattr(actions, "authenticate_elastic", fake_auth)
    monkeypatch.setattr(actions, "collect_elastic_data", fake_data)

    runs = (
        AuditCredentialRun(username="elastic", password="changeme", source="default"),
        AuditCredentialRun(username="elastic", password="elastic", source="default"),
        AuditCredentialRun(username="elastic", password="password", source="default"),
    )
    plan = AuditCommandPlan(
        targets_by_port={9200: ("127.0.0.1",)},
        credential_runs=runs,
        output_format="txt",
    )
    emitted: list[str] = []
    runner = AuditCommandRunner(
        args=args,
        spec=elastic_stage.build_elastic_spec(args),
        emit_line=emitted.append,
    )
    result = runner.run_plan(plan)
    return emitted, result, auth_calls, data_sources


def test_all_neutral_400_probes_are_not_detected() -> None:
    probes: list[dict[str, Any]] = []
    for path in (
        "/",
        "/_cluster/health",
        "/_nodes?filter_path=nodes.*.version",
        "/_cat/health",
        "/_security/_authenticate",
    ):
        classified = actions._classify_detect_probe(
            path,
            400,
            b'{"error":{"type":"illegal_argument_exception","reason":"bad request"},"status":400}',
            {"Content-Type": "application/json"},
            None,
        )
        probes.append(
            {
                "path": path,
                "status": 400,
                "signal_kind": classified["signal_kind"],
                "signals": classified["signals"],
                "version": classified["version"],
            }
        )

    decision = actions._evaluate_detect_decision(probes)

    assert decision["detected"] is False
    assert decision["confidence"] == "low"
    assert decision["has_positive"] is False


def test_opensearch_root_is_supported_and_uses_opensearch_label() -> None:
    payload = (
        b'{"name":"os-01","cluster_name":"opensearch-cluster",'
        b'"version":{"number":"2.19.1","distribution":"opensearch"},'
        b'"tagline":"The OpenSearch Project: https://opensearch.org/"}'
    )

    classified = actions._classify_detect_probe(
        "/",
        200,
        payload,
        {"Content-Type": "application/json"},
        None,
    )
    decision = actions._evaluate_detect_decision(
        [
            {
                "path": "/",
                "status": 200,
                "signal_kind": classified["signal_kind"],
                "signals": classified["signals"],
                "version": classified["version"],
                "vendor": classified.get("vendor"),
            }
        ]
    )

    assert classified["signal_kind"] == "hard_positive"
    assert classified["vendor"] == "opensearch"
    assert decision["detected"] is True
    assert decision["vendor"] == "opensearch"

    line = actions._format_detect_record(
        {
            **_detected_record(vendor="opensearch"),
            "server_version": "2.19.1",
        },
        "txt",
    )
    assert "OpenSearch API" in line
    assert "Elasticsearch API" not in line


def test_explicit_opensearch_root_marker_wins_over_conflicting_auth_probe() -> None:
    decision = actions._evaluate_detect_decision(
        [
            {
                "path": "/",
                "status": 200,
                "signal_kind": "hard_positive",
                "signals": ["vendor_opensearch_version_distribution"],
                "version": "2.19.1",
                "vendor": "opensearch",
            },
            {
                "path": "/_security/_authenticate",
                "status": 401,
                "signal_kind": "hard_positive",
                "signals": ["security_exception_missing_auth"],
                "version": None,
                "vendor": "elasticsearch",
            },
        ]
    )

    assert decision["detected"] is True
    assert decision["vendor"] == "opensearch"


def test_opensearch_auth_uses_vendor_endpoint_and_confirms_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths: list[str] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        paths.append(path)
        if path == "/_plugins/_security/authinfo":
            return (
                200,
                b'{"user_name":"elastic","backend_roles":["admin"],"user_requested_tenant":null}',
                {"Content-Type": "application/json"},
                None,
            )
        return 404, b'{"error":"not found"}', {"Content-Type": "application/json"}, None

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    ctx = _auth_context(username="elastic", password="password", source="default")

    record = actions.authenticate_elastic(
        ctx,
        _detected_record(vendor="opensearch"),
        {},
    )

    assert paths[0] == "/_plugins/_security/authinfo"
    assert record["status"] == "weak_default_creds"
    assert record["auth_valid"] is True
    assert record["effective_username"] == "elastic"
    assert record["auth_probe_endpoint"] == "/_plugins/_security/authinfo"
    assert record["auth_probe_status"] == "verified"


def test_auth_400_uses_root_fallback_but_does_not_accept_unverified_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths: list[str] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        paths.append(path)
        if path == "/_security/_authenticate":
            return (
                400,
                (
                    b'{"error":{"type":"illegal_argument_exception",'
                    b'"reason":"authenticate endpoint is unavailable"},"status":400}'
                ),
                {"Content-Type": "application/json"},
                None,
            )
        if path == "/":
            return (
                200,
                (
                    b'{"name":"public","cluster_name":"public",'
                    b'"version":{"number":"8.17.3"},"tagline":"You Know, for Search"}'
                ),
                {
                    "Content-Type": "application/json",
                    "X-Elastic-Product": "Elasticsearch",
                },
                None,
            )
        raise AssertionError(f"unexpected auth fallback path: {path}")

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    ctx = _auth_context(username="alice", password="secret")

    record = actions.authenticate_elastic(
        ctx,
        _detected_record(vendor="elasticsearch"),
        {},
    )

    assert paths[:2] == ["/_security/_authenticate", "/"]
    assert record["auth_valid"] is not True
    assert record["auth_probe_status"] == "unverified"
    assert record["auth_probe_endpoint"] == "/"
    assert record["auth_error_detail"]["type"] == "authentication_unverified"
    endpoint_error = record["auth_error_detail"]["auth_endpoint_error"]
    assert endpoint_error["status"] == 400
    assert endpoint_error["type"] == "illegal_argument_exception"


def test_root_access_change_without_identity_remains_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        if path == "/_security/_authenticate":
            return (
                400,
                b'{"error":{"type":"illegal_argument_exception","reason":"unsupported"}}',
                {"Content-Type": "application/json"},
                None,
            )
        if path == "/":
            return (
                200,
                b'{"name":"node","cluster_name":"lab","version":{"number":"7.17.0"}}',
                {"Content-Type": "application/json", "X-Elastic-Product": "Elasticsearch"},
                None,
            )
        raise AssertionError(path)

    monkeypatch.setattr(actions, "_elastic_request", fake_request)

    probe = actions._probe_authenticate(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers=actions._elastic_headers(
            username="alice",
            password="secret",
            api_token=None,
        ),
        vendor="elasticsearch",
        anonymous_status=401,
        expected_username="alice",
    )

    assert probe.valid is None
    assert probe.endpoint == "/"
    assert probe.detail is not None
    assert probe.detail["type"] == "authentication_unverified"
    assert "identity could not be confirmed" in probe.detail["reason"]


def test_api_token_requires_anonymous_control_to_confirm_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_request(
        _host: str,
        _port: int,
        _path: str,
        _timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        return (
            200,
            b'{"username":"public-user"}',
            {"Content-Type": "application/json"},
            None,
        )

    monkeypatch.setattr(actions, "_elastic_request", fake_request)

    probe = actions._probe_authenticate(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers=actions._elastic_headers(
            username=None,
            password=None,
            api_token="secret-token",
        ),
        vendor="elasticsearch",
        anonymous_status=200,
        expected_username=None,
    )

    assert probe.valid is None
    assert probe.detail is not None
    assert probe.detail["type"] == "token_identity_unverified"


def test_auth_200_with_different_identity_is_not_a_valid_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        assert path == "/_security/_authenticate"
        return (
            200,
            b'{"username":"anonymous-proxy-user","roles":[]}',
            {"Content-Type": "application/json"},
            None,
        )

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    ctx = _auth_context(username="alice", password="secret")

    record = actions.authenticate_elastic(
        ctx,
        _detected_record(vendor="elasticsearch"),
        {},
    )

    assert record["auth_valid"] is not True
    assert record["auth_probe_status"] == "unverified"
    assert record["auth_error_detail"]["type"] == "identity_mismatch"
    assert record["effective_username"] == "anonymous-proxy-user"


@pytest.mark.parametrize(
    ("debug", "output_format", "expected_fragment"),
    [
        (False, "txt", "No ELASTIC service detected"),
        (True, "txt", "connection failed"),
        (False, "json", '"transport_errors"'),
    ],
)
def test_dual_transport_close_is_suppressed_only_in_normal_txt(
    monkeypatch: pytest.MonkeyPatch,
    debug: bool,
    output_format: str,
    expected_fragment: str,
) -> None:
    args = _elastic_args(debug=debug)
    transport_errors = {
        "https": "TLS/SSL connection has been closed (EOF) (_ssl.c:992)",
        "http": "Broken pipe",
    }

    def fake_detect(_ctx: Any, _options: Any) -> dict[str, Any]:
        return {
            "host": "127.0.0.1",
            "port": 9200,
            "service": "elastic",
            "module": "elastic",
            "status": "fail",
            "is_elastic": False,
            "auth_required": None,
            "vendor": "compatible",
            "transport_errors": transport_errors,
            "error": ("https=TLS/SSL connection has been closed (EOF) (_ssl.c:992); http=Broken pipe"),
        }

    monkeypatch.setattr(actions, "detect_elastic", fake_detect)
    emitted: list[str] = []
    runner = AuditCommandRunner(
        args=args,
        spec=elastic_stage.build_elastic_spec(args),
        emit_line=emitted.append,
    )
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={9200: ("127.0.0.1",)},
            output_format=output_format,
        )
    )

    assert any(expected_fragment in line for line in emitted)
    assert result.records[0]["transport_errors"] == transport_errors
    if output_format == "json":
        assert json.loads(emitted[0])["transport_errors"] == transport_errors
    elif debug:
        assert any("Broken pipe" in line for line in emitted)
    else:
        assert all("Broken pipe" not in line and "TLS/SSL" not in line for line in emitted)
        assert result.suppressed_records == 1


def test_not_elastic_is_hidden_in_normal_txt_but_retained_in_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_detect(_ctx: Any, _options: Any) -> dict[str, Any]:
        return {
            "host": "127.0.0.1",
            "port": 9200,
            "service": "elastic",
            "module": "elastic",
            "status": "not_elastic",
            "is_elastic": False,
            "auth_required": None,
            "vendor": "compatible",
            "error": None,
        }

    monkeypatch.setattr(actions, "detect_elastic", fake_detect)

    txt_lines: list[str] = []
    args = _elastic_args()
    txt_result = AuditCommandRunner(
        args=args,
        spec=elastic_stage.build_elastic_spec(args),
        emit_line=txt_lines.append,
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={9200: ("127.0.0.1",)},
            output_format="txt",
        )
    )
    assert txt_lines == ["[*] No ELASTIC service detected on target"]
    assert txt_result.suppressed_records == 1

    json_lines: list[str] = []
    json_result = AuditCommandRunner(
        args=args,
        spec=elastic_stage.build_elastic_spec(args),
        emit_line=json_lines.append,
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={9200: ("127.0.0.1",)},
            output_format="json",
        )
    )
    assert json.loads(json_lines[0])["status"] == "not_elastic"
    assert json_result.records[0]["status"] == "not_elastic"


def test_defcreds_records_failures_then_late_success_without_anonymous_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted, result, auth_calls, data_sources = _run_fake_lifecycle(
        monkeypatch,
        auth_statuses=[
            "invalid_credentials_anonymous",
            "invalid_credentials_anonymous",
            "weak_default_creds",
        ],
    )

    assert auth_calls == [
        "elastic:changeme",
        "elastic:elastic",
        "elastic:password",
    ]
    assert data_sources == ["password"]
    assert result.records[0]["status"] == "weak_default_creds"
    assert result.records[0]["attempted_credentials"] == [
        {
            "username": "elastic",
            "password": "changeme",
            "source": "default",
            "status": "invalid_credentials_anonymous",
            "error": "authentication failed",
        },
        {
            "username": "elastic",
            "password": "elastic",
            "source": "default",
            "status": "invalid_credentials_anonymous",
            "error": "authentication failed",
        },
        {
            "username": "elastic",
            "password": "password",
            "source": "default",
            "status": "weak_default_creds",
            "error": None,
        },
    ]
    assert any("[-] elastic:changeme" in line for line in emitted)
    assert any("[-] elastic:elastic" in line for line in emitted)
    assert any("[+] elastic:password" in line for line in emitted)
    assert all("anonymous access" not in line for line in emitted)


def test_defcreds_checks_later_candidates_after_multiple_successes_and_uses_first_winner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted, result, auth_calls, data_sources = _run_fake_lifecycle(
        monkeypatch,
        auth_statuses=[
            "invalid_credentials_anonymous",
            "weak_default_creds",
            "weak_default_creds",
        ],
    )

    assert auth_calls == [
        "elastic:changeme",
        "elastic:elastic",
        "elastic:password",
    ]
    assert data_sources == ["elastic"]
    assert result.records[0]["status"] == "weak_default_creds"
    assert [attempt["status"] for attempt in result.records[0]["attempted_credentials"]] == [
        "invalid_credentials_anonymous",
        "weak_default_creds",
        "weak_default_creds",
    ]
    assert sum("[+] elastic:elastic" in line for line in emitted) == 1
    assert sum("[+] elastic:password" in line for line in emitted) == 1


def test_defcreds_all_fail_then_requested_actions_use_anonymous_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted, result, auth_calls, data_sources = _run_fake_lifecycle(
        monkeypatch,
        auth_statuses=["invalid_credentials_anonymous"] * 3,
    )

    assert len(auth_calls) == 3
    assert data_sources == ["anonymous"]
    assert result.records[0]["status"] == "open_no_auth"
    assert len(result.records[0]["attempted_credentials"]) == 3
    assert sum("[-] elastic:" in line for line in emitted) == 3
    assert all("anonymous access" not in line for line in emitted)


def test_weak_default_formatter_is_success_not_connection_failure() -> None:
    line = actions._format_record(
        {
            **_detected_record(status="weak_default_creds", auth_required=True),
            "provided_username": "elastic",
            "provided_password": "changeme",
            "credentials_source": "default",
            "auth_valid": True,
        },
        "txt",
    )

    assert "[+] elastic:changeme" in line
    assert "connection failed" not in line


def test_json_renderer_never_serializes_api_token() -> None:
    secret = "ZXM6bGFiLXN1cGVyLXNlY3JldA=="
    line = actions._format_record(
        {
            **_detected_record(status="valid_credentials", auth_required=True),
            "provided_token": True,
            "api_token": secret,
            "attempted_credentials": [
                {
                    "username": None,
                    "password": None,
                    "source": "provided",
                    "status": "unverified",
                    "error": "unsupported endpoint",
                }
            ],
        },
        "json",
    )

    payload = json.loads(line)
    assert "api_token" not in payload
    assert secret not in line
    assert all("token" not in attempt for attempt in payload["attempted_credentials"])


def test_json_runner_redacts_api_token_but_keeps_attempt_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "ZXM6bGFiLXN1cGVyLXNlY3JldA=="
    args = _elastic_args()

    def fake_detect(_ctx: Any, _options: Any) -> dict[str, Any]:
        return _detected_record(status="auth_required", auth_required=True)

    def fake_auth(ctx: Any, detect_record: Any, _options: Any) -> dict[str, Any]:
        payload = dict(detect_record.to_dict())
        payload.update(
            {
                "status": "valid_credentials",
                "auth_valid": True,
                "provided_token": True,
                "api_token": ctx.credential.token,
                "error": None,
            }
        )
        return payload

    monkeypatch.setattr(actions, "detect_elastic", fake_detect)
    monkeypatch.setattr(actions, "authenticate_elastic", fake_auth)
    monkeypatch.setattr(actions, "collect_elastic_data", lambda _ctx, record, _options: record)

    emitted: list[str] = []
    result = AuditCommandRunner(
        args=args,
        spec=elastic_stage.build_elastic_spec(args),
        emit_line=emitted.append,
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={9200: ("127.0.0.1",)},
            credential_runs=(AuditCredentialRun(token=secret, source="token"),),
            output_format="json",
        )
    )

    assert secret not in emitted[0]
    payload = json.loads(emitted[0])
    assert "api_token" not in payload
    assert payload["attempted_credentials"] == [
        {
            "username": None,
            "password": None,
            "source": "token",
            "status": "valid_credentials",
            "error": None,
        }
    ]
    assert secret not in json.dumps(result.records[0]["attempted_credentials"])


def test_credential_file_and_api_token_keep_defcreds_as_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    captured_plans: list[AuditCommandPlan] = []

    class CaptureRunner:
        def __init__(self, **_kwargs: Any) -> None:
            return

        def run_plan(self, plan: AuditCommandPlan) -> AuditCommandResult:
            captured_plans.append(plan)
            return AuditCommandResult(
                records=[],
                detected_count=0,
                emitted_lines=0,
                typed_records=[],
            )

    monkeypatch.setattr(elastic_stage, "AuditCommandRunner", CaptureRunner)

    credentials_file = tmp_path / "credentials.txt"
    credentials_file.write_text("alice:one\nbob:two\n", encoding="utf-8")

    common = {
        "timeout": 1.0,
        "retries": 0,
        "workers": 1,
        "port": 9200,
        "ports": None,
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "endpoints": False,
        "plugins": False,
        "cluster": False,
        "user": False,
        "discover": False,
        "output": None,
        "output_format": "txt",
        "debug": False,
        "ca_file": None,
        "proxy": None,
        "defcreds": True,
    }
    logger = SimpleNamespace(log=lambda *_args, **_kwargs: None)

    file_args = SimpleNamespace(
        **common,
        username=str(credentials_file),
        password=None,
        apitoken=None,
    )
    assert elastic_stage.run_elastic_stage(file_args, logger) == 0

    token_args = SimpleNamespace(
        **common,
        username=None,
        password=None,
        apitoken="token-secret",
    )
    assert elastic_stage.run_elastic_stage(token_args, logger) == 0

    file_runs = captured_plans[0].credential_runs
    assert [(run.username, run.password, run.source) for run in file_runs] == [
        ("alice", "one", "file"),
        ("bob", "two", "file"),
        ("admin", "admin", "default"),
        ("admin", "changeme", "default"),
        ("admin", "password", "default"),
        ("elastic", "changeme", "default"),
        ("elastic", "elastic", "default"),
        ("elastic", "password", "default"),
        ("kibana", "changeme", "default"),
        ("kibana", "kibana", "default"),
        ("logstash", "logstash", "default"),
        ("logstash_system", "changeme", "default"),
        ("opensearch", "opensearch", "default"),
        ("opensearch", "password", "default"),
    ]

    token_runs = captured_plans[1].credential_runs
    assert [(run.token, run.username, run.password, run.source) for run in token_runs] == [
        ("token-secret", None, None, "token"),
        (None, "admin", "admin", "default"),
        (None, "admin", "changeme", "default"),
        (None, "admin", "password", "default"),
        (None, "elastic", "changeme", "default"),
        (None, "elastic", "elastic", "default"),
        (None, "elastic", "password", "default"),
        (None, "kibana", "changeme", "default"),
        (None, "kibana", "kibana", "default"),
        (None, "logstash", "logstash", "default"),
        (None, "logstash_system", "changeme", "default"),
        (None, "opensearch", "opensearch", "default"),
        (None, "opensearch", "password", "default"),
    ]


def test_elastic_error_parser_preserves_status_type_reason_and_root_cause() -> None:
    payload = (
        b'{"error":{"root_cause":[{"type":"too_many_clauses",'
        b'"reason":"maxClauseCount is set to 1024"}],'
        b'"type":"search_phase_execution_exception","reason":"all shards failed"},'
        b'"status":500}'
    )

    detail = actions._parse_elastic_error(500, payload)

    assert detail["status"] == 500
    assert detail["type"] == "search_phase_execution_exception"
    assert detail["reason"] == "all shards failed"
    assert detail["root_cause"] == [
        {
            "type": "too_many_clauses",
            "reason": "maxClauseCount is set to 1024",
        }
    ]


def test_list_indices_prefers_open_and_filters_closed_on_legacy_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths: list[str] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        paths.append(path)
        if "expand_wildcards=open" in path:
            return (
                400,
                b'{"error":{"type":"illegal_argument_exception","reason":"unsupported parameter"}}',
                {"Content-Type": "application/json"},
                None,
            )
        return (
            200,
            b'[{"index":"open-a","status":"open"},{"index":"closed-a","status":"close"}]',
            {"Content-Type": "application/json"},
            None,
        )

    monkeypatch.setattr(actions, "_elastic_request", fake_request)

    indices, error = actions._list_index_names(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )

    assert error is None
    assert indices == ["open-a"]
    assert "expand_wildcards=open" in paths[0]
    assert len(paths) == 2


def test_discover_compat_adapter_delegates_to_v2_without_keyword_queries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = [
        {
            "index": "logs",
            "total_hits": 1,
            "shown_hits": 1,
            "hits": [{"index": "logs", "id": "same", "source": {"password": "secret"}}],
            "error": None,
        }
    ]
    calls = 0

    def fake_report(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return SimpleNamespace(legacy_results=expected, error=None)

    monkeypatch.setattr(actions, "_collect_discover_report", fake_report)
    monkeypatch.setattr(
        actions,
        "_search_index_detailed",
        lambda *_args, **_kwargs: pytest.fail("legacy keyword search must not be called"),
    )

    results, error = actions._collect_discover_results(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )

    assert error is None
    assert results == expected
    assert calls == 1


def test_discover_detailed_compat_adapter_preserves_structured_terminal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detail = {
        "status": 500,
        "type": "search_phase_execution_exception",
        "reason": "all shards failed",
        "root_cause": [{"type": "circuit_breaking_exception", "reason": "data too large"}],
        "count": 2,
        "indices": ["logs-a", "logs-b"],
    }
    expected = [
        {"index": "logs-a", "error": "search: all shards failed", "error_detail": detail},
        {"index": "logs-b", "error": "search: all shards failed", "error_detail": detail},
    ]
    monkeypatch.setattr(
        actions,
        "_collect_discover_report",
        lambda *_args, **_kwargs: SimpleNamespace(
            legacy_results=expected,
            error="status=500 type=search_phase_execution_exception reason=all shards failed",
            error_detail=detail,
        ),
    )

    results, error, error_detail = actions._collect_discover_results_detailed(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )

    assert error is not None
    assert error_detail is not None
    assert error_detail["status"] == 500
    assert error_detail["type"] == "search_phase_execution_exception"
    assert error_detail["count"] == 2
    assert results == expected
    assert results is not None
    assert all(item["error_detail"]["status"] == 500 for item in results)
    assert all(item["error_detail"]["type"] == "search_phase_execution_exception" for item in results)

    lines = actions._format_detail_records(
        {
            **_detected_record(),
            "discover": True,
            "discover_results": results,
            "discover_error": None,
            "discover_error_detail": None,
        },
        "txt",
    )
    error_lines = [line for line in lines if "discover error" in line]
    assert len(error_lines) == 1
    assert "2" in error_lines[0]
    assert "search_phase_execution_exception" in error_lines[0]
    assert "all shards failed" in error_lines[0]
    assert "circuit_breaking_exception" in error_lines[0]


def test_negative_debug_output_keeps_transport_and_probe_diagnostics() -> None:
    assert actions._transport_errors_from_combined("https=raw TLS failure") == {"https": "raw TLS failure"}
    lines = actions._format_detail_records(
        {
            "host": "10.0.0.10",
            "port": 9200,
            "status": "not_elastic",
            "transport_errors": {
                "https": "TLS/SSL connection has been closed (EOF)",
                "http": "Broken pipe",
            },
            "detect_probe_trace": [
                {
                    "path": "/",
                    "status": 400,
                    "scheme": "https",
                    "signal_kind": "neutral",
                    "signals": [],
                    "error": None,
                }
            ],
        },
        "txt",
        debug=True,
    )

    assert any("transport scheme=https" in line and "closed (EOF)" in line for line in lines)
    assert any("transport scheme=http" in line and "Broken pipe" in line for line in lines)
    assert any("probe path=/ status=400" in line and "signal=neutral" in line for line in lines)


def test_discover_compat_adapter_preserves_non_terminal_index_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fake_report(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return SimpleNamespace(
            legacy_results=[
                {
                    "index": "logs",
                    "error": "search: unexpected backend failure",
                    "error_detail": {
                        "status": 500,
                        "type": "internal_server_error",
                        "reason": "unexpected backend failure",
                    },
                }
            ],
            error=None,
        )

    monkeypatch.setattr(actions, "_collect_discover_report", fake_report)

    results, error = actions._collect_discover_results(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )

    assert error is None
    assert calls == 1
    assert results is not None
    assert results[0]["error_detail"]["type"] == "internal_server_error"
