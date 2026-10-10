"""Regressions for conclusive credentials and non-misleading inventory output."""

from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.airflow import render as airflow
from redposture_core.modules.grpc import actions as grpc
from redposture_core.modules.kubeapi import actions as kubeapi
from redposture_core.modules.minio import actions as minio_actions
from redposture_core.modules.minio import render as minio
from redposture_core.modules.rabbitmq import render as rabbitmq
from redposture_core.modules.registry import actions as registry
from redposture_core.modules.zookeeper import actions as zookeeper
from redposture_core.stage_runtime import AuditCredentialRun


def test_minio_unknown_attempts_do_not_claim_a_credential_result_in_txt() -> None:
    record = {
        "host": "10.0.0.1",
        "port": 6443,
        "detection_status": "confirmed",
        "credential_state": "verification_unavailable",
        "credential_results": [{"access_key": "access", "state": "verification_unavailable"}],
        "attempted_credentials": [
            {"username": "access", "password": "secret", "credential_state": "verification_unavailable"},
            {"username": "admin", "password": "admin", "credential_state": "invalid"},
            {"username": "minioadmin", "password": "minioadmin", "credential_state": "valid"},
        ],
    }
    assert minio._format_record(record, "txt") == ""
    attempts = minio._format_credential_attempts_records(record, "txt")
    assert attempts == [
        "MINIO\t10.0.0.1\t6443\t [-] admin:admin",
        "MINIO\t10.0.0.1\t6443\t [+] minioadmin:minioadmin",
    ]


@given(
    st.lists(
        st.sampled_from(["verification_unavailable", "transient_failure", "invalid", "valid"]), min_size=2, max_size=30
    )
)
def test_minio_attempt_fuzz_only_renders_conclusive_states(states: list[str]) -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9000,
        "credential_state": "verification_unavailable",
        "attempted_credentials": [
            {"username": f"user{i}", "password": f"pass{i}", "credential_state": state}
            for i, state in enumerate(states)
        ],
    }
    lines = minio._format_credential_attempts_records(record, "txt")
    assert len(lines) == sum(state in {"invalid", "valid"} for state in states)
    assert not any("verification unavailable" in line or "transient_failure" in line for line in lines)


@given(status=st.integers(min_value=200, max_value=299), body=st.binary(max_size=512))
def test_minio_fuzz_generic_success_never_proves_credentials(status: int, body: bytes) -> None:
    response = MinioResponse(http_status=status, headers={}, body=body)
    result = minio_actions._signed_credential_verdict(response, "AKID")
    expected = (
        "valid" if status == 200 and minio_actions._is_service_bucket_listing(body) else "verification_unavailable"
    )
    assert result.state == expected


@given(
    status=st.sampled_from([200, 401, 403, 404, 429, 500, 502]),
    code=st.one_of(st.none(), st.text(max_size=35)),
    body=st.binary(max_size=512),
)
def test_minio_fuzz_admin_fallback_never_guesses_from_http_status(status: int, code: str | None, body: bytes) -> None:
    error = S3Error(status, code, "") if code else None
    response = MinioResponse(http_status=status, headers={}, body=body, error=error)
    result = minio_actions._signed_credential_verdict(response, "AKID", admin=True)
    if result.state == "valid":
        assert status == 200 and minio_actions._is_admin_info_response(body)
    elif result.state == "invalid":
        assert code in minio_actions._INVALID_CRED_CODES
    elif result.state == "valid_but_restricted":
        assert code == "AccessDenied"


@given(
    images=st.lists(st.text(min_size=1, max_size=30), max_size=8),
    error=st.one_of(st.none(), st.sampled_from(["authentication required", "timeout", "connection reset"])),
)
def test_registry_fuzz_auth_gate_never_claims_empty_inventory(images: list[str], error: str | None) -> None:
    record = {
        "host": "127.0.0.1",
        "port": 5000,
        "status": "auth_required",
        "is_registry": True,
        "show_images": True,
        "images": images or None,
        "images_error": error,
    }
    lines = registry._format_detail_records(record, "txt")
    assert not any("<no images>" in line for line in lines)
    assert any("Images Enumeration" in line for line in lines) is bool(images)


@given(
    payload=st.dictionaries(st.text(max_size=25), st.one_of(st.none(), st.text(max_size=60), st.integers()), max_size=8)
)
def test_registry_fuzz_generic_nginx_json_cannot_confirm_nexus(payload: dict[str, object]) -> None:
    # Generic reverse-proxy headers and random JSON fields are not Nexus evidence.
    assert registry._nexus_status_info({"Server": "nginx", "Content-Type": "application/json"}, payload) is None


def test_registry_auth_gate_does_not_repeat_auth_requirement_or_print_empty_images() -> None:
    record = {
        "host": "10.0.0.2",
        "port": 5000,
        "is_registry": True,
        "status": "auth_required",
        "auth_required": True,
        "provided_credentials": False,
        "show_images": True,
        "images": None,
        "images_error": None,
    }
    assert registry._format_record(record, "txt") == ""
    assert registry._format_detail_records(record, "txt") == []


@pytest.mark.parametrize(
    "module_name",
    [
        "clickhouse",
        "docker",
        "etcd",
        "grafana",
        "grpc",
        "kafka",
        "mongodb",
        "postgres",
        "qdrant",
        "redis",
        "registry",
    ],
)
def test_auth_required_without_credentials_has_no_redundant_summary(module_name: str) -> None:
    module = import_module(f"redposture_core.modules.{module_name}.actions")
    record = {"host": "127.0.0.1", "port": 12345, "status": "auth_required", "auth_required": True}
    assert module._format_record(record, "txt") == ""


def test_kubeapi_requested_namespace_inventory_uses_enumeration_heading() -> None:
    record = {
        "host": "10.0.0.3",
        "port": 6443,
        "status": "anonymous_limited",
        "auth_mode": "none",
        "show_namespaces": True,
        "namespaces": None,
        "namespaces_error": "anonymous access denied",
    }
    lines = kubeapi._format_detail_records(record, "txt")
    assert lines[0] == "KUBEAPI \t10.0.0.3\t6443\t [*] Namespaces Enumeration"
    assert len(lines) == 2


@given(
    containers=st.one_of(st.none(), st.integers(min_value=-100, max_value=1000), st.text(max_size=80)),
    denied=st.booleans(),
)
def test_kubeapi_fuzz_inventory_rendering_handles_malformed_counts(containers: int | str | None, denied: bool) -> None:
    record = {
        "host": "127.0.0.1",
        "port": 6443,
        "status": "anonymous_limited",
        "show_namespaces": True,
        "show_pods": True,
        "show_secrets": True,
        "namespaces_error": "anonymous access denied" if denied else None,
        "pods": [{"namespace": "default", "name": "api", "phase": "Running", "containers": containers}],
        "secrets_error": "anonymous access denied" if denied else None,
    }
    lines = kubeapi._format_detail_records(record, "txt")
    assert all(" Show " not in line for line in lines)
    assert sum("Namespaces Enumeration" in line for line in lines) == 1
    assert sum("Pods Enumeration" in line for line in lines) == 1
    assert sum("Secrets Enumeration" in line for line in lines) == 1


def test_other_modules_do_not_print_unverified_pairs_as_credential_results() -> None:
    airflow_record = {
        "host": "127.0.0.1",
        "port": 8080,
        "attempted_credentials": [
            {"username": "test", "password": "test", "credential_state": "verification_unavailable"},
            {"username": "admin", "password": "bad", "credential_state": "invalid"},
        ],
    }
    assert airflow._format_credential_attempts_records(airflow_record, "txt") == [
        "AIRFLOW\t127.0.0.1\t8080\t [-] admin:bad"
    ]

    rabbit_record = {
        "host": "127.0.0.1",
        "port": 15672,
        "attempted_credentials": [
            {"username": "guest", "password": "guest", "credential_state": "unverified"},
            {"username": "admin", "password": "bad", "credential_state": "rejected"},
        ],
    }
    rabbit_lines = rabbitmq._format_credential_attempts_records(rabbit_record, "txt")
    assert len(rabbit_lines) == 1 and "[-] admin:bad" in rabbit_lines[0]

    zoo_record = {
        "host": "127.0.0.1",
        "port": 2181,
        "status": "auth_required",
        "provided_credentials": True,
        "provided_username": "admin",
        "provided_password": "secret",
        "credential_verdict": "unverified",
        "provided_credentials_ok": None,
    }
    zoo_line = zookeeper._format_record(zoo_record, "txt")
    assert "credential verification inconclusive" in zoo_line
    assert "admin:secret" not in zoo_line


def test_grpc_unknown_attempt_remains_unknown_instead_of_becoming_rejected() -> None:
    attempt = {
        "attempts": [
            {
                "candidate": {"type": "basic", "username": "admin", "password": "secret", "source": "default"},
                "ok": False,
                "verdict": "unverified",
            }
        ]
    }
    assert grpc._public_auth_attempts(attempt)[0]["status"] == "unverified"
    record = {"host": "127.0.0.1", "port": 50051, "attempted_credentials": grpc._public_auth_attempts(attempt)}
    assert grpc._format_credential_attempts_records(record, "txt") == []


@pytest.mark.parametrize(
    ("grpc_status", "expected"),
    [(0, "valid"), (16, "rejected"), (None, "unverified"), (7, "unverified")],
)
def test_grpc_auth_attempt_records_only_definitive_verdicts(
    monkeypatch: pytest.MonkeyPatch, grpc_status: int | None, expected: str
) -> None:
    response = {"grpc_status": grpc_status, "call": {"is_grpc": grpc_status is not None}}
    monkeypatch.setattr(grpc, "_health_check_call", lambda *_args, **_kwargs: response)
    monkeypatch.setattr(grpc, "_reflection_capability_call", lambda *_args, **_kwargs: response)
    _ok, _candidate, history = grpc._try_credentials(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        candidates=[{"type": "basic", "username": "admin", "password": "secret", "source": "default"}],
        required_capability="health",
    )
    assert history is not None
    assert history["attempts"][0]["verdict"] == expected


@pytest.mark.parametrize("explicit_nexus", [False, True])
def test_registry_nexus_selector_filters_docker_only_endpoint_but_cve_probe_does_not(
    monkeypatch: pytest.MonkeyPatch, explicit_nexus: bool
) -> None:
    requests: list[str] = []

    def request(_host, _port, _method, path, _timeout, *, headers=None):
        _ = headers
        requests.append(path)
        assert path == "/v2/"
        return (
            401,
            b'{"errors":[{"code":"UNAUTHORIZED"}]}',
            {"docker-distribution-api-version": "registry/2.0"},
            None,
        )

    monkeypatch.setattr(registry, "_http_request", request)
    monkeypatch.setattr(registry, "_fetch_nexus_info", lambda *_args, **_kwargs: (None, "not nexus"))
    options = {
        "docker": False,
        "show_images": True,
        "show_tags": False,
        "repository": None,
        "tag": None,
        "metadata": False,
        "harbor": False,
        "gitlab": False,
        "nexus": True,
        "assets": False,
        "inspect": False,
        "image": None,
        "download": False,
        "download_dir": ".",
    }
    ctx = SimpleNamespace(
        lifecycle_state=registry.RegistryLifecycleState(),
        host="127.0.0.1",
        port=5000,
        args=SimpleNamespace(timeout=1.0, retries=0, debug=False, nexus=explicit_nexus, enum_cve=True),
        credential=AuditCredentialRun(),
    )
    record = registry.detect_registry(ctx, options)
    assert requests == ["/v2/"]
    assert record["is_nexus"] is False if explicit_nexus else record["is_nexus"] is None
    assert record["is_registry"] is (not explicit_nexus)
