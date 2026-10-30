from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.elastic import actions
from redposture_core.stage_runtime import AuditCredentialRun


def _attempt(
    password: str,
    *,
    status: str = "credentials_unverified_anonymous",
    probe_status: str = "unverified",
    error: str = "root endpoint is also anonymously accessible",
) -> dict[str, Any]:
    return {
        "username": "elastic",
        "password": password,
        "source": "default",
        "status": status,
        "error": error,
        "auth_probe_status": probe_status,
        "auth_probe_http_status": 200,
        "auth_probe_endpoint": "/",
        "auth_error_detail": {
            "status": 200,
            "type": "authentication_unverified",
            "reason": error,
            "fallback_endpoint": "/",
        },
        "network_attempted": True,
        "verification_capability": "identity_endpoint_unavailable",
    }


def _record(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "host": "10.109.236.131",
        "port": 9200,
        "status": "open_no_auth",
        "auth_required": False,
        "attempted_credentials": attempts,
    }


def _ctx(state: actions.ElasticLifecycleState, password: str) -> SimpleNamespace:
    return SimpleNamespace(
        lifecycle_state=state,
        host="127.0.0.1",
        port=9200,
        target=None,
        args=SimpleNamespace(timeout=1.0, ca_file=None, proxy="http://unit-test-proxy.invalid"),
        credential=AuditCredentialRun(
            username="elastic",
            password=password,
            source="default",
        ),
    )


def _token_ctx(state: actions.ElasticLifecycleState, token: str) -> SimpleNamespace:
    return SimpleNamespace(
        lifecycle_state=state,
        host="127.0.0.1",
        port=9200,
        target=None,
        args=SimpleNamespace(timeout=1.0, ca_file=None, proxy="http://unit-test-proxy.invalid"),
        credential=AuditCredentialRun(token=token, source="token"),
    )


def _detected_record() -> dict[str, Any]:
    return {
        "host": "127.0.0.1",
        "port": 9200,
        "status": "open_no_auth",
        "auth_required": False,
        "anonymous_root_status": 200,
        "server_version": "8.17.3",
        "vendor": "elasticsearch",
        "scheme": "http",
        "insecure_effective": False,
    }


def test_normal_txt_omits_public_root_unverified_basic_pairs() -> None:
    attempts = [_attempt("changeme"), _attempt("elastic"), _attempt("password")]

    lines = actions._format_credential_attempts_records(_record(attempts), "txt")

    assert lines == []


def test_debug_txt_keeps_each_pair_and_full_diagnostic() -> None:
    long_error = "root endpoint is also anonymously accessible; " + ("diagnostic-" * 30)
    attempts = [_attempt("changeme", error=long_error), _attempt("elastic", error=long_error)]

    lines = actions._format_credential_attempts_records(_record(attempts), "txt", debug=True)

    assert len(lines) == 2
    assert all(long_error in line for line in lines)
    assert any("elastic:changeme" in line for line in lines)
    assert any("elastic:elastic" in line for line in lines)
    assert all("network_attempted=True" in line for line in lines)


def test_inconclusive_root_fallback_is_debug_only() -> None:
    attempt = _attempt(
        "changeme",
        error="authentication endpoint is unsupported and root fallback is inconclusive",
    )
    attempt["auth_error_detail"]["reason"] = attempt["error"]

    lines = actions._format_credential_attempts_records(_record([attempt]), "txt")

    assert lines == []
    debug_lines = actions._format_credential_attempts_records(_record([attempt]), "txt", debug=True)
    assert len(debug_lines) == 1
    assert "[!] elastic:changeme" in debug_lines[0]


def test_verified_and_definitively_rejected_candidates_keep_markers() -> None:
    accepted = _attempt("", status="weak_default_creds", probe_status="verified", error="")
    rejected = _attempt("bad", status="auth_required", probe_status="rejected", error="authentication failed")

    lines = actions._format_credential_attempts_records(_record([accepted, rejected]), "txt")

    assert any("[+] elastic:<empty>" in line for line in lines)
    assert any("[-] elastic:bad" in line for line in lines)


def test_selected_credential_renders_once_after_capabilities() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 29201,
        "status": "valid_credentials",
        "provided_credentials": True,
        "provided_username": "observer",
        "provided_password": "V13w-Only!2026",
        "provided_token": False,
        "can_read": None,
        "can_write": None,
        "can_manage": None,
        "can_manage_security": None,
        "attempted_credentials": [
            {
                "username": "observer",
                "password": "V13w-Only!2026",
                "source": "provided",
                "status": "valid_credentials",
                "auth_probe_status": "verified",
            }
        ],
    }

    assert actions._format_record({**record, "_credential_capabilities_pending": True}, "txt") == ""
    assert actions._format_record(record, "txt").endswith(
        "[+] observer:V13w-Only!2026 (Indices:Unknown) (Write:Unknown) (Delete:Unknown) "
        "(Documents:Unknown) (Cluster:Unknown) (Nodes:Unknown) (Users:Unknown)"
    )
    assert actions._format_credential_attempts_records(record, "txt") == []


def test_selected_credential_renders_verified_resource_access() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 29201,
        "status": "valid_credentials",
        "provided_credentials": True,
        "provided_username": "observer",
        "provided_password": "V13w-Only!2026",
        "provided_token": False,
        "credential_resource_access_checked": True,
        "credential_indices_access": "allowed",
        "credential_indices_count": 7,
        "credential_documents_access": "allowed",
        "credential_cluster_access": "denied",
        "credential_nodes_access": "denied",
        "credential_nodes_count": None,
        "credential_users_access": "denied",
        "credential_users_count": None,
    }

    assert actions._format_record(record, "txt").endswith(
        "[+] observer:V13w-Only!2026 (Indices:7) (Write:Unknown) (Delete:Unknown) "
        "(Documents:Read) (Cluster:Access Denied) (Nodes:Access Denied) (Users:Access Denied)"
    )


def test_every_accepted_elastic_pair_keeps_its_own_resource_evidence() -> None:
    record = _record(
        [
            {
                "username": "reader",
                "password": "one",
                "status": "valid_credentials",
                "auth_probe_status": "verified",
                "credential_resource_access_checked": True,
                "credential_indices_access": "allowed",
                "credential_indices_count": 2,
                "credential_documents_access": "allowed",
                "credential_cluster_access": "denied",
                "credential_nodes_access": "allowed",
                "credential_nodes_count": 1,
                "credential_users_access": "denied",
                "credential_write_access": "denied",
                "credential_delete_access": "unknown",
            },
            {
                "username": "writer",
                "password": "two",
                "status": "valid_credentials",
                "auth_probe_status": "verified",
                "credential_resource_access_checked": True,
                "credential_indices_access": "allowed",
                "credential_indices_count": 5,
                "credential_documents_access": "allowed",
                "credential_cluster_access": "allowed",
                "credential_nodes_access": "allowed",
                "credential_nodes_count": 3,
                "credential_users_access": "denied",
                "credential_write_access": "allowed",
                "credential_delete_access": "allowed",
            },
        ]
    )
    record.update({"provided_username": "writer", "provided_password": "two"})

    lines = actions._format_credential_attempts_records(record, "txt")

    assert len(lines) == 1
    assert "reader:one (Indices:2) (Write:Access Denied) (Delete:Unknown) (Documents:Read)" in lines[0]
    assert "(Cluster:Access Denied)" in lines[0]
    assert "Indices:5" not in lines[0]


def test_defcreds_renders_capabilities_for_every_accepted_pair() -> None:
    record = _record(
        [
            {
                "username": "first",
                "password": "one",
                "status": "weak_default_creds",
                "auth_probe_status": "verified",
                "credential_indices_access": "allowed",
                "credential_indices_count": 2,
                "credential_write_access": "allowed",
                "credential_delete_access": "allowed",
            },
            {
                "username": "second",
                "password": "two",
                "status": "weak_default_creds",
                "auth_probe_status": "verified",
                "credential_indices_access": "denied",
                "credential_write_access": "denied",
                "credential_delete_access": "denied",
            },
        ]
    )

    lines = actions._format_credential_attempts_records(record, "txt")

    assert len(lines) == 2
    assert "[+] first:one (Indices:2) (Write:Allowed) (Delete:Allowed)" in lines[0]
    assert "[+] second:two (Indices:Access Denied) (Write:Access Denied) (Delete:Access Denied)" in lines[1]


def test_elastic_selected_pair_is_matched_by_both_username_and_password() -> None:
    record = _record(
        [
            {"username": "admin", "password": "first", "status": "valid_credentials", "auth_probe_status": "verified"},
            {"username": "admin", "password": "second", "status": "valid_credentials", "auth_probe_status": "verified"},
        ]
    )
    record.update({"provided_username": "admin", "provided_password": "second"})

    lines = actions._format_credential_attempts_records(record, "txt")

    assert len(lines) == 1
    assert "[+] admin:first" in lines[0]


def test_active_write_delete_probe_cleans_only_its_unique_index(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[str, str]] = []

    def fake_request(_host: str, _port: int, path: str, _timeout: float, *, method: str = "GET", **_kw: Any):
        requests.append((method, path))
        if method == "PUT" and path.count("/") == 1:
            assert _kw["headers"]["Content-Type"] == "application/json"
            return 200, b'{"acknowledged":true}', {}, None
        if method == "PUT" and "/_doc/" in path:
            return 201, b'{"result":"created"}', {}, None
        if method == "DELETE" and "/_doc/" in path:
            return 200, b'{"result":"deleted"}', {}, None
        if method == "DELETE" and path.count("/") == 1:
            return 200, b'{"acknowledged":true}', {}, None
        raise AssertionError((method, path))

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    result = actions._probe_credential_write_delete_access(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "Basic redacted"},
    )

    assert result["credential_write_access"] == "allowed"
    assert result["credential_delete_access"] == "allowed"
    assert result["credential_probe_cleanup"] == "complete"
    assert [method for method, _ in requests] == ["PUT", "PUT", "DELETE", "DELETE"]
    index_path = requests[0][1]
    assert index_path.startswith("/redposture-access-probe-")
    assert requests[-1][1] == index_path
    assert all(path.startswith(index_path) for _, path in requests)


def test_active_probe_never_claims_document_write_when_index_create_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, str]] = []

    def fake_request(_host: str, _port: int, path: str, _timeout: float, *, method: str = "GET", **_kw: Any):
        requests.append((method, path))
        return 403, b'{"error":"forbidden"}', {}, None

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    result = actions._probe_credential_write_delete_access(
        "127.0.0.1", 9200, 1.0, scheme="http", insecure=False, ca_file=None, auth_headers={}
    )

    assert result["credential_write_access"] == "unknown"
    assert result["credential_delete_access"] == "unknown"
    assert result["credential_probe_cleanup"] == "not_needed"
    assert len(requests) == 1


def test_active_probe_checks_opensearch_own_index_after_generic_index_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, str]] = []

    def fake_request(_host: str, _port: int, path: str, _timeout: float, *, method: str = "GET", **_kw: Any):
        requests.append((method, path))
        if method == "PUT" and path.startswith("/redposture-access-probe-"):
            return 403, b'{"error":"forbidden"}', {}, None
        if method == "GET" and path == "/_plugins/_security/authinfo":
            return 200, b'{"user_name":"logstash","roles":["logstash","own_index"]}', {}, None
        if method == "HEAD" and path == "/logstash":
            return 404, b"", {}, None
        if method == "PUT" and path == "/logstash":
            return 200, b'{"acknowledged":true}', {}, None
        if method == "PUT" and path.startswith("/logstash/_doc/"):
            return 201, b'{"result":"created"}', {}, None
        if method == "DELETE" and path.startswith("/logstash/_doc/"):
            return 200, b'{"result":"deleted"}', {}, None
        if method == "DELETE" and path == "/logstash":
            return 200, b'{"acknowledged":true}', {}, None
        raise AssertionError((method, path))

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    result = actions._probe_credential_write_delete_access(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=True,
        ca_file=None,
        auth_headers={"Authorization": "Basic redacted"},
    )

    assert result["credential_write_access"] == "allowed"
    assert result["credential_delete_access"] == "allowed"
    assert result["credential_probe_cleanup"] == "complete"
    assert ("PUT", "/logstash") in requests
    assert requests[-1] == ("DELETE", "/logstash")


def test_active_probe_cleans_existing_own_index_after_ambiguous_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, str]] = []
    document_deletes = 0

    def fake_request(_host: str, _port: int, path: str, _timeout: float, *, method: str = "GET", **_kw: Any):
        nonlocal document_deletes
        requests.append((method, path))
        if method == "PUT" and path.startswith("/redposture-access-probe-"):
            return 403, b'{"error":"forbidden"}', {}, None
        if method == "GET" and path == "/_plugins/_security/authinfo":
            return 200, b'{"user_name":"logstash","roles":["own_index"]}', {}, None
        if method == "HEAD" and path == "/logstash":
            return 200, b"", {}, None
        if method == "DELETE" and path.startswith("/logstash/_doc/"):
            document_deletes += 1
            if document_deletes == 1:
                return 404, b'{"result":"not_found"}', {}, None
            return 200, b'{"result":"deleted"}', {}, None
        if method == "PUT" and path.startswith("/logstash/_doc/"):
            return 0, b"", {}, "connection reset after write"
        raise AssertionError((method, path))

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    result = actions._probe_credential_write_delete_access(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=True,
        ca_file=None,
        auth_headers={"Authorization": "Basic redacted"},
    )

    assert result["credential_write_access"] == "unknown"
    assert result["credential_probe_cleanup"] == "complete"
    assert document_deletes == 2
    assert ("DELETE", "/logstash") not in requests


def test_active_probe_ignores_malformed_own_index_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[str, str]] = []

    def fake_request(_host: str, _port: int, path: str, _timeout: float, *, method: str = "GET", **_kw: Any):
        requests.append((method, path))
        if method == "PUT" and path.startswith("/redposture-access-probe-"):
            return 403, b'{"error":"forbidden"}', {}, None
        if method == "GET" and path == "/_plugins/_security/authinfo":
            return 200, b'{"user_name":"logstash","roles":null}', {}, None
        raise AssertionError((method, path))

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    result = actions._probe_credential_write_delete_access(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=True,
        ca_file=None,
        auth_headers={"Authorization": "Basic redacted"},
    )

    assert result["credential_write_access"] == "unknown"
    assert result["credential_probe_cleanup"] == "not_needed"
    assert [method for method, _path in requests] == ["PUT", "GET"]


def test_active_probe_authinfo_transport_failure_does_not_claim_failed_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, str]] = []

    def fake_request(_host: str, _port: int, path: str, _timeout: float, *, method: str = "GET", **_kw: Any):
        requests.append((method, path))
        if method == "PUT" and path.startswith("/redposture-access-probe-"):
            return 403, b'{"error":"forbidden"}', {}, None
        if method == "GET" and path == "/_plugins/_security/authinfo":
            raise TimeoutError("identity endpoint timed out")
        raise AssertionError((method, path))

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    result = actions._probe_credential_write_delete_access(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=True,
        ca_file=None,
        auth_headers={"Authorization": "Basic redacted"},
    )

    assert result["credential_write_access"] == "unknown"
    assert result["credential_probe_cleanup"] == "not_needed"
    assert [method for method, _path in requests] == ["PUT", "GET"]


def test_active_probe_cleans_own_index_after_ambiguous_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[str, str]] = []

    def fake_request(_host: str, _port: int, path: str, _timeout: float, *, method: str = "GET", **_kw: Any):
        requests.append((method, path))
        if method == "PUT" and path.startswith("/redposture-access-probe-"):
            return 403, b'{"error":"forbidden"}', {}, None
        if method == "GET" and path == "/_plugins/_security/authinfo":
            return 200, b'{"user_name":"logstash","roles":["own_index"]}', {}, None
        if method == "HEAD" and path == "/logstash":
            return 404, b"", {}, None
        if method == "PUT" and path == "/logstash":
            raise TimeoutError("index created but response lost")
        if method == "DELETE" and path == "/logstash":
            return 200, b'{"acknowledged":true}', {}, None
        raise AssertionError((method, path))

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    result = actions._probe_credential_write_delete_access(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=True,
        ca_file=None,
        auth_headers={"Authorization": "Basic redacted"},
    )

    assert result["credential_write_access"] == "unknown"
    assert result["credential_probe_cleanup"] == "complete"
    assert requests[-1] == ("DELETE", "/logstash")


def test_active_probe_reports_failed_cleanup_without_overstating_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_request(_host: str, _port: int, path: str, _timeout: float, *, method: str = "GET", **_kw: Any):
        if method == "PUT" and "/_doc/" not in path:
            return 200, b'{"acknowledged":true}', {}, None
        if method == "PUT":
            return 201, b'{"result":"created"}', {}, None
        return 403, b'{"error":"forbidden"}', {}, None

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    result = actions._probe_credential_write_delete_access(
        "127.0.0.1", 9200, 1.0, scheme="http", insecure=False, ca_file=None, auth_headers={}
    )

    assert result["credential_write_access"] == "allowed"
    assert result["credential_delete_access"] == "denied"
    assert result["credential_probe_cleanup"] == "failed"
    assert result["credential_probe_index"].startswith("redposture-access-probe-")
    assert "Cleanup:Failed; index:" in actions._credential_resource_suffix(result)


def test_auth_phase_attaches_separate_resource_probes_to_each_accepted_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auths = [
        actions._elastic_headers(username="elastic", password=password, api_token=None)["Authorization"]
        for password in ("one", "two")
    ]

    monkeypatch.setattr(
        actions,
        "_probe_authenticate",
        lambda *_args, **_kw: actions.ElasticAuthProbeResult(
            valid=True, error=None, username="elastic", status=200, endpoint="/_security/_authenticate"
        ),
    )

    def resource_probe(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        authorization = kwargs["auth_headers"]["Authorization"]
        return {
            "credential_resource_access_checked": True,
            "credential_indices_access": "allowed",
            "credential_indices_count": 1 if authorization == auths[0] else 2,
        }

    def write_probe(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "credential_write_access": "denied" if kwargs["auth_headers"]["Authorization"] == auths[0] else "allowed"
        }

    monkeypatch.setattr(actions, "_probe_credential_resource_access", resource_probe)
    monkeypatch.setattr(actions, "_probe_credential_write_delete_access", write_probe)
    state = actions.ElasticLifecycleState()

    one = actions.authenticate_elastic(_ctx(state, "one"), _detected_record(), {})
    two = actions.authenticate_elastic(_ctx(state, "two"), _detected_record(), {})

    assert one["credential_indices_count"] == 1
    assert one["credential_write_access"] == "denied"
    assert two["credential_indices_count"] == 2
    assert two["credential_write_access"] == "allowed"


def test_opensearch_resource_access_uses_only_read_only_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[str, str]] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        method: str = "GET",
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        requests.append((method, path))
        if path.startswith("/_resolve/index/"):
            return 200, b'{"indices":[{"name":"logs-a"},{"name":"logs-b"}]}', {}, None
        if path.startswith("/logs-a/_search"):
            return 403, b'{"error":"denied"}', {}, None
        if path.startswith("/logs-b/_search"):
            return 200, b'{"hits":{"total":0,"hits":[]}}', {}, None
        if path == "/_cluster/health":
            return 403, b'{"error":"denied"}', {}, None
        if path.startswith("/_nodes?"):
            return 200, b'{"nodes":{"node-1":{"name":"one"}}}', {}, None
        if path == "/_plugins/_security/api/internalusers":
            return 403, b'{"error":"denied"}', {}, None
        raise AssertionError(f"unexpected request: {method} {path}")

    monkeypatch.setattr(actions, "_elastic_request", fake_request)

    result = actions._probe_credential_resource_access(
        "127.0.0.1",
        29201,
        1.0,
        scheme="https",
        insecure=True,
        ca_file=None,
        auth_headers={"Authorization": "Basic redacted"},
        vendor="opensearch",
    )

    assert result == {
        "credential_resource_access_checked": True,
        "credential_indices_access": "allowed",
        "credential_indices_count": 2,
        "credential_documents_access": "allowed",
        "credential_cluster_access": "denied",
        "credential_nodes_access": "allowed",
        "credential_nodes_count": 1,
        "credential_users_access": "denied",
        "credential_users_count": None,
    }
    assert requests
    assert {method for method, _path in requests} == {"GET"}


def test_debug_renderer_never_reveals_api_token() -> None:
    attempt = {
        "username": None,
        "password": None,
        "token": "do-not-print-this-token",
        "source": "token",
        "status": "unknown_auth",
        "auth_probe_status": "error",
        "error": "transport failed",
    }

    lines = actions._format_credential_attempts_records(_record([attempt]), "txt", debug=True)

    assert len(lines) == 1
    assert "API token (source:token)" in lines[0]
    assert "do-not-print-this-token" not in lines[0]


@pytest.mark.parametrize(
    ("status", "payload"),
    [
        (404, b'{"error":"not found"}'),
        (
            400,
            b'{"error":{"type":"illegal_argument_exception","reason":"authentication endpoint is unavailable"}}',
        ),
    ],
)
def test_unsupported_identity_endpoint_is_cached_for_public_root(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    payload: bytes,
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
            return status, payload, {"Content-Type": "application/json"}, None
        if path == "/":
            return (
                200,
                b'{"name":"node","cluster_name":"lab","version":{"number":"8.17.3"}}',
                {"Content-Type": "application/json", "X-Elastic-Product": "Elasticsearch"},
                None,
            )
        raise AssertionError(path)

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    state = actions.ElasticLifecycleState()

    first = actions.authenticate_elastic(_ctx(state, "one"), _detected_record(), {})
    second = actions.authenticate_elastic(_ctx(state, "two"), _detected_record(), {})

    assert paths == ["/_security/_authenticate", "/"]
    assert first["network_attempted"] is True
    assert second["network_attempted"] is False
    assert second["auth_probe_status"] == "unverified"
    assert second["verification_capability"] == "identity_endpoint_unavailable"
    assert second["credential_verification"] == {
        "status": "unverified",
        "capability": "identity_endpoint_unavailable",
        "supported_endpoint": None,
        "unsupported_endpoints": ["/_security/_authenticate"],
        "credential_accepted": False,
        "identity_verified": False,
    }


def test_arbitrary_400_is_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
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
                b'{"error":{"type":"illegal_argument_exception","reason":"bad request"}}',
                {"Content-Type": "application/json"},
                None,
            )
        return (
            200,
            b'{"name":"node","cluster_name":"lab","version":{"number":"8.17.3"}}',
            {"Content-Type": "application/json", "X-Elastic-Product": "Elasticsearch"},
            None,
        )

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    state = actions.ElasticLifecycleState()

    actions.authenticate_elastic(_ctx(state, "one"), _detected_record(), {})
    actions.authenticate_elastic(_ctx(state, "two"), _detected_record(), {})

    assert paths == ["/_security/_authenticate", "/", "/_security/_authenticate", "/"]
    assert state.unsupported_auth_endpoints == set()


def test_supported_identity_endpoint_is_probed_for_each_candidate(
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
        return (
            401,
            b'{"error":{"type":"security_exception","reason":"unable to authenticate user"}}',
            {"Content-Type": "application/json"},
            None,
        )

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    state = actions.ElasticLifecycleState()

    first = actions.authenticate_elastic(_ctx(state, "one"), _detected_record(), {})
    second = actions.authenticate_elastic(_ctx(state, "two"), _detected_record(), {})

    assert paths == ["/_security/_authenticate", "/_security/_authenticate"]
    assert first["auth_probe_status"] == "rejected"
    assert second["auth_probe_status"] == "rejected"
    assert state.supported_auth_endpoint == "/_security/_authenticate"


def test_supported_endpoint_allows_late_success_without_credential_only_privilege_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths: list[str] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        **kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        paths.append(path)
        authorization = str((kwargs.get("headers") or {}).get("Authorization") or "")
        if (
            authorization
            == actions._elastic_headers(
                username="elastic",
                password="works",
                api_token=None,
            )["Authorization"]
        ):
            return (
                200,
                b'{"username":"elastic","roles":["superuser"]}',
                {"Content-Type": "application/json"},
                None,
            )
        return (
            401,
            b'{"error":{"type":"security_exception","reason":"unable to authenticate user"}}',
            {"Content-Type": "application/json"},
            None,
        )

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    monkeypatch.setattr(actions, "_probe_credential_resource_access", lambda *_args, **_kw: {})
    monkeypatch.setattr(actions, "_probe_credential_write_delete_access", lambda *_args, **_kw: {})
    monkeypatch.setattr(
        actions,
        "_check_privileges",
        lambda *_args, **_kwargs: pytest.fail("credential-only run must not probe privileges"),
    )
    state = actions.ElasticLifecycleState()
    detected = {**_detected_record(), "status": "auth_required", "auth_required": True, "anonymous_root_status": 401}

    rejected = actions.authenticate_elastic(_ctx(state, "wrong"), detected, {})
    accepted = actions.authenticate_elastic(_ctx(state, "works"), detected, {})
    final = actions.collect_elastic_data(
        _ctx(state, "works"),
        accepted,
        {
            "show_endpoints": False,
            "show_plugins": False,
            "show_cluster": False,
            "show_users": False,
            "discover": False,
        },
    )

    assert paths == ["/_security/_authenticate", "/_security/_authenticate"]
    assert rejected["auth_probe_status"] == "rejected"
    assert accepted["auth_probe_status"] == "verified"
    assert accepted["status"] == "weak_default_creds"
    assert final["rights_error"] is None


def test_reflected_api_token_is_redacted_from_lifecycle_record_and_debug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "encoded-api-token-secret"
    reflected = f"invalid raw={token} authorization=ApiKey {token}"

    def fake_request(
        _host: str,
        _port: int,
        _path: str,
        _timeout: float,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        body = json.dumps(
            {
                "error": {
                    "type": "security_exception",
                    "reason": reflected,
                    "root_cause": [{"type": "security_exception", "reason": reflected}],
                }
            }
        ).encode()
        return 500, body, {"Content-Type": "application/json"}, None

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    state = actions.ElasticLifecycleState()
    detected = {**_detected_record(), "status": "auth_required", "auth_required": True, "anonymous_root_status": 401}

    record = actions.authenticate_elastic(_token_ctx(state, token), detected, {})
    serialized = json.dumps(record, ensure_ascii=False)
    attempt = {
        "username": None,
        "password": None,
        "source": "token",
        "status": record["status"],
        "error": record["error"],
        "auth_probe_status": record["auth_probe_status"],
        "auth_probe_http_status": record["auth_probe_http_status"],
        "auth_probe_endpoint": record["auth_probe_endpoint"],
        "auth_error_detail": record["auth_error_detail"],
        "network_attempted": record["network_attempted"],
        "verification_capability": record["verification_capability"],
    }
    debug_lines = actions._format_credential_attempts_records(_record([attempt]), "txt", debug=True)

    assert token not in serialized
    assert f"ApiKey {token}" not in serialized
    assert token not in "\n".join(debug_lines)
    assert "<redacted>" in serialized
    assert record["api_token"] is None


def test_reflected_token_is_removed_from_cached_unsupported_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "cached-api-token-secret"
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
            reflected = f"authentication endpoint is unavailable for {token} and ApiKey {token}"
            body = json.dumps(
                {
                    "error": {
                        "type": "illegal_argument_exception",
                        "reason": reflected,
                    }
                }
            ).encode()
            return 400, body, {"Content-Type": "application/json"}, None
        return (
            200,
            b'{"name":"node","cluster_name":"lab","version":{"number":"8.17.3"}}',
            {"Content-Type": "application/json", "X-Elastic-Product": "Elasticsearch"},
            None,
        )

    monkeypatch.setattr(actions, "_elastic_request", fake_request)
    state = actions.ElasticLifecycleState()

    first = actions.authenticate_elastic(_token_ctx(state, token), _detected_record(), {})
    second = actions.authenticate_elastic(_ctx(state, "password"), _detected_record(), {})

    assert paths == ["/_security/_authenticate", "/"]
    assert token not in json.dumps(first)
    assert token not in json.dumps(state.unsupported_auth_details)
    assert token not in json.dumps(second)
    assert second["network_attempted"] is False


def test_legacy_monolithic_record_and_live_debug_redact_reflected_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "legacy-api-token-secret"
    reflected = f"server reflected {token} and ApiKey {token}"
    monkeypatch.setattr(
        actions,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            401,
            b'{"error":{"type":"security_exception","reason":"missing authentication credentials"}}',
            {"Content-Type": "application/json", "X-Elastic-Product": "Elasticsearch"},
            None,
            "http",
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        actions,
        "_probe_authenticate",
        lambda *_args, **_kwargs: actions.ElasticAuthProbeResult(
            valid=None,
            error=reflected,
            username=token,
            status=500,
            endpoint="/_security/_authenticate",
            detail={
                "status": 500,
                "type": "security_exception",
                "reason": reflected,
                "root_cause": [{"type": "security_exception", "reason": reflected}],
            },
        ),
    )
    live_debug: list[str] = []
    actions._THREAD_LOCAL_DEBUG_EMIT.callback = live_debug.append
    try:
        record = actions._audit_elastic_host(
            "127.0.0.1",
            9200,
            1.0,
            0,
            username=None,
            password=None,
            api_token=token,
            ca_file=None,
            show_endpoints=False,
            show_plugins=False,
            show_cluster=False,
            show_users=False,
            discover=False,
            preferred_scheme="http",
            debug=True,
            run_deep_checks=False,
        )
    finally:
        delattr(actions._THREAD_LOCAL_DEBUG_EMIT, "callback")

    serialized = json.dumps(record, ensure_ascii=False)
    assert token not in serialized
    assert token not in "\n".join(live_debug)
    assert "<redacted>" in serialized
    assert record["api_token"] is None


def test_collected_action_diagnostics_recursively_redact_api_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "action-api-token-secret"
    reflected = f"request rejected for {token} (ApiKey {token})"
    monkeypatch.setattr(
        actions,
        "_check_privileges",
        lambda *_args, **_kwargs: (None, None, None, None, reflected),
    )
    monkeypatch.setattr(
        actions,
        "_fetch_cat_endpoints",
        lambda *_args, **_kwargs: (
            [],
            reflected,
            [{"reason": reflected, "nested": [{"authorization": f"ApiKey {token}"}]}],
        ),
    )
    state = actions.ElasticLifecycleState()
    record = {
        **_detected_record(),
        "status": "valid_credentials",
        "auth_required": True,
        "api_token": token,
    }

    result = actions.collect_elastic_data(
        _token_ctx(state, token),
        record,
        {
            "show_endpoints": True,
            "show_plugins": False,
            "show_cluster": False,
            "show_users": False,
            "discover": False,
        },
    )

    serialized = json.dumps(result, ensure_ascii=False)
    assert token not in serialized
    assert "<redacted>" in serialized
    assert result["api_token"] is None


def test_cluster_action_promotes_already_fetched_node_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        actions,
        "_fetch_cluster_data",
        lambda *_args, **_kwargs: (
            {"cluster_name": "protected-opensearch", "status": "green"},
            [
                {
                    "id": "node-1",
                    "name": "opensearch-1",
                    "ip": "127.0.0.1",
                    "host": "opensearch-1",
                    "roles": ["cluster_manager", "data"],
                    "version": "2.19.1",
                }
            ],
            None,
        ),
    )
    monkeypatch.setattr(actions, "_fetch_cluster_misconfig_findings", lambda *_args, **_kwargs: ([], None))
    state = actions.ElasticLifecycleState()
    record = {
        **_detected_record(),
        "server_version": None,
        "vendor": "opensearch",
    }

    result = actions.collect_elastic_data(
        _ctx(state, "unused"),
        record,
        {
            "show_endpoints": False,
            "show_plugins": False,
            "show_cluster": True,
            "show_users": False,
            "discover": False,
        },
    )

    assert result["server_version"] == "2.19.1"
    assert result["cluster_nodes"][0]["version"] == "2.19.1"


def test_discovery_streams_start_before_collecting_and_renders_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[str] = []

    class FakePool:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def close(self) -> None:
            pass

    monkeypatch.setattr(actions, "HttpSessionPool", FakePool)
    monkeypatch.setattr(
        actions,
        "_collect_discover_report",
        lambda *_args, **_kwargs: SimpleNamespace(
            error=None,
            error_detail=None,
            to_dict=lambda: {
                "discover_results": [],
                "discover_findings": [],
                "discover_coverage": {
                    "complete": True,
                    "status": "complete",
                    "indices_enumerated": 0,
                    "indices_scanned": 0,
                },
            },
        ),
    )
    state = actions.ElasticLifecycleState()
    ctx = _ctx(state, "works")
    ctx.args.discover_time = 30.0
    ctx.args.discover_max_bytes = 50 * 1024 * 1024
    ctx.args._audit_nested_workers = 8
    ctx.args._proxy_config = None
    ctx.nested_scheduler = None
    ctx.debug_emit = None
    ctx.live_emit = emitted.extend
    record = {**_detected_record(), "status": "valid_credentials", "auth_valid": True}

    result = actions.collect_elastic_data(
        ctx,
        record,
        {
            "show_endpoints": False,
            "show_plugins": False,
            "show_cluster": False,
            "show_users": False,
            "discover": True,
        },
    )

    assert emitted == ["ELASTIC\t127.0.0.1\t9200\t [*] Discover Secrets"]
    assert result["_discover_findings_streamed"] is True
    rendered = actions._format_detail_records(result, "txt")
    assert any("Discover Complete (status:complete) (findings:0)" in line for line in rendered)


def test_unsupported_users_api_does_not_fail_other_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        actions,
        "_fetch_security_users",
        lambda *_args, **_kwargs: (None, "security users API unsupported"),
    )
    state = actions.ElasticLifecycleState()

    result = actions.collect_elastic_data(
        _ctx(state, "unused"),
        _detected_record(),
        {
            "show_endpoints": False,
            "show_plugins": False,
            "show_cluster": False,
            "show_users": True,
            "discover": False,
        },
    )

    assert result["users"] is None
    assert result["users_error"] == "security users API unsupported"
    assert result["error"] is None


def test_lifecycle_reuses_one_direct_session_for_auth_candidates_and_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions: list[Any] = []

    class FakeSession:
        def __init__(
            self,
            host: str,
            port: int,
            timeout: float,
            insecure: bool,
            ca_file: str | None,
        ) -> None:
            _ = (timeout, insecure, ca_file)
            self.host = host
            self.port = port
            self.paths: list[str] = []
            self.closed = False
            sessions.append(self)

        def request(
            self,
            _scheme: str,
            _method: str,
            path: str,
            *,
            headers: dict[str, str],
            data: bytes | None,
            response_size_cap: int | None = None,
        ) -> HttpResponse:
            _ = (headers, data)
            assert response_size_cap is None or 0 < response_size_cap <= 10 * 1024 * 1024
            self.paths.append(path)
            if path == "/_security/_authenticate":
                return HttpResponse(
                    status=404,
                    body=b'{"error":"not found"}',
                    headers={"Content-Type": "application/json"},
                )
            if path == "/":
                return HttpResponse(
                    status=200,
                    body=b'{"name":"node","cluster_name":"lab","version":{"number":"8.17.3"}}',
                    headers={
                        "Content-Type": "application/json",
                        "X-Elastic-Product": "Elasticsearch",
                    },
                )
            raise AssertionError(path)

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(actions, "ElasticHttpSession", FakeSession)
    state = actions.ElasticLifecycleState()

    def direct_ctx(password: str) -> SimpleNamespace:
        ctx = _ctx(state, password)
        ctx.args.proxy = None
        return ctx

    first = actions.authenticate_elastic(direct_ctx("one"), _detected_record(), {})
    second = actions.authenticate_elastic(direct_ctx("two"), _detected_record(), {})
    final = actions.collect_elastic_data(
        direct_ctx("two"),
        second,
        {
            "show_endpoints": False,
            "show_plugins": False,
            "show_cluster": False,
            "show_users": False,
            "discover": False,
        },
    )

    assert first["network_attempted"] is True
    assert second["network_attempted"] is False
    assert final["rights_error"] is None
    assert len(sessions) == 1
    assert sessions[0].paths == ["/_security/_authenticate", "/"]
    assert getattr(actions._THREAD_LOCAL_ELASTIC_SESSION, "session", None) is None
    actions.close_elastic_lifecycle_state(state)
    assert sessions[0].closed is True
