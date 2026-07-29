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


def test_normal_txt_prints_each_public_root_unverified_basic_pair_without_reason() -> None:
    attempts = [_attempt("changeme"), _attempt("elastic"), _attempt("password")]

    lines = actions._format_credential_attempts_records(_record(attempts), "txt")

    assert len(lines) == 3
    assert any(line.endswith("[-] elastic:changeme") for line in lines)
    assert any(line.endswith("[-] elastic:elastic") for line in lines)
    assert any(line.endswith("[-] elastic:password") for line in lines)
    assert all("anonymously accessible" not in line for line in lines)
    assert all("err=" not in line for line in lines)


def test_debug_txt_keeps_each_pair_and_full_diagnostic() -> None:
    long_error = "root endpoint is also anonymously accessible; " + ("diagnostic-" * 30)
    attempts = [_attempt("changeme", error=long_error), _attempt("elastic", error=long_error)]

    lines = actions._format_credential_attempts_records(_record(attempts), "txt", debug=True)

    assert len(lines) == 2
    assert all(long_error in line for line in lines)
    assert any("elastic:changeme" in line for line in lines)
    assert any("elastic:elastic" in line for line in lines)
    assert all("network_attempted=True" in line for line in lines)


def test_inconclusive_root_fallback_remains_a_warning() -> None:
    attempt = _attempt(
        "changeme",
        error="authentication endpoint is unsupported and root fallback is inconclusive",
    )
    attempt["auth_error_detail"]["reason"] = attempt["error"]

    lines = actions._format_credential_attempts_records(_record([attempt]), "txt")

    assert len(lines) == 1
    assert "[!] elastic:changeme" in lines[0]
    assert "root fallback is inconclusive" in lines[0]


def test_verified_and_definitively_rejected_candidates_keep_markers() -> None:
    accepted = _attempt("", status="weak_default_creds", probe_status="verified", error="")
    rejected = _attempt("bad", status="auth_required", probe_status="rejected", error="authentication failed")

    lines = actions._format_credential_attempts_records(_record([accepted, rejected]), "txt")

    assert any("[+] elastic:<empty>" in line for line in lines)
    assert any("[-] elastic:bad" in line for line in lines)


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
        ) -> HttpResponse:
            _ = (headers, data)
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
