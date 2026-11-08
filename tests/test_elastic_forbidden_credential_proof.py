"""A generic gateway 403 is not proof that supplied credentials were accepted."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from redposture_core.modules.elastic import actions
from redposture_core.stage_runtime import AuditCredentialRun


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        b"<html><title>403 Forbidden</title>Blocked by gateway</html>",
        b'{"error":"forbidden"}',
        b"{}",
        b'{"error":{"type":"security_exception","reason":"unable to authenticate user [qa]"}}',
    ],
)
def test_forbidden_without_backend_authorization_evidence_is_unverified(monkeypatch, fallback, body):
    calls = []

    def request(_host, _port, path, _timeout, **kwargs):
        calls.append(path)
        if fallback and path != "/":
            return 404, b'{"error":{"type":"resource_not_found_exception","reason":"no handler found"}}', {}, None
        return 403, body, {}, None

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions._probe_authenticate(
        "qa.invalid",
        9200,
        1,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "Basic cWE6d3Jvbmc="},
        vendor="elasticsearch",
        expected_username="qa",
        anonymous_status=401,
        capability_state=actions.ElasticLifecycleState(),
    )
    assert result.valid is None, "generic 403 incorrectly accepted credentials"
    assert result.username is None and actions._auth_probe_status(result) == "unverified"
    assert result.verification_capability == "indeterminate"
    assert calls == (["/_security/_authenticate", "/"] if fallback else ["/_security/_authenticate"])


def test_gateway_forbidden_never_triggers_capability_or_write_probes(monkeypatch):
    calls = []

    def request(_host, _port, path, _timeout, **kwargs):
        calls.append((kwargs.get("method", "GET"), path))
        return 403, b"<html>Gateway policy denied request</html>", {}, None

    monkeypatch.setattr(actions, "_elastic_request", request)
    monkeypatch.setattr(actions, "_activate_lifecycle_session", lambda *_: None)
    ctx = SimpleNamespace(
        host="qa.invalid",
        port=9200,
        args=SimpleNamespace(timeout=1, ca_file=None),
        credential=AuditCredentialRun(username="qa", password="wrong", source="provided"),
        lifecycle_state=actions.ElasticLifecycleState(),
    )
    record = actions.authenticate_elastic(
        ctx,
        {
            "is_elastic": True,
            "vendor": "elasticsearch",
            "scheme": "http",
            "auth_required": True,
            "anonymous_root_status": 401,
            "server_version": "8.19.0",
        },
        {},
    )
    assert record["auth_valid"] is None and not record["credential_accepted"] and not record["identity_verified"]
    assert record["auth_probe_status"] == "unverified"
    assert calls == [("GET", "/_security/_authenticate")]


def test_known_backend_authorization_denial_retains_accepted_without_identity(monkeypatch):
    monkeypatch.setattr(
        actions,
        "_elastic_request",
        lambda *a, **k: (403, b'{"error":{"type":"security_exception","reason":"action unauthorized"}}', {}, None),
    )
    result = actions._probe_authenticate(
        "qa.invalid",
        9200,
        1,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "Basic cWE6d3Jvbmc="},
        vendor="elasticsearch",
        expected_username="qa",
    )
    assert result.valid is True and result.username is None


@pytest.mark.parametrize("vendor", [None, "opensearch"])
def test_gateway_block_on_one_api_does_not_hide_identity_on_the_other(monkeypatch, vendor):
    calls = []
    endpoints = actions._auth_endpoint_candidates(vendor)
    state = actions.ElasticLifecycleState()

    def request(_host, _port, path, _timeout, **kwargs):
        calls.append(path)
        if path == endpoints[0]:
            return 403, b"<html>Gateway denied</html>", {}, None
        return 200, json.dumps({"username": "qa"}).encode(), {}, None

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions._probe_authenticate(
        "qa.invalid",
        9200,
        1,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "Basic cWE6cHc="},
        vendor=vendor,
        expected_username="qa",
        capability_state=state,
    )
    assert result.valid is True and result.username == "qa"
    assert calls == list(endpoints) and state.supported_auth_endpoint == endpoints[1]
    assert not state.unsupported_auth_endpoints and not state.unsupported_auth_details


@pytest.mark.parametrize("cached", [False, True])
def test_generic_forbidden_does_not_create_or_destroy_endpoint_capability(monkeypatch, cached):
    endpoint = "/_security/_authenticate"
    state = actions.ElasticLifecycleState(supported_auth_endpoint=endpoint if cached else None)
    monkeypatch.setattr(actions, "_elastic_request", lambda *a, **k: (403, b"{}", {}, None))
    result = actions._probe_authenticate(
        "qa.invalid",
        9200,
        1,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "Basic cWE6cHc="},
        vendor="elasticsearch",
        expected_username="qa",
        capability_state=state,
    )
    assert result.valid is None
    assert state.supported_auth_endpoint == (endpoint if cached else None)
    assert not state.unsupported_auth_endpoints and not state.unsupported_auth_details


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("status", [401, 403])
def test_backend_auth_denial_semantics_survive_identity_and_root_paths(monkeypatch, fallback, status):
    def request(_host, _port, path, _timeout, **kwargs):
        if fallback and path != "/":
            return 404, b"{}", {}, None
        return status, b'{"error":{"type":"security_exception","reason":"action unauthorized"}}', {}, None

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions._probe_authenticate(
        "qa.invalid",
        9200,
        1,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "Basic cWE6cHc="},
        vendor="elasticsearch",
        expected_username="qa",
        capability_state=actions.ElasticLifecycleState(),
    )
    assert result.valid is (status == 403) and result.username is None
    assert result.endpoint == ("/" if fallback else "/_security/_authenticate")
    assert actions._auth_probe_status(result) == ("accepted" if status == 403 else "rejected")
    if status == 403:
        assert result.verification_capability == "credential_accepted_identity_unavailable"


@pytest.mark.parametrize("output_format", ["txt", "json"])
@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("debug", [False, True])
def test_public_cli_gateway_block_preserves_detection_but_never_accepts_or_writes(
    tmp_path, output_format, fallback, debug
):
    from scripts.performance_http_fixtures import response
    from scripts.performance_http_server import AsyncHttpFixture

    calls = []

    def router(method, path, headers, body, host):
        calls.append((method, path, bool(headers.get(b"authorization"))))
        if headers.get(b"authorization"):
            status = 404 if fallback and path != "/" else 403
            return response(status, "<html>Gateway policy denied request</html>")
        return response(
            401,
            {"error": {"type": "security_exception", "reason": "missing authentication credentials"}, "status": 401},
            headers={"X-Elastic-Product": "Elasticsearch"},
        )

    peer = AsyncHttpFixture(router)
    peer.start()
    output = tmp_path / ("result." + output_format)
    try:
        result = subprocess.run(
            [
                sys.executable,
                "redposture.py",
                "elastic",
                "-t",
                f"http://127.0.0.1:{peer.port}",
                "-u",
                "qa",
                "-p",
                "wrong",
                "--timeout",
                "1",
                "-r",
                "0",
                "--no-color",
                "-f",
                output_format,
                "-o",
                str(output),
                *(["--debug"] if debug else []),
            ],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=20,
        )
    finally:
        peer.close()
    assert result.returncode == 0, result.stderr
    saved = output.read_text()
    assert "\x1b" not in saved + result.stdout
    if output_format == "json":
        record = json.loads(saved)
        assert record["is_elastic"] is True and record["auth_required"] is True
        assert record["auth_valid"] is None and record["credential_accepted"] is False
        assert record["auth_probe_http_status"] == 403 and record["auth_probe_status"] == "unverified"
    else:
        assert "Elasticsearch" in saved
        assert "[+] qa:wrong" not in saved and "[-] qa:wrong" not in saved
        assert ("qa:wrong" in saved) is debug
        if debug:
            assert "forbidden response does not establish credential acceptance" in saved
            assert "auth_probe_http_status=403" in saved
    authenticated = [(method, path) for method, path, auth in calls if auth]
    assert authenticated == [("GET", "/_security/_authenticate"), *([("GET", "/")] if fallback else [])]
    assert not peer.errors and peer.stats["active"] == 0
