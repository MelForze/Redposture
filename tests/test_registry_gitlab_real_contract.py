from __future__ import annotations

import json

import pytest

from redposture_core import stage_registry as registry
from redposture_core.cli_args import parse_args
from redposture_core.console import Console
from redposture_core.stage_runtime import AuditCommandRunner


@pytest.mark.parametrize("enum_cve,valid", [(False, True), (True, True), (True, False)])
def test_authenticated_registry_keeps_original_gitlab_identity_and_gates_version(monkeypatch, enum_cve, valid) -> None:
    requests = []
    challenge = 'Bearer realm="http://127.0.0.1:18080/jwt/auth",service="container_registry"'

    def http(_host, _port, method, path, _timeout, *, headers=None, body=None):
        requests.append((method, path))
        if path == "/v2/":
            if headers and headers.get("Authorization") and valid:
                return 200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None
            return (
                401,
                b'{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}',
                {"docker-distribution-api-version": "registry/2.0", "www-authenticate": challenge},
                None,
            )
        return 404, b"", {}, None

    def absolute(url, method, _timeout, *, headers):
        requests.append((method, url))
        if url.endswith("/api/v4/version"):
            assert headers == {"PRIVATE-TOKEN": "glpat-fixture"}
            return 200, b'{"version":"17.7.1","revision":"ea03507eff8"}', {}, None
        return 200, b'{"token":"fixture-token"}', {}, None

    monkeypatch.setattr(registry, "_http_request", http)
    monkeypatch.setattr(registry, "_http_request_url", absolute)
    args = parse_args(
        [
            "registry",
            "-t",
            "127.0.0.1:15003",
            "--gitlab",
            "-u",
            "root",
            "-p",
            "glpat-fixture",
            "--retries",
            "0",
            *(["--enum-cve"] if enum_cve else []),
            "--format",
            "json",
        ]
    )
    args._registry_console = Console()
    runner = AuditCommandRunner(args=args, spec=registry.build_registry_spec(args), emit_line=lambda line: None)
    record = runner.run_plan(registry.build_registry_plan(args)).records[0]
    assert record["is_gitlab"] is True
    assert record["provided_credentials_ok"] is valid
    assert all(method == "GET" for method, _ in requests)
    version_requests = [path for _, path in requests if path.endswith("/api/v4/version")]
    assert version_requests == (["http://127.0.0.1:18080/api/v4/version"] if valid and enum_cve else [])
    if valid and enum_cve:
        assert record["cve_enumeration"]["products"][0]["normalized_version"] == "17.7.1"
    elif not enum_cve:
        assert "cve_enumeration" not in record


@pytest.mark.parametrize("realm", ["", "file:///jwt/auth", "http://registry/token", "http:///jwt/auth"])
def test_unconfirmed_issuer_is_not_used_for_gitlab_version_requests(monkeypatch, realm) -> None:
    monkeypatch.setattr(registry, "_http_request_url", lambda *a, **k: pytest.fail("unexpected version request"))
    info = {"realm": realm}
    registry._enrich_registry_gitlab_version(info, 1, "glpat-fixture")
    assert "version" not in info


@pytest.mark.parametrize(
    "status,payload,error",
    [
        (401, {}, None),
        (403, {}, None),
        (200, {"version": "17.7.1"}, None),
        (200, {"version": "17.7.1", "revision": []}, None),
        (200, {"version": "unknown", "revision": "fixture"}, None),
        (200, [], None),
        (0, {}, "timeout"),
    ],
)
def test_unavailable_or_generic_api_version_does_not_produce_gitlab_release(
    monkeypatch, status, payload, error
) -> None:
    monkeypatch.setattr(
        registry, "_http_request_url", lambda *a, **k: (status, json.dumps(payload).encode(), {}, error)
    )
    info = {"realm": "http://gitlab/jwt/auth"}
    registry._enrich_registry_gitlab_version(info, 1, "glpat-fixture")
    assert "version" not in info
