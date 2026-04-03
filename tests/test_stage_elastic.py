from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import redposture_core.stage_elastic as elastic_stage
from redposture_core.stage_elastic import (
    _audit_elastic_host,
    _build_discover_query_string,
    _check_privileges,
    _elastic_headers,
    _extract_cat_endpoints,
    _extract_cat_plugins,
    _extract_discover_total,
    _fetch_cat_endpoints,
    _format_detail_records,
    _format_detect_record,
    _format_record,
    _looks_like_elastic_root,
    _normalize_access_level,
    _request_with_tls_fallback,
    _search_index,
    _verify_api_key_probe,
    _verify_authenticate,
    audit_elastic_targets,
    run_elastic_stage,
)


def test_elastic_headers_prefer_apikey_over_basic() -> None:
    headers = _elastic_headers(username="elastic", password="pass", api_token="token123")
    assert headers["Authorization"] == "ApiKey token123"

    basic_headers = _elastic_headers(username="elastic", password="pass", api_token=None)
    assert basic_headers["Authorization"].startswith("Basic ")


def test_detect_and_discover_helpers() -> None:
    payload = b'{"version":{"number":"8.12.1"},"tagline":"You Know, for Search"}'
    looks_like, version = _looks_like_elastic_root(200, payload, {"X-Elastic-Product": "Elasticsearch"})
    assert looks_like is True
    assert version == "8.12.1"

    assert (
        _normalize_access_level(can_read=True, can_write=False, can_manage=False, can_manage_security=False)
        == "read_only"
    )
    assert (
        _normalize_access_level(can_read=True, can_write=True, can_manage=False, can_manage_security=False)
        == "more_than_read"
    )
    assert (
        _normalize_access_level(can_read=None, can_write=False, can_manage=False, can_manage_security=False)
        == "unknown"
    )

    assert _extract_discover_total(15) == 15
    assert _extract_discover_total({"value": 9}) == 9
    assert _extract_discover_total({"value": "bad"}) == 0

    query = _build_discover_query_string()
    assert "password" in query
    assert ".kibana" in query
    assert "AKIA" in query
    assert "ASIA" in query
    assert "aws_secret_access_key" in query
    assert "service_token" in query
    assert "jwt" in query
    assert " OR " in query

    endpoints = _extract_cat_endpoints(b"/ _cat\n/_cat/indices\n/_cat/health\n/_cat/indices\n")
    assert endpoints == ["/_cat/indices", "/_cat/health"]

    plugins = _extract_cat_plugins(
        b'[{"name":"node-1","component":"analysis-icu","version":"8.13.0","description":"ICU analysis plugin"}]'
    )
    assert plugins == [
        {
            "node": "node-1",
            "component": "analysis-icu",
            "version": "8.13.0",
            "description": "ICU analysis plugin",
        }
    ]


def test_request_with_tls_fallback_switches_to_http(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def fake_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, path, timeout, insecure, ca_file, method, headers, data)
        calls.append(use_https)
        if use_https:
            return 0, b"", {}, "ssl: wrong version number"
        return 200, b"{}", {}, None

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_request)

    status, payload, _headers, error, scheme, effective_insecure, tls_auto_plain = _request_with_tls_fallback(
        "127.0.0.1",
        9200,
        "/",
        1.0,
        ca_file=None,
    )

    assert calls == [True, False]
    assert status == 200
    assert payload == b"{}"
    assert error is None
    assert scheme == "http"
    assert effective_insecure is False
    assert tls_auto_plain is True


def test_request_with_tls_fallback_retries_http_on_non_tls_error(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def fake_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, path, timeout, insecure, ca_file, method, headers, data)
        calls.append(use_https)
        if use_https:
            return 0, b"", {}, "connection timeout"
        return 200, b"{}", {}, None

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_request)

    status, _payload, _headers, error, scheme, effective_insecure, tls_auto_plain = _request_with_tls_fallback(
        "127.0.0.1",
        9200,
        "/",
        1.0,
        ca_file=None,
    )

    assert calls == [True, False]
    assert status == 200
    assert error is None
    assert scheme == "http"
    assert effective_insecure is False
    assert tls_auto_plain is True


def test_request_with_tls_fallback_double_fail_includes_ca_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def fake_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, path, timeout, insecure, ca_file, method, headers, data)
        calls.append(use_https)
        if use_https:
            return 0, b"", {}, "certificate verify failed"
        return 0, b"", {}, "Remote end closed connection without response"

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_request)

    status, _payload, _headers, error, scheme, effective_insecure, tls_auto_plain = _request_with_tls_fallback(
        "127.0.0.1",
        9200,
        "/",
        1.0,
        ca_file=None,
    )

    assert calls == [True, False]
    assert status == 0
    assert scheme == "http"
    assert effective_insecure is False
    assert tls_auto_plain is True
    assert isinstance(error, str)
    assert "https=certificate verify failed" in error
    assert "http=Remote end closed connection without response" in error
    assert "provide --ca-file <path>" in error


def test_verify_authenticate_and_privileges(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request_auth_ok(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, timeout, use_https, insecure, ca_file, method, headers, data)
        if path == "/_security/_authenticate":
            return 200, b'{"username":"elastic-reader"}', {}, None
        if path == "/_security/user/_has_privileges":
            return (
                200,
                b'{"cluster":{"manage":false,"manage_security":false},"index":{"*":{"read":true,"view_index_metadata":true,"write":false,"create_index":false}}}',
                {},
                None,
            )
        return 404, b"{}", {}, None

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_request_auth_ok)

    auth_ok, auth_error, username = _verify_authenticate(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "ApiKey token"},
    )
    assert auth_ok is True
    assert auth_error is None
    assert username == "elastic-reader"

    can_read, can_write, can_manage, can_manage_security, rights_error = _check_privileges(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "ApiKey token"},
    )
    assert (can_read, can_write, can_manage, can_manage_security) == (True, False, False, False)
    assert rights_error is None


def test_verify_api_key_probe_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_ok(
        *_args,
        **_kwargs,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        return 200, b'{"api_keys":[{"id":"k1"}]}', {}, None

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_ok)
    status, error = _verify_api_key_probe(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "ApiKey token"},
    )
    assert status == "ok"
    assert error is None

    def fake_denied(
        *_args,
        **_kwargs,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        return 403, b"{}", {}, None

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_denied)
    status, error = _verify_api_key_probe(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "ApiKey token"},
    )
    assert status == "denied"
    assert error == "Access Denied"

    def fake_error(
        *_args,
        **_kwargs,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        return 0, b"", {}, "connection timeout"

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_error)
    status, error = _verify_api_key_probe(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "ApiKey token"},
    )
    assert status == "error"
    assert error == "connection timeout"


def test_fetch_cat_endpoints_collects_cat_and_common_2xx_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (use_https, insecure, ca_file, method, headers, data)
        if path == "/_cat?help":
            return (
                200,
                b"aliases /_cat/aliases\nindices /_cat/indices\ntasks /_cat/tasks\n",
                {},
                None,
            )
        if path == "/_cat/":
            return 200, b"/_cat/health\n/_cat/nodes\n", {}, None
        if path in {"/_cat/aliases", "/_cat/indices", "/_cat/tasks", "/_cat/health", "/_cat/nodes"}:
            return 200, b"ok", {}, None
        if path in {"/_ingest/pipeline", "/_remote/info"}:
            return 403, b"{}", {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_request)
    endpoints, error, diagnostics = _fetch_cat_endpoints(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert error is None
    assert endpoints == ["/_cat/aliases", "/_cat/health", "/_cat/indices", "/_cat/nodes", "/_cat/tasks"]
    assert isinstance(diagnostics, list)
    assert any(item.get("endpoint") == "/_ingest/pipeline" for item in diagnostics)


def test_search_index_builds_query_and_returns_full_source(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, timeout, use_https, insecure, ca_file, headers)
        captured["path"] = path
        captured["method"] = method
        captured["body"] = json.loads((data or b"{}").decode("utf-8"))
        return (
            200,
            b'{"hits":{"total":{"value":250},"hits":[{"_id":"1","_source":{"password":"secret"}}]}}',
            {},
            None,
        )

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_request)

    total_hits, hits, error = _search_index(
        "127.0.0.1",
        9200,
        1.0,
        scheme="https",
        insecure=False,
        ca_file=None,
        auth_headers={"Authorization": "ApiKey token"},
        index_name=".security",
        query_string="password OR secret",
    )

    assert error is None
    assert total_hits == 250
    assert hits == [{"id": "1", "source": {"password": "secret"}}]
    assert str(captured["path"]).startswith("/.security/_search?size=10000")
    assert captured["method"] == "POST"
    assert captured["body"] == {
        "size": 10000,
        "query": {
            "query_string": {
                "query": "password OR secret",
                "default_operator": "OR",
                "analyze_wildcard": True,
            }
        },
    }


def test_audit_elastic_host_status_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    # not_elastic
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (200, b"<html>nginx</html>", {}, None, "http", False, True),
    )
    record = _audit_elastic_host(
        "127.0.0.1",
        9200,
        1.0,
        0,
        username=None,
        password=None,
        api_token=None,
        ca_file=None,
        show_endpoints=False,
        show_plugins=False,
        show_cluster=False,
        show_users=False,
        discover=False,
    )
    assert record["status"] == "not_elastic"

    # auth required without credentials
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            401,
            b'{"error":"missing authentication credentials"}',
            {"X-Elastic-Product": "Elasticsearch"},
            None,
            "https",
            False,
            False,
        ),
    )
    record = _audit_elastic_host(
        "127.0.0.1",
        9200,
        1.0,
        0,
        username=None,
        password=None,
        api_token=None,
        ca_file=None,
        show_endpoints=False,
        show_plugins=False,
        show_cluster=False,
        show_users=False,
        discover=False,
    )
    assert record["status"] == "auth_required"
    assert record["auth_required"] is True


def test_audit_elastic_host_resolves_version_with_authenticated_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            401,
            b'{"error":"missing authentication credentials"}',
            {"X-Elastic-Product": "Elasticsearch"},
            None,
            "https",
            False,
            False,
        ),
    )
    monkeypatch.setattr(elastic_stage, "_verify_authenticate", lambda *_args, **_kwargs: (True, None, "elastic"))
    monkeypatch.setattr(elastic_stage, "_resolve_server_version_with_auth", lambda *_args, **_kwargs: ("8.13.4", None))
    monkeypatch.setattr(elastic_stage, "_verify_api_key_probe", lambda *_args, **_kwargs: ("ok", None))
    monkeypatch.setattr(elastic_stage, "_check_privileges", lambda *_args, **_kwargs: (True, False, False, False, None))

    record = _audit_elastic_host(
        "127.0.0.1",
        9200,
        1.0,
        0,
        username=None,
        password=None,
        api_token="token",
        ca_file=None,
        show_endpoints=False,
        show_plugins=False,
        show_cluster=False,
        show_users=False,
        discover=False,
    )

    assert record["status"] == "valid_credentials"
    assert record["server_version"] == "8.13.4"
    assert record["api_key_probe_status"] == "ok"
    assert record["api_key_probe_error"] is None


def test_audit_elastic_host_with_auth_and_features(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            b'{"version":{"number":"8.13.0"},"tagline":"You Know, for Search"}',
            {"X-Elastic-Product": "Elasticsearch"},
            None,
            "https",
            False,
            False,
        ),
    )
    monkeypatch.setattr(elastic_stage, "_verify_authenticate", lambda *_args, **_kwargs: (True, None, "elastic"))
    monkeypatch.setattr(elastic_stage, "_check_privileges", lambda *_args, **_kwargs: (True, True, False, False, None))
    monkeypatch.setattr(elastic_stage, "_verify_api_key_probe", lambda *_args, **_kwargs: ("not_run", None))
    monkeypatch.setattr(elastic_stage, "_fetch_cat_endpoints", lambda *_args, **_kwargs: (["/_cat/health"], None, []))
    monkeypatch.setattr(
        elastic_stage,
        "_fetch_cat_plugins",
        lambda *_args, **_kwargs: (
            [
                {
                    "node": "n1",
                    "component": "analysis-icu",
                    "version": "8.13.0",
                    "description": "ICU analysis plugin",
                }
            ],
            None,
        ),
    )
    monkeypatch.setattr(
        elastic_stage,
        "_fetch_cluster_data",
        lambda *_args, **_kwargs: (
            {"cluster_name": "lab", "status": "yellow", "number_of_nodes": 2, "number_of_data_nodes": 1},
            [{"name": "n1", "ip": "10.0.0.1", "host": "node-1", "roles": ["master"]}],
            None,
        ),
    )
    monkeypatch.setattr(
        elastic_stage,
        "_fetch_cluster_misconfig_findings",
        lambda *_args, **_kwargs: (
            [
                {
                    "key": "xpack.security.enabled",
                    "value": "false",
                    "reason": "security is disabled",
                }
            ],
            None,
        ),
    )
    monkeypatch.setattr(
        elastic_stage,
        "_fetch_security_users",
        lambda *_args, **_kwargs: ([{"username": "elastic", "roles": ["superuser"], "enabled": True}], None),
    )
    monkeypatch.setattr(
        elastic_stage,
        "_collect_discover_results",
        lambda *_args, **_kwargs: (
            [
                {
                    "index": ".security",
                    "total_hits": 320,
                    "shown_hits": 200,
                    "truncated": True,
                    "hits": [{"id": "1", "source": {"password": "secret"}}],
                    "error": None,
                }
            ],
            None,
        ),
    )

    record = _audit_elastic_host(
        "127.0.0.1",
        9200,
        1.0,
        0,
        username="elastic",
        password="ElasticRead!2026",
        api_token=None,
        ca_file=None,
        show_endpoints=True,
        show_plugins=True,
        show_cluster=True,
        show_users=True,
        discover=True,
    )

    assert record["status"] == "valid_credentials"
    assert record["access_level"] == "more_than_read"
    assert record["server_version"] == "8.13.0"
    assert record["cat_endpoints"] == ["/_cat/health"]
    assert isinstance(record["cat_plugins"], list)
    assert isinstance(record["cluster_nodes"], list)
    assert isinstance(record["users"], list)
    assert isinstance(record["discover_results"], list)

    status_line = _format_record(record, "txt")
    assert "[+] elastic:ElasticRead!2026" in status_line
    assert "(plugins:1)" not in status_line
    assert "(access:more_than_read)" not in status_line

    detail_lines = _format_detail_records(record, "txt")
    detail_text = "\n".join(detail_lines)
    assert "[*] 1 Endpoints" in detail_text
    assert "[*] 1 Plugins" in detail_text
    assert "[*] Cluster" in detail_text
    assert "[*] 1 Cluster Nodes" in detail_text
    assert "[*] Misconfig Findings" in detail_text
    assert "key=xpack.security.enabled value=false reason=security is disabled" in detail_text
    assert "[*] 1 Users" in detail_text
    assert "[*] 320 Discover Hits" in detail_text
    assert "showing first 200 of 320 hits" in detail_text

    detail_json = [_json for _json in _format_detail_records(record, "json")]
    parsed_json = [json.loads(item) for item in detail_json]
    assert any(item.get("type") == "misconfig_dump" for item in parsed_json)


def test_audit_targets_and_renderers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-04-03T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9200,
            "is_elastic": True,
            "status": "open_no_auth",
            "auth_required": False,
            "server_version": "8.12.0",
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_token": False,
            "api_token": None,
            "api_key_probe_status": "not_run",
            "api_key_probe_error": None,
            "effective_username": None,
            "auth_valid": None,
            "show_endpoints": True,
            "show_plugins": False,
            "show_cluster": False,
            "show_users": False,
            "discover": False,
            "cat_endpoints": ["/_cat/health", "/_cat/indices"],
            "endpoint_diagnostics": [],
            "cat_plugins": None,
            "cluster_health": None,
            "cluster_nodes": None,
            "misconfig_findings": None,
            "misconfig_error": None,
            "users": None,
            "discover_results": None,
            "can_read": None,
            "can_write": None,
            "can_manage": None,
            "can_manage_security": None,
            "access_level": "unknown",
            "rights_error": None,
            "endpoints_error": None,
            "plugins_error": None,
            "cluster_error": None,
            "users_error": None,
            "discover_error": None,
            "scheme": "http",
            "insecure_effective": False,
            "tls_auto_plain": True,
            "elapsed_ms": 4,
            "error": None,
        }

    monkeypatch.setattr(elastic_stage, "_audit_elastic_host", fake_audit)

    lines: list[str] = []
    total, open_no_auth, valid, auth_required, failed = audit_elastic_targets(
        hosts=["127.0.0.1"],
        port=9200,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        api_token=None,
        ca_file=None,
        show_endpoints=True,
        show_plugins=False,
        show_cluster=False,
        show_users=False,
        discover=False,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        logger=None,
        append_output=False,
        suppress_timeout_status_lines=False,
    )

    assert (total, open_no_auth, valid, auth_required, failed) == (1, 1, 0, 0, 0)
    assert any("[*] Elasticsearch API" in line for line in lines)
    assert any("[+] anonymous access" in line for line in lines)
    assert any("[*] 2 Endpoints" in line for line in lines)

    detect_json = json.loads(_format_detect_record(fake_audit(), "json"))
    assert detect_json["service"] == "elastic"
    assert detect_json["detected"] is True


def test_run_elastic_stage_validation_and_apikey_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    args_bad_pair = SimpleNamespace(
        timeout=1.0,
        retries=0,
        port=9200,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        username="elastic",
        password=None,
        apitoken=None,
        endpoints=False,
        plugins=False,
        cluster=False,
        user=False,
        discover=False,
        output=None,
        output_format="txt",
        debug=False,
        workers=1,
        insecure=False,
        ca_file=None,
    )
    rc = run_elastic_stage(args_bad_pair, logger=SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 2

    captured: dict[str, object] = {}

    def fake_audit_targets(**kwargs):
        captured.update(kwargs)
        return 1, 0, 1, 0, 0

    monkeypatch.setattr(elastic_stage, "audit_elastic_targets", fake_audit_targets)

    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        port=9200,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        username="elastic",
        password="ElasticRead!2026",
        apitoken="ZXM6bGFiLXRva2Vu",
        endpoints=False,
        plugins=False,
        cluster=False,
        user=False,
        discover=False,
        output=None,
        output_format="txt",
        debug=False,
        workers=1,
        insecure=False,
        ca_file=None,
    )

    rc = run_elastic_stage(args, logger=SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 0
    assert captured["username"] is None
    assert captured["password"] is None
    assert captured["api_token"] == "ZXM6bGFiLXRva2Vu"
    assert captured["show_plugins"] is False
