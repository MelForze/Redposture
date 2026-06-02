from __future__ import annotations

import gzip
import io
import json
import ssl
import urllib.error
import zlib
from types import SimpleNamespace

import pytest

import redposture_core.stage_elastic as elastic_stage
from redposture_core.stage_elastic import (
    _audit_elastic_host,
    _build_discover_query_string,
    _check_privileges,
    _classify_detect_probe,
    _elastic_headers,
    _evaluate_detect_decision,
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
    run_elastic_stage,
)
from tests.stage_runtime_helpers import patch_runner_for_legacy_target_fake, run_module_targets_for_test


def test_elastic_headers_prefer_apikey_over_basic() -> None:
    headers = _elastic_headers(username="elastic", password="pass", api_token="token123")
    assert headers["Authorization"] == "ApiKey token123"

    basic_headers = _elastic_headers(username="elastic", password="pass", api_token=None)
    assert basic_headers["Authorization"].startswith("Basic ")


def test_elastic_default_credential_runs_are_exact_and_deduplicated() -> None:
    assert elastic_stage._build_credential_runs(None, None, True) == [
        ("elastic", "changeme"),
        ("elastic", "elastic"),
        ("elastic", "password"),
    ]
    assert elastic_stage._build_credential_runs("elastic", "elastic", True) == [
        ("elastic", "elastic"),
        ("elastic", "changeme"),
        ("elastic", "password"),
    ]
    assert elastic_stage._build_credential_runs(None, None, False) == [(None, None)]


def test_detect_and_discover_helpers() -> None:
    payload = b'{"version":{"number":"8.12.1"},"tagline":"You Know, for Search"}'
    looks_like, version = _looks_like_elastic_root(200, payload, {"X-Elastic-Product": "Elasticsearch"})
    assert looks_like is True
    assert version == "8.12.1"

    prefixed_payload = (
        b"HTTP/1.1 200 Connection established\r\n\r\n"
        b'{"name":"elk-01","cluster_name":"elastic-cluster","version":{"number":"8.17.3"},"tagline":"You Know, for Search"}'
    )
    looks_like, version = _looks_like_elastic_root(200, prefixed_payload, {})
    assert looks_like is True
    assert version == "8.17.3"

    gzipped_payload = gzip.compress(
        b'{"name":"elk-01","cluster_name":"elastic-cluster","version":{"number":"8.17.3"},"tagline":"You Know, for Search"}'
    )
    looks_like, version = _looks_like_elastic_root(200, gzipped_payload, {"Content-Encoding": "gzip"})
    assert looks_like is True
    assert version == "8.17.3"

    deflated_payload = zlib.compress(
        b'{"name":"elk-01","cluster_name":"elastic-cluster","version":{"number":"8.17.3"},"tagline":"You Know, for Search"}'
    )
    looks_like, version = _looks_like_elastic_root(200, deflated_payload, {"Content-Encoding": "deflate"})
    assert looks_like is True
    assert version == "8.17.3"

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

    assert elastic_stage._extract_version_hint(b'{"nodes":{"n1":{"version":"8.17.3"}}}') == "8.17.3"


def test_classify_detect_probe_rejects_opensearch_markers() -> None:
    payload = (
        b'{"name":"os-01","cluster_name":"opensearch-cluster","version":{"number":"2.14.0","distribution":"opensearch"},'
        b'"tagline":"The OpenSearch Project: https://opensearch.org/"}'
    )
    classified = _classify_detect_probe("/", 200, payload, {}, None)
    assert classified["signal_kind"] == "hard_negative"
    assert "vendor_opensearch_tagline" in classified["signals"]


def test_detect_decision_policy_matrix() -> None:
    hard_positive = {
        "path": "/",
        "signal_kind": "hard_positive",
        "signals": ["header_x_elastic_product"],
        "version": "8.17.3",
    }
    hard_negative = {
        "path": "/",
        "signal_kind": "hard_negative",
        "signals": ["vendor_opensearch_tagline"],
        "version": None,
    }
    soft_cluster = {
        "path": "/_cluster/health",
        "signal_kind": "soft_positive",
        "signals": ["cluster_health_shape"],
        "version": None,
    }
    soft_cat = {
        "path": "/_cat/health",
        "signal_kind": "soft_positive",
        "signals": ["cat_health_text_shape"],
        "version": None,
    }
    neutral = {"path": "/", "signal_kind": "neutral", "signals": [], "version": None}

    decision = _evaluate_detect_decision([hard_positive, hard_negative])
    assert decision["detected"] is True
    assert decision["confidence"] == "medium"

    decision = _evaluate_detect_decision([soft_cluster, soft_cat])
    assert decision["detected"] is True
    assert decision["confidence"] == "medium"

    decision = _evaluate_detect_decision([hard_negative])
    assert decision["detected"] is False
    assert decision["confidence"] == "low"

    decision = _evaluate_detect_decision([neutral])
    assert decision["detected"] is True
    assert decision["confidence"] == "low"


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


def test_request_with_tls_fallback_double_fail_has_combined_errors(monkeypatch: pytest.MonkeyPatch) -> None:
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
    assert "provide --ca-file <path>" not in error


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
            "simple_query_string": {
                "query": "password OR secret",
                "fields": ["*"],
                "default_operator": "OR",
                "analyze_wildcard": True,
                "lenient": True,
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


def test_audit_elastic_host_runs_extended_detect_pass_on_ambiguous_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            b"{}",
            {"Content-Type": "application/json"},
            None,
            "https",
            True,
            False,
        ),
    )

    calls: list[tuple[str, float]] = []

    def fake_detect_probe(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        preferred_scheme: str,
        ca_file: str | None,
    ) -> tuple[int, bytes, dict[str, str], str | None, str]:
        _ = (host, port, preferred_scheme, ca_file)
        calls.append((path, timeout))
        if len(calls) <= 4:
            return 404, b"{}", {"Content-Type": "application/json"}, None, "https"
        if path == "/_cluster/health":
            return 200, b'{"cluster_name":"elastic-cluster","status":"yellow"}', {}, None, "https"
        if path == "/_cat/health":
            return 200, b"cluster status node.total node.data\nelastic-cluster yellow 1 1", {}, None, "https"
        return 404, b"{}", {"Content-Type": "application/json"}, None, "https"

    monkeypatch.setattr(elastic_stage, "_request_detect_probe", fake_detect_probe)

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

    assert record["is_elastic"] is True
    assert record["status"] == "open_no_auth"
    assert record["detect_confidence"] == "medium"
    assert isinstance(record["detect_probe_trace"], list)
    assert len(record["detect_probe_trace"]) == 9
    assert 2.5 in [timeout for _path, timeout in calls]


def test_audit_elastic_host_skips_extended_detect_pass_on_high_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            b'{"name":"elk-01","cluster_name":"elastic-cluster","version":{"number":"8.17.3"},"tagline":"You Know, for Search"}',
            {"X-Elastic-Product": "Elasticsearch"},
            None,
            "https",
            True,
            False,
        ),
    )

    calls: list[tuple[str, float]] = []

    def fake_detect_probe(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        preferred_scheme: str,
        ca_file: str | None,
    ) -> tuple[int, bytes, dict[str, str], str | None, str]:
        _ = (host, port, preferred_scheme, ca_file)
        calls.append((path, timeout))
        return 404, b"{}", {"Content-Type": "application/json"}, None, "https"

    monkeypatch.setattr(elastic_stage, "_request_detect_probe", fake_detect_probe)

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

    assert record["is_elastic"] is True
    assert record["detect_confidence"] == "high"
    assert len(calls) == 4
    assert all(timeout == 1.0 for _path, timeout in calls)


def test_audit_elastic_host_rechecks_http_when_https_looks_non_elastic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (200, b"<html>proxy</html>", {}, None, "https", True, False),
    )

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
        if use_https:
            return 200, b"<html>proxy</html>", {}, None
        return (
            200,
            b'{"name":"elk-01","cluster_name":"elastic-cluster","version":{"number":"8.17.3"},"tagline":"You Know, for Search"}',
            {"X-Elastic-Product": "Elasticsearch"},
            None,
        )

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_request)

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

    assert record["status"] == "open_no_auth"
    assert record["is_elastic"] is True
    assert record["scheme"] == "http"
    assert record["tls_auto_plain"] is True
    assert record["server_version"] == "8.17.3"


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


def test_audit_elastic_host_auth_required_resolves_version_without_auth_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            401,
            b'{"error":{"type":"security_exception","reason":"missing authentication credentials"}}',
            {"X-Elastic-Product": "Elasticsearch"},
            None,
            "https",
            True,
            False,
        ),
    )
    monkeypatch.setattr(
        elastic_stage, "_request_detect_probe", lambda *_args, **_kwargs: (401, b"{}", {}, None, "https")
    )
    monkeypatch.setattr(
        elastic_stage, "_resolve_server_version_without_auth", lambda *_args, **_kwargs: ("8.17.3", None)
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
    assert record["server_version"] == "8.17.3"


def test_audit_elastic_host_uses_root_status_for_auth_required_and_hides_version_probe_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            b'{"name":"elk-01","cluster_name":"elastic-cluster"}',
            {"Content-Type": "application/json"},
            None,
            "https",
            True,
            False,
        ),
    )

    def fake_detect_probe(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        preferred_scheme: str,
        ca_file: str | None,
    ) -> tuple[int, bytes, dict[str, str], str | None, str]:
        _ = (preferred_scheme, ca_file)
        if path == "/_security/_authenticate":
            return (
                401,
                b'{"error":{"type":"security_exception","reason":"missing authentication credentials"}}',
                {"Content-Type": "application/json"},
                None,
                "https",
            )
        return 404, b"{}", {"Content-Type": "application/json"}, None, "https"

    monkeypatch.setattr(elastic_stage, "_request_detect_probe", fake_detect_probe)
    monkeypatch.setattr(elastic_stage, "_resolve_server_version_without_auth", lambda *_args, **_kwargs: (None, "x"))

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

    assert record["is_elastic"] is True
    assert record["status"] == "open_no_auth"
    assert record["auth_required"] is False
    assert record["error"] in {None, ""}


def test_resolve_server_version_without_auth_prefers_root_tls_fallback_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            b'{"name":"elk-01","cluster_name":"elastic-cluster","version":{"number":"8.17.3"},"tagline":"You Know, for Search"}',
            {"Content-Type": "application/json"},
            None,
            "https",
            True,
            False,
        ),
    )
    monkeypatch.setattr(
        elastic_stage,
        "_request_detect_probe",
        lambda *_args, **_kwargs: (0, b"", {}, "should_not_be_used", "https"),
    )

    version, error = elastic_stage._resolve_server_version_without_auth(
        "127.0.0.1",
        9200,
        1.0,
        preferred_scheme="https",
        ca_file=None,
    )

    assert version == "8.17.3"
    assert error is None


def test_resolve_server_version_without_auth_uses_cat_nodes_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            401,
            b'{"error":"missing authentication credentials"}',
            {},
            None,
            "https",
            True,
            False,
        ),
    )

    def fake_detect_probe(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        preferred_scheme: str,
        ca_file: str | None,
    ) -> tuple[int, bytes, dict[str, str], str | None, str]:
        _ = (preferred_scheme, ca_file)
        if path == "/_cat/nodes?format=json&h=version":
            return 200, b'[{"version":"8.17.3"}]', {"Content-Type": "application/json"}, None, "https"
        return 401, b'{"error":"missing authentication credentials"}', {}, None, "https"

    monkeypatch.setattr(elastic_stage, "_request_detect_probe", fake_detect_probe)

    version, error = elastic_stage._resolve_server_version_without_auth(
        "127.0.0.1",
        9200,
        1.0,
        preferred_scheme="https",
        ca_file=None,
    )

    assert version == "8.17.3"
    assert error is None


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
    total, open_no_auth, valid, auth_required, failed = run_module_targets_for_test(
        "elastic",
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
        defcreds=False,
    )
    rc = run_elastic_stage(args_bad_pair, logger=SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 2

    captured: dict[str, object] = {}

    def fake_audit_targets(**kwargs):
        captured.update(kwargs)
        return 1, 0, 1, 0, 0

    patch_runner_for_legacy_target_fake(monkeypatch, "elastic", fake_audit_targets)

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
        defcreds=True,
    )

    rc = run_elastic_stage(args, logger=SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 0
    assert captured["username"] is None
    assert captured["password"] is None
    assert captured["api_token"] == "ZXM6bGFiLXRva2Vu"
    assert captured["show_plugins"] is False


def test_run_elastic_stage_defcreds_expands_default_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str | None, str | None]] = []

    def fake_audit_targets(**kwargs):
        captured.append((kwargs["username"], kwargs["password"]))
        return 1, 0, 0, 1, 0

    class _FakeProgressBar:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def advance(self, _amount: int = 1) -> None:
            return

        def close(self) -> None:
            return

    patch_runner_for_legacy_target_fake(monkeypatch, "elastic", fake_audit_targets)
    monkeypatch.setattr(
        elastic_stage,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        port=9200,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        username=None,
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
        ca_file=None,
        defcreds=True,
        proxy=None,
    )

    rc = run_elastic_stage(args, logger=SimpleNamespace(log=lambda *a, **k: None))

    assert rc == 0
    assert captured == [
        ("elastic", "changeme"),
        ("elastic", "elastic"),
        ("elastic", "password"),
    ]


def test_run_elastic_stage_multi_group_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Console:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug

        def error(self, _message: str) -> None:
            return

        def warn(self, _message: str) -> None:
            return

        def info(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def render_tagged_payload_line(self, _line: str, _tag: str, payload_color: str | None = None) -> bool:
            _ = payload_color
            return False

    class _FakeProgress:
        instances: list[_FakeProgress] = []

        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            self.total = total
            self.advances: list[int] = []
            self.closed = False
            type(self).instances.append(self)

        def advance(self, step: int = 1) -> None:
            self.advances.append(int(step))

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(elastic_stage, "Console", _Console)
    monkeypatch.setattr(
        elastic_stage,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgress(label, total, **kwargs),
    )
    monkeypatch.setattr(elastic_stage, "collect_scan_ports", lambda *_a, **_k: [9200, 9201])
    monkeypatch.setattr(
        elastic_stage,
        "collect_scan_target_specs",
        lambda *_a, **_k: [SimpleNamespace(host="127.0.0.1", scheme="", explicit_port=None)],
    )
    monkeypatch.setattr(
        elastic_stage,
        "build_scan_execution_groups",
        lambda *_a, **_k: [
            SimpleNamespace(hosts=["127.0.0.1"], port=9200, scheme_hint=None),
            SimpleNamespace(hosts=["127.0.0.1"], port=9201, scheme_hint=None),
        ],
    )

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (len(kwargs["hosts"]), 1, 0, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "elastic", fake_audit_targets)

    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        port=9200,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        username=None,
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
        ca_file=None,
    )
    rc = run_elastic_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert len(captured) == 2
    assert all(call["show_progress"] is False for call in captured)
    assert len(_FakeProgress.instances) == 1
    progress = _FakeProgress.instances[0]
    assert progress.total == 2
    assert progress.advances == [1, 1]
    assert progress.closed is True


def test_run_elastic_stage_credential_file_output_uses_single_global_progress(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    class _Console:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug

        def error(self, _message: str) -> None:
            return

        def warn(self, _message: str) -> None:
            return

        def info(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def render_tagged_payload_line(self, _line: str, _tag: str, payload_color: str | None = None) -> bool:
            _ = payload_color
            return False

    class _FakeProgress:
        instances: list[_FakeProgress] = []

        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            self.total = int(total)
            self.advances: list[int] = []
            self.closed = False
            type(self).instances.append(self)

        def advance(self, step: int = 1) -> None:
            self.advances.append(int(step))

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(elastic_stage, "Console", _Console)
    monkeypatch.setattr(
        elastic_stage,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgress(label, total, **kwargs),
    )
    monkeypatch.setattr(elastic_stage, "collect_scan_ports", lambda *_a, **_k: [9200])
    monkeypatch.setattr(
        elastic_stage,
        "collect_scan_target_specs",
        lambda *_a, **_k: [
            SimpleNamespace(host="10.0.0.1", scheme=None, explicit_port=None),
            SimpleNamespace(host="10.0.0.2", scheme=None, explicit_port=None),
        ],
    )
    monkeypatch.setattr(
        elastic_stage,
        "build_scan_execution_groups",
        lambda *_a, **_k: [SimpleNamespace(hosts=["10.0.0.1", "10.0.0.2"], port=9200, scheme_hint=None)],
    )
    monkeypatch.setattr(
        elastic_stage,
        "filter_open_tcp_hosts_for_credential_file",
        lambda hosts, *_a, **_k: list(hosts),
    )

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (len(kwargs["hosts"]), 0, 0, 1, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "elastic", fake_audit_targets)

    creds_file = tmp_path / "creds.txt"
    creds_file.write_text("alice:one\nbob:two\n", encoding="utf-8")
    output_file = tmp_path / "elastic.txt"

    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        port=9200,
        ports=None,
        targets="targets.txt",
        hosts=None,
        hosts_file=None,
        username=str(creds_file),
        password=None,
        apitoken=None,
        endpoints=True,
        plugins=False,
        cluster=False,
        user=False,
        discover=False,
        output=str(output_file),
        output_format="txt",
        debug=False,
        workers=1,
        ca_file=None,
        proxy=None,
        defcreds=False,
    )

    rc = run_elastic_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))

    assert rc == 0
    assert [(call["hosts"], call["username"], call["password"]) for call in captured] == [
        (["10.0.0.1"], None, None),
        (["10.0.0.1"], "alice", "one"),
        (["10.0.0.1"], "bob", "two"),
        (["10.0.0.2"], None, None),
        (["10.0.0.2"], "alice", "one"),
        (["10.0.0.2"], "bob", "two"),
    ]
    assert all(call["show_progress"] is False for call in captured)
    assert len(_FakeProgress.instances) == 1
    progress = _FakeProgress.instances[0]
    assert progress.total == 6
    assert progress.advances == [1, 1, 1, 1, 1, 1]
    assert progress.closed is True


def test_audit_elastic_host_debug_stage_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_request_with_tls_fallback",
        lambda *_args, **_kwargs: (
            200,
            b'{"name":"elk","cluster_name":"elastic-cluster","version":{"number":"8.17.3"},"tagline":"You Know, for Search"}',
            {"X-Elastic-Product": "Elasticsearch"},
            None,
            "https",
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        elastic_stage,
        "_request_detect_probe",
        lambda *_args, **_kwargs: (404, b"{}", {"Content-Type": "application/json"}, None, "https"),
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
        debug=True,
    )

    assert record["status"] == "open_no_auth"
    assert isinstance(record.get("stages"), list)
    stage_names = [str(item.get("stage_name") or "") for item in record["stages"] if isinstance(item, dict)]
    assert "detect_protocol" in stage_names
    assert "auth_inference_credentials" in stage_names
    assert "access_capabilities" in stage_names
    assert "data" in stage_names
    assert isinstance(record.get("stage_durations_ms"), dict)
    assert isinstance(record.get("stage_attempts"), dict)
    debug_events = record.get("debug_events") or []
    assert any("stage_timing_summary" in str(item) for item in debug_events)


def test_audit_elastic_targets_two_pass_gate_and_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool]] = []

    def fake_call(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        api_token: str | None,
        ca_file: str | None,
        show_endpoints: bool,
        show_plugins: bool,
        show_cluster: bool,
        show_users: bool,
        discover: bool,
        preferred_scheme: str | None,
        debug: bool,
        run_deep_checks: bool,
        debug_emit,
    ) -> dict[str, object]:
        _ = (
            port,
            timeout,
            retries,
            username,
            password,
            api_token,
            ca_file,
            show_endpoints,
            show_plugins,
            show_cluster,
            show_users,
            discover,
            preferred_scheme,
            debug,
            debug_emit,
        )
        calls.append((host, run_deep_checks))
        status = "open_no_auth" if host == "10.0.0.1" else "auth_required"
        return {
            "timestamp": "2026-04-10T00:00:00Z",
            "host": host,
            "port": 9200,
            "is_elastic": True,
            "status": status,
            "auth_required": status == "auth_required",
            "server_version": "8.17.3",
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_token": False,
            "api_token": None,
            "api_key_probe_status": "not_run",
            "api_key_probe_error": None,
            "effective_username": None,
            "auth_valid": None,
            "show_endpoints": False,
            "show_plugins": False,
            "show_cluster": False,
            "show_users": False,
            "discover": False,
            "cat_endpoints": None,
            "endpoint_diagnostics": None,
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
            "scheme": "https",
            "insecure_effective": False,
            "tls_auto_plain": False,
            "detect_confidence": "high",
            "detect_signals": ["header_x_elastic_product"],
            "detect_probe_trace": [{"path": "/", "status": 200, "scheme": "https"}],
            "elapsed_ms": 1,
            "error": None,
            "stages": [],
            "stage_failed_at": None,
            "stage_durations_ms": {},
            "stage_attempts": {},
            "debug_events": [],
            "debug_events_streamed": False,
        }

    monkeypatch.setattr(elastic_stage, "_call_audit_elastic_host_with_thread_debug", fake_call)

    text_lines: list[str] = []
    debug_lines: list[str] = []
    totals = run_module_targets_for_test(
        "elastic",
        hosts=["10.0.0.1", "10.0.0.2"],
        port=9200,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        api_token=None,
        ca_file=None,
        show_endpoints=False,
        show_plugins=False,
        show_cluster=False,
        show_users=False,
        discover=False,
        output_path=None,
        output_format="txt",
        emit_line=text_lines.append,
        suppress_timeout_status_lines=False,
        debug_emit=debug_lines.append,
    )

    assert totals == (2, 1, 0, 1, 0)
    assert calls == [
        ("10.0.0.1", False),
        ("10.0.0.2", False),
        ("10.0.0.1", True),
    ]
    assert any("pass=1 detect start total=2" in line for line in debug_lines)
    assert any("pass=2 deep start total=1" in line for line in debug_lines)
    assert any("10.0.0.1:9200 stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("10.0.0.2:9200 stage2_gate=skip reason=status=auth_required" in line for line in debug_lines)


def test_elastic_misconfig_helpers_and_fetch_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    assert elastic_stage._normalize_setting_value(True) == "true"
    assert elastic_stage._normalize_setting_value(False) == "false"
    assert elastic_stage._normalize_setting_value(None) == ""
    assert elastic_stage._is_truthy_setting("enabled") is True
    assert elastic_stage._is_false_setting("off") is True
    assert elastic_stage._is_wildcard_origin("https://*") is True
    assert elastic_stage._is_world_bind("127.0.0.1,0.0.0.0") is True

    cluster_flat = elastic_stage._collect_cluster_flat_settings(
        {
            "persistent": {"xpack": {"security": {"enabled": False}}},
            "transient": {"http": {"cors": {"enabled": True, "allow-origin": "*"}}},
            "defaults": {"network": {"host": "::"}, "script": {"allowed_types": "inline,stored"}},
        }
    )
    nodes_flat = elastic_stage._collect_nodes_flat_settings(
        {
            "nodes": {
                "node-1": {
                    "settings": {
                        "http": {"bind_host": "0.0.0.0"},
                        "script": {"inline": True},
                        "xpack": {"security": {"http": {"ssl": {"enabled": False}}}},
                    }
                }
            }
        }
    )
    merged = elastic_stage._merge_settings_values(cluster_flat, nodes_flat)
    findings = elastic_stage._build_misconfig_findings(merged)
    reasons = {str(item.get("reason")) for item in findings}
    assert "security is disabled" in reasons
    assert "http tls is disabled" in reasons
    assert "service is bound to all interfaces" in reasons
    assert "script execution appears permissive" in reasons
    assert "inline script execution is enabled" in reasons
    assert "cors allows wildcard origins" in reasons

    request_calls: list[str] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        headers: dict[str, str] | None,
        method: str = "GET",
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (use_https, insecure, ca_file, headers, method, data)
        request_calls.append(path)
        if path.startswith("/_cluster/settings"):
            payload = json.dumps(
                {"persistent": {"xpack": {"security": {"enabled": False}}}, "transient": {}, "defaults": {}}
            ).encode("utf-8")
            return 200, payload, {"content-type": "application/json"}, None
        if path.startswith("/_nodes/settings"):
            payload = json.dumps({"nodes": {"n1": {"settings": {"http": {"bind_host": "0.0.0.0"}}}}}).encode("utf-8")
            return 200, payload, {"content-type": "application/json"}, None
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr(elastic_stage, "_elastic_request", fake_request)
    findings_fetch, fetch_error = elastic_stage._fetch_cluster_misconfig_findings(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert fetch_error is None
    assert isinstance(findings_fetch, list) and findings_fetch
    assert request_calls == [
        "/_cluster/settings?include_defaults=true&flat_settings=true",
        "/_nodes/settings?flat_settings=true",
    ]

    monkeypatch.setattr(
        elastic_stage,
        "_elastic_request",
        lambda *_args, **_kwargs: (403, b"{}", {"content-type": "application/json"}, None),
    )
    denied_findings, denied_error = elastic_stage._fetch_cluster_misconfig_findings(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert denied_findings is None
    assert denied_error == "Access Denied"


def test_elastic_users_and_indices_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    def users_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        headers: dict[str, str] | None,
        method: str = "GET",
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (use_https, insecure, ca_file, headers, method, data)
        assert path == "/_security/user"
        payload = json.dumps(
            {
                "elastic": {"roles": ["superuser"], "enabled": True, "full_name": "Elastic User"},
                "viewer": {"roles": ["monitoring_user"], "enabled": False, "full_name": ""},
                "invalid": "skip-me",
            }
        ).encode("utf-8")
        return 200, payload, {"content-type": "application/json"}, None

    monkeypatch.setattr(elastic_stage, "_elastic_request", users_request)
    users, users_error = elastic_stage._fetch_security_users(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert users_error is None
    assert users == [
        {"username": "elastic", "roles": ["superuser"], "enabled": True, "full_name": "Elastic User"},
        {"username": "viewer", "roles": ["monitoring_user"], "enabled": False, "full_name": ""},
    ]

    monkeypatch.setattr(
        elastic_stage,
        "_elastic_request",
        lambda *_args, **_kwargs: (200, b'{"not":"a-list"}', {"content-type": "application/json"}, None),
    )
    indices, indices_error = elastic_stage._list_index_names(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert indices is None
    assert indices_error == "invalid indices payload"

    monkeypatch.setattr(
        elastic_stage,
        "_elastic_request",
        lambda *_args, **_kwargs: (
            200,
            b'[{"index":"b"},{"index":"a"},{"index":"a"},{"skip":1},"x"]',
            {"content-type": "application/json"},
            None,
        ),
    )
    indices, indices_error = elastic_stage._list_index_names(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert indices_error is None
    assert indices == ["a", "b"]


def test_elastic_low_level_error_and_tls_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    assert elastic_stage._clip("abcdef", 3) == "abc"
    assert elastic_stage._clip("abcdef", 2) == "ab"
    assert elastic_stage._clip("abcdef", 0) == ""

    assert elastic_stage._friendly_error_text("") == "connection failed"
    assert (
        elastic_stage._friendly_error_text("<urlopen error [Errno 111] Connection refused>")
        == "connection refused (service is not listening on target port)"
    )
    assert elastic_stage._friendly_error_text("[Errno 60] timed out") == "connection timeout"
    assert elastic_stage._friendly_error_text("[Errno -2] Name or service not known") == "dns lookup failed"
    assert elastic_stage._friendly_error_text("[Errno 101] no route to host") == "network unreachable"
    assert (
        elastic_stage._friendly_error_text("operation not permitted by policy")
        == "operation not permitted by local environment"
    )
    assert elastic_stage._friendly_error_text("[Errno 1] custom detail") == "custom detail"

    assert elastic_stage._friendly_error_from_exception(TimeoutError()) == "connection timeout"
    assert (
        elastic_stage._friendly_error_from_exception(urllib.error.URLError(OSError("[Errno 111] Connection refused")))
        == "connection refused (service is not listening on target port)"
    )
    assert elastic_stage._is_tls_or_protocol_error("ssl wrong version number") is True
    assert elastic_stage._is_tls_or_protocol_error("plain text") is False

    insecure_ctx = elastic_stage._build_ssl_context(insecure=True, ca_file=None)
    assert insecure_ctx.check_hostname is False
    assert insecure_ctx.verify_mode == ssl.CERT_NONE

    captured: dict[str, object] = {}

    def fake_default_context(cafile: str | None = None):
        captured["cafile"] = cafile
        return SimpleNamespace(cafile=cafile)

    monkeypatch.setattr(elastic_stage.ssl, "create_default_context", fake_default_context)
    ctx_with_ca = elastic_stage._build_ssl_context(insecure=False, ca_file="/tmp/custom-ca.pem")
    assert getattr(ctx_with_ca, "cafile", None) == "/tmp/custom-ca.pem"
    assert captured["cafile"] == "/tmp/custom-ca.pem"
    ctx_default = elastic_stage._build_ssl_context(insecure=False, ca_file=None)
    assert getattr(ctx_default, "cafile", None) is None
    assert captured["cafile"] is None


def test_elastic_request_http_error_and_exception_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    class _UrlOpen:
        def __init__(self, mode: str) -> None:
            self.mode = mode

        def __call__(self, _request, **_kwargs):
            if self.mode == "http_error":
                raise urllib.error.HTTPError(
                    url="http://127.0.0.1:9200/",
                    code=418,
                    msg="teapot",
                    hdrs={"Content-Type": "application/json"},
                    fp=io.BytesIO(b'{"error":"teapot"}'),
                )
            raise urllib.error.URLError(OSError("[Errno 111] Connection refused"))

    monkeypatch.setattr(elastic_stage.urllib.request, "urlopen", _UrlOpen("http_error"))
    status, payload, headers, error = elastic_stage._elastic_request(
        "127.0.0.1",
        9200,
        "/",
        1.0,
        use_https=False,
        insecure=False,
        ca_file=None,
    )
    assert status == 418
    assert payload == b'{"error":"teapot"}'
    assert headers == {"Content-Type": "application/json"}
    assert error is None

    monkeypatch.setattr(elastic_stage.urllib.request, "urlopen", _UrlOpen("url_error"))
    status, payload, headers, error = elastic_stage._elastic_request(
        "127.0.0.1",
        9200,
        "/",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert status == 0
    assert payload == b""
    assert headers == {}
    assert "connection refused" in str(error or "").lower()


def test_collect_discover_results_mixed_and_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(elastic_stage, "_list_index_names", lambda *_args, **_kwargs: (["good", "denied", "big"], None))

    def fake_search(
        _host: str,
        _port: int,
        _timeout: float,
        *,
        scheme: str,
        insecure: bool,
        ca_file: str | None,
        auth_headers: dict[str, str],
        index_name: str,
        query_string: str,
    ) -> tuple[int, list[dict[str, object]] | None, str | None]:
        _ = (scheme, insecure, ca_file, auth_headers, query_string)
        if index_name == "denied":
            return 0, None, "Access Denied"
        if index_name == "big":
            hits = [
                {"id": f"doc-{idx}", "source": {"k": idx}}
                for idx in range(elastic_stage._DISCOVER_MAX_PRINT_PER_INDEX + 3)
            ]
            return len(hits), hits, None
        return 2, [{"id": "doc-1", "source": {"password": "secret"}}, {"id": "doc-2", "source": {"token": "abc"}}], None

    monkeypatch.setattr(elastic_stage, "_search_index", fake_search)
    results, error = elastic_stage._collect_discover_results(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert error is None
    assert isinstance(results, list) and len(results) == 3
    by_index = {str(item["index"]): item for item in results}
    assert by_index["good"]["shown_hits"] == 2
    assert by_index["good"]["truncated"] is False
    assert by_index["denied"]["error"] == "Access Denied"
    assert by_index["big"]["shown_hits"] == elastic_stage._DISCOVER_MAX_PRINT_PER_INDEX
    assert by_index["big"]["truncated"] is True


def test_run_elastic_stage_debug_emit_and_payload_rendering(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Console:
        instances: list[_Console] = []

        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.warns: list[str] = []
            self.infos: list[str] = []
            self.plains: list[str] = []
            self.render_calls = 0
            type(self).instances.append(self)

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, message: str) -> None:
            self.warns.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def plain(self, message: str, color: str | None = None) -> None:
            _ = color
            self.plains.append(message)

        def render_tagged_payload_line(self, line: str, tag: str, payload_color: str | None = None) -> bool:
            _ = (tag, payload_color)
            self.render_calls += 1
            return self.render_calls > 1 and line.endswith("payload-secondary")

    monkeypatch.setattr(elastic_stage, "Console", _Console)
    monkeypatch.setattr(elastic_stage, "collect_scan_ports", lambda _ports: [19200])
    monkeypatch.setattr(
        elastic_stage,
        "collect_scan_target_specs",
        lambda _targets: [SimpleNamespace(host="127.0.0.1", scheme="http", explicit_port=19200)],
    )
    monkeypatch.setattr(
        elastic_stage,
        "build_scan_execution_groups",
        lambda _specs, _ports, include_scheme_in_key=True: [
            SimpleNamespace(hosts=["127.0.0.1"], port=19200, scheme_hint="http")
        ],
    )

    def fake_audit(**kwargs):
        emit_line = kwargs["emit_line"]
        emit_line("ELASTIC\t127.0.0.1\t19200\tpayload-primary")
        emit_line("ELASTIC\t127.0.0.1\t19200\tpayload-secondary")
        emit_line("unparsed-line")
        debug_emit = kwargs.get("debug_emit")
        if callable(debug_emit):
            debug_emit("debug-event")
        return 1, 1, 0, 0, 0

    patch_runner_for_legacy_target_fake(monkeypatch, "elastic", fake_audit)

    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        port=19200,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        username=None,
        password=None,
        apitoken=None,
        endpoints=True,
        plugins=True,
        cluster=True,
        user=True,
        discover=True,
        output="elastic.txt",
        output_format="txt",
        debug=True,
        workers=1,
        ca_file=None,
    )
    rc = run_elastic_stage(args, logger=SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 0
    console = _Console.instances[-1]
    assert any("elastic audit started" in message for message in console.infos)
    assert any("debug-event" in message for message in console.infos)
    assert any("payload-primary" in line for line in console.plains)
    assert any("unparsed-line" in line for line in console.plains)


def test_elastic_classify_and_version_resolution_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    nodes_partial = _classify_detect_probe(
        "/_nodes?filter_path=nodes.*.version",
        200,
        b'{"nodes":{"n1":{"name":"node-a"}}}',
        {"Content-Type": "application/json"},
        None,
    )
    assert nodes_partial["signal_kind"] == "soft_positive"
    assert "nodes_partial_shape" in (nodes_partial.get("signals") or [])

    gateway_like = _classify_detect_probe(
        "/",
        200,
        b"<!doctype html><html><body>bad gateway</body></html>",
        {"Content-Type": "text/html"},
        None,
    )
    assert gateway_like["signal_kind"] == "hard_negative"
    assert "root_non_json_payload" in (gateway_like.get("signals") or [])

    monkeypatch.setattr(elastic_stage, "_elastic_request", lambda *_args, **_kwargs: (0, b"", {}, "transport"))
    version, error = elastic_stage._resolve_server_version_with_auth(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert version is None
    assert error == "transport"

    monkeypatch.setattr(elastic_stage, "_elastic_request", lambda *_args, **_kwargs: (500, b"{}", {}, None))
    version, error = elastic_stage._resolve_server_version_with_auth(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert version is None
    assert error == "status=500"

    responses = iter(
        [
            (401, b"{}", {}, None),
            (500, b"{}", {}, None),
        ]
    )
    monkeypatch.setattr(elastic_stage, "_elastic_request", lambda *_args, **_kwargs: next(responses))
    version, error = elastic_stage._resolve_server_version_with_auth(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert version is None
    assert error == "nodes status=500"

    responses = iter(
        [
            (401, b"{}", {}, None),
            (200, b'{"nodes":{"n1":{"name":"node-a"}}}', {}, None),
        ]
    )
    monkeypatch.setattr(elastic_stage, "_elastic_request", lambda *_args, **_kwargs: next(responses))
    version, error = elastic_stage._resolve_server_version_with_auth(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert version is None
    assert error == "version unavailable"


def test_elastic_fetch_helpers_and_rendering_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        elastic_stage,
        "_elastic_request",
        lambda *_args, **_kwargs: (403, b"{}", {"content-type": "application/json"}, None),
    )
    monkeypatch.setattr(elastic_stage, "_probe_endpoint_status", lambda *_args, **_kwargs: (404, None))
    endpoints, endpoints_error, diagnostics = _fetch_cat_endpoints(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert endpoints == []
    assert endpoints_error == "Access Denied"
    assert diagnostics

    calls: list[str] = []

    def cat_req(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        headers: dict[str, str] | None,
        method: str = "GET",
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (use_https, insecure, ca_file, headers, method, data)
        calls.append(path)
        if path == "/_cat?help":
            return 0, b"", {}, "timeout"
        if path == "/_cat/":
            return 500, b"{}", {}, None
        raise AssertionError(path)

    monkeypatch.setattr(elastic_stage, "_elastic_request", cat_req)
    endpoints, endpoints_error, diagnostics = _fetch_cat_endpoints(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert endpoints == []
    assert endpoints_error == "timeout"
    assert [entry["endpoint"] for entry in diagnostics[:2]] == ["/_cat?help", "/_cat/"]
    assert calls == ["/_cat?help", "/_cat/"]

    responses = iter(
        [
            (200, b'{"cluster_name":"c"}', {}, None),
            (200, b'{"nodes":{"n2":{"name":"b"},"n1":{"name":"a"}}}', {}, None),
        ]
    )
    monkeypatch.setattr(elastic_stage, "_elastic_request", lambda *_args, **_kwargs: next(responses))
    health, nodes, cluster_error = elastic_stage._fetch_cluster_data(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert cluster_error is None
    assert isinstance(health, dict)
    assert isinstance(nodes, list)
    assert [item["name"] for item in nodes] == ["a", "b"]

    monkeypatch.setattr(
        elastic_stage,
        "_elastic_request",
        lambda *_args, **_kwargs: (200, b'{"cluster_name":"c"}', {}, None),
    )
    health, nodes, cluster_error = elastic_stage._fetch_cluster_data(
        "127.0.0.1",
        9200,
        1.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
    )
    assert isinstance(health, dict)
    assert nodes == []
    assert cluster_error is None

    json_lines = _format_detail_records(
        {
            "timestamp": "2026-04-10T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9200,
            "status": "valid_credentials",
            "show_endpoints": True,
            "show_plugins": True,
            "show_cluster": True,
            "show_users": True,
            "discover": True,
            "cat_endpoints": [],
            "endpoint_diagnostics": [{"endpoint": "/_cat/health", "status": 200, "error": None}],
            "cat_plugins": [],
            "cluster_health": None,
            "cluster_nodes": [],
            "misconfig_findings": [],
            "misconfig_error": "denied",
            "users": [],
            "discover_results": [],
            "endpoints_error": "Access Denied",
            "plugins_error": None,
            "cluster_error": "cluster down",
            "users_error": None,
            "discover_error": "discover down",
        },
        "json",
    )
    assert len(json_lines) == 6
    assert any('"type": "misconfig_dump"' in line for line in json_lines)


def test_elastic_record_and_renderer_variants() -> None:
    class _Console:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, _color: str, _stream) -> str:
            return text

        def plain(self, line: str) -> None:
            self.lines.append(line)

    assert elastic_stage._bool_text(None) == "unknown"
    assert elastic_stage._caps_suffix({"provided_credentials": False, "provided_token": False}) == ""
    assert elastic_stage._counts_suffix({"unused": True}) == ""

    fail_line = _format_detect_record({"host": "h", "port": 1, "status": "fail", "error": "boom"}, "txt")
    assert "connection failed" in fail_line
    assert "boom" in fail_line
    assert "not an Elasticsearch API" in _format_detect_record({"host": "h", "port": 1, "status": "not_elastic"}, "txt")

    assert "authentication required" in _format_record({"host": "h", "port": 1, "status": "auth_required"}, "txt")
    assert "credentials invalid" in _format_record(
        {"host": "h", "port": 1, "status": "auth_required", "provided_credentials": True},
        "txt",
    )
    assert "auth status unknown" in _format_record(
        {"host": "h", "port": 1, "status": "unknown_auth", "error": "slow link"},
        "txt",
    )
    assert "elastic:<none>" in _format_record(
        {
            "host": "h",
            "port": 1,
            "status": "valid_credentials",
            "provided_token": False,
            "provided_password": None,
            "provided_username": None,
            "effective_username": "elastic",
            "provided_credentials": True,
            "can_read": True,
            "can_write": False,
            "can_manage": None,
            "can_manage_security": None,
        },
        "txt",
    )

    txt_details = _format_detail_records(
        {
            "host": "h",
            "port": 1,
            "status": "valid_credentials",
            "show_endpoints": True,
            "cat_endpoints": [],
            "endpoints_error": "",
            "show_plugins": True,
            "cat_plugins": [{"node": "n1", "component": "c1", "version": "v1", "description": "d1"}, "skip-me"],
            "plugins_error": "",
            "show_cluster": True,
            "cluster_health": {
                "cluster_name": "c",
                "status": "yellow",
                "number_of_nodes": 1,
                "number_of_data_nodes": 1,
            },
            "cluster_nodes": [],
            "cluster_error": "cluster denied",
            "misconfig_findings": [],
            "misconfig_error": "",
            "show_users": True,
            "users": [],
            "users_error": "denied",
            "discover": True,
            "discover_results": [{"index": "idx", "total_hits": 1, "shown_hits": 1, "error": "denied", "hits": []}],
            "discover_error": "",
        },
        "txt",
    )
    assert any("<no endpoints>" in line for line in txt_details)
    assert any("node=n1 component=c1" in line for line in txt_details)
    assert any("cluster unavailable" in line for line in txt_details)
    assert any("users unavailable" in line for line in txt_details)
    assert any("discover error" in line for line in txt_details)

    console = _Console()
    assert elastic_stage._render_colored_elastic_line(console, "OTHER\tline") is False
    assert (
        elastic_stage._render_colored_elastic_line(
            console,
            "ELASTIC\t127.0.0.1\t9200\t [*] Elasticsearch API (auth required:True) (read:True) (write:False)",
        )
        is True
    )
    assert console.lines


def test_elastic_audit_targets_counts_and_logger_branches(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    def fake_call(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        api_token: str | None,
        ca_file: str | None,
        show_endpoints: bool,
        show_plugins: bool,
        show_cluster: bool,
        show_users: bool,
        discover: bool,
        preferred_scheme: str | None,
        debug: bool,
        run_deep_checks: bool,
        debug_emit,
    ) -> dict[str, object]:
        _ = (
            port,
            timeout,
            retries,
            username,
            password,
            api_token,
            ca_file,
            show_endpoints,
            show_plugins,
            show_cluster,
            show_users,
            discover,
            preferred_scheme,
            debug_emit,
        )
        if host == "h1" and not run_deep_checks:
            return {
                "timestamp": "2026-04-10T00:00:00Z",
                "host": host,
                "port": 9200,
                "is_elastic": True,
                "status": "valid_credentials",
                "auth_required": True,
                "provided_credentials": True,
                "provided_token": False,
                "provided_username": "elastic",
                "provided_password": "pass",
                "effective_username": "elastic",
                "auth_valid": True,
                "cat_endpoints": [],
                "cat_plugins": [],
                "misconfig_findings": [],
                "users": [],
                "discover_results": [],
                "detect_confidence": "high",
                "stages": [],
                "stage_durations_ms": {},
                "stage_attempts": {},
                "debug_events": [],
                "debug_events_streamed": bool(debug),
            }
        if host == "h1" and run_deep_checks:
            return {
                "timestamp": "2026-04-10T00:00:01Z",
                "host": host,
                "port": 9200,
                "is_elastic": True,
                "status": "valid_credentials",
                "auth_required": True,
                "provided_credentials": True,
                "provided_token": False,
                "provided_username": "elastic",
                "provided_password": "pass",
                "effective_username": "elastic",
                "auth_valid": True,
                "cat_endpoints": ["/_cat/health"],
                "cat_plugins": [{"node": "n", "component": "c", "version": "v", "description": "d"}],
                "misconfig_findings": [{"key": "x", "value": "y", "reason": "r"}],
                "users": [{"username": "elastic", "roles": ["superuser"], "enabled": True, "full_name": ""}],
                "discover_results": [{"index": "idx", "shown_hits": 2}],
                "detect_confidence": "high",
                "stages": [],
                "stage_durations_ms": {},
                "stage_attempts": {},
                "debug_events": ["evt-h1"],
                "debug_events_streamed": False,
            }
        if host == "h2":
            return {
                "timestamp": "2026-04-10T00:00:00Z",
                "host": host,
                "port": 9200,
                "is_elastic": True,
                "status": "auth_required",
                "auth_required": True,
                "provided_credentials": False,
                "provided_token": False,
                "stages": [],
                "stage_durations_ms": {},
                "stage_attempts": {},
                "debug_events": ["evt-h2"],
                "debug_events_streamed": False,
            }
        return {
            "timestamp": "2026-04-10T00:00:00Z",
            "host": host,
            "port": 9200,
            "is_elastic": False,
            "status": "fail",
            "auth_required": None,
            "error": "connection timeout",
            "stages": [],
            "stage_durations_ms": {},
            "stage_attempts": {},
            "debug_events": ["evt-h3"],
            "debug_events_streamed": False,
        }

    logs: list[tuple[tuple[object, ...], dict[str, object]]] = []
    debug_lines: list[str] = []
    lines: list[str] = []
    monkeypatch.setattr(elastic_stage, "_call_audit_elastic_host_with_thread_debug", fake_call)
    total, open_no_auth, valid, auth_required, failed = run_module_targets_for_test(
        "elastic",
        hosts=["h1", "h2", "h3"],
        port=9200,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        api_token=None,
        ca_file=None,
        show_endpoints=False,
        show_plugins=False,
        show_cluster=False,
        show_users=False,
        discover=False,
        output_path=str(tmp_path / "elastic_targets.txt"),
        output_format="txt",
        emit_line=lines.append,
        logger=SimpleNamespace(log=lambda *a, **k: logs.append((a, k))),
        append_output=False,
        suppress_timeout_status_lines=True,
        preferred_scheme="http",
        debug_emit=debug_lines.append,
    )
    assert (total, open_no_auth, valid, auth_required, failed) == (3, 0, 1, 1, 1)
    assert any("pass=1 detect start total=3" in line for line in debug_lines)
    assert any("pass=2 deep start total=1" in line for line in debug_lines)
    assert len(logs) == 3


def test_call_audit_elastic_wrapper_fallbacks_for_signature_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def fake_audit(*_args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(dict(kwargs))
        if "run_deep_checks" in kwargs:
            raise TypeError("got an unexpected keyword argument 'run_deep_checks'")
        return {"status": "ok"}

    monkeypatch.setattr(elastic_stage, "_audit_elastic_host", fake_audit)
    result = elastic_stage._call_audit_elastic_host_with_thread_debug(
        "127.0.0.1",
        9200,
        1.0,
        0,
        None,
        None,
        None,
        None,
        False,
        False,
        False,
        False,
        False,
        None,
        debug=False,
        run_deep_checks=True,
        debug_emit=None,
    )

    assert result == {"status": "ok"}
    assert len(calls) == 2
    assert calls[0].get("run_deep_checks") is True
    assert "run_deep_checks" not in calls[1]


def test_call_audit_elastic_wrapper_propagates_unexpected_typeerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_audit(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise TypeError("boom")

    monkeypatch.setattr(elastic_stage, "_audit_elastic_host", fake_audit)
    with pytest.raises(TypeError, match="boom"):
        elastic_stage._call_audit_elastic_host_with_thread_debug(
            "127.0.0.1",
            9200,
            1.0,
            0,
            None,
            None,
            None,
            None,
            False,
            False,
            False,
            False,
            False,
            None,
            debug=False,
            run_deep_checks=True,
            debug_emit=None,
        )
