from __future__ import annotations

from types import SimpleNamespace

import pytest

import redposture_core.stage_grafana as grafana_stage
from redposture_core.stage_grafana import (
    _audit_grafana_host,
    _auth_header,
    _build_credential_candidates,
    _delete_temp_datasource,
    _extract_create_payload,
    _fetch_datasources,
    _format_auth_attempt_detail_records,
    _format_check_detail_records,
    _format_datasources_detail_records,
    _format_record,
    _header_lookup,
    _load_json_dict,
    _load_json_list,
    _looks_like_grafana_health,
    _looks_like_grafana_login,
    _normalize_check_urls,
    _run_temp_prometheus_check,
    _split_check_target_url,
    _verify_credentials,
    audit_grafana_targets,
    run_grafana_stage,
)


def test_normalize_check_urls_builds_cartesian_product_for_targets_and_ports() -> None:
    urls = _normalize_check_urls("host.docker.internal,127.0.0.1", "9115,9187")
    assert urls == [
        "http://host.docker.internal:9115/",
        "http://host.docker.internal:9187/",
        "http://127.0.0.1:9115/",
        "http://127.0.0.1:9187/",
    ]


def test_normalize_check_urls_keeps_target_port_when_ssrf_port_is_not_set() -> None:
    urls = _normalize_check_urls("http://127.0.0.1:3000/probe", None)
    assert urls == ["http://127.0.0.1:3000/probe"]


def test_normalize_check_urls_applies_ssrf_path_override() -> None:
    urls = _normalize_check_urls("host.docker.internal,127.0.0.1", "9115,9187", "/debug/vars?full=1")
    assert urls == [
        "http://host.docker.internal:9115/debug/vars?full=1",
        "http://host.docker.internal:9187/debug/vars?full=1",
        "http://127.0.0.1:9115/debug/vars?full=1",
        "http://127.0.0.1:9187/debug/vars?full=1",
    ]


def test_normalize_check_urls_expands_cidr_targets() -> None:
    urls = _normalize_check_urls("192.168.65.0/30", "9115,9187")
    assert urls == [
        "http://192.168.65.1:9115/",
        "http://192.168.65.1:9187/",
        "http://192.168.65.2:9115/",
        "http://192.168.65.2:9187/",
    ]


def test_split_check_target_url_splits_base_and_upstream_path() -> None:
    split = _split_check_target_url("http://host.docker.internal:9115/debug/vars?x=1")
    assert split == ("http://host.docker.internal:9115", "/debug/vars?x=1")


def test_format_check_detail_records_includes_proxy_request_line() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 3000,
        "check_results": [
            {
                "target_url": "http://host.docker.internal:9115/debug/vars",
                "probe_proxy_path": "/api/datasources/proxy/12/debug/vars",
                "create_ok": True,
                "probe_ok": True,
                "probe_status": 200,
                "probe_elapsed_ms": 5,
                "probe_sample": '{"ok":1}',
                "cleanup_ok": True,
            }
        ],
    }
    lines = _format_check_detail_records(record, "txt")
    assert any("proxy request: GET /api/datasources/proxy/12/debug/vars" in line for line in lines)


def test_grafana_helper_parsers_and_auth_helpers() -> None:
    assert _load_json_dict('{"ok":1}') == {"ok": 1}
    assert _load_json_dict("[]") is None
    assert _load_json_list("[1,2]") == [1, 2]
    assert _load_json_list("{}") is None
    assert _header_lookup({"Set-Cookie": "grafana_session=1"}, "set-cookie") == "grafana_session=1"
    assert _header_lookup({}, "missing") is None

    assert _looks_like_grafana_login(200, "<title>Grafana</title>", {}) is True
    assert _looks_like_grafana_login(302, "", {"Location": "/login"}) is True
    assert _looks_like_grafana_login(404, "", {}) is False

    assert _looks_like_grafana_health(200, '{"database":"ok","version":"11.0.0"}') == (True, "11.0.0")
    assert _looks_like_grafana_health(200, "grafana ready") == (True, None)
    assert _looks_like_grafana_health(500, "{}") == (False, None)

    assert _auth_header("admin", "admin").startswith("Basic ")
    assert _build_credential_candidates("admin", "secret", True) == [
        ("admin", "secret", "provided"),
        ("admin", "admin", "default"),
    ]
    assert _build_credential_candidates(None, None, False) == []
    assert _build_credential_candidates(None, None, True) == [("admin", "admin", "default")]


def test_verify_datasource_and_temp_datasource_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_grafana._http_request",
        lambda *_args, **_kwargs: (200, "{}", {}),
    )
    ok, error = _verify_credentials("127.0.0.1", 3000, 1.0, "admin", "admin")
    assert (ok, error) == (True, None)

    monkeypatch.setattr(
        "redposture_core.stage_grafana._http_request",
        lambda *_args, **_kwargs: (403, "{}", {}),
    )
    ok, error = _verify_credentials("127.0.0.1", 3000, 1.0, "admin", "bad")
    assert (ok, error) == (False, "invalid credentials")

    monkeypatch.setattr(
        "redposture_core.stage_grafana._http_request",
        lambda *_args, **_kwargs: (
            200,
            '[{"name":"prom","type":"prometheus","url":"http://127.0.0.1:9090","access":"proxy"}]',
            {},
        ),
    )
    datasources, error, status = _fetch_datasources("127.0.0.1", 3000, 1.0)
    assert datasources == [{"name": "prom", "type": "prometheus", "url": "http://127.0.0.1:9090", "access": "proxy"}]
    assert (error, status) == (None, 200)

    monkeypatch.setattr(
        "redposture_core.stage_grafana._http_request",
        lambda *_args, **_kwargs: (401, "", {}),
    )
    datasources, error, status = _fetch_datasources("127.0.0.1", 3000, 1.0)
    assert datasources is None
    assert (error, status) == ("authentication required", 401)

    monkeypatch.setattr(
        "redposture_core.stage_grafana._http_request",
        lambda *_args, **_kwargs: (200, "not-json", {}),
    )
    datasources, error, status = _fetch_datasources("127.0.0.1", 3000, 1.0)
    assert datasources is None
    assert error == "/api/datasources returned invalid JSON"
    assert status == 200

    assert _extract_create_payload('{"id":7,"uid":"abc"}') == (7, "abc")
    assert _extract_create_payload('{"datasource":{"id":9,"uid":"uid-9"}}') == (9, "uid-9")

    monkeypatch.setattr(
        "redposture_core.stage_grafana._http_request",
        lambda *_args, **_kwargs: (200, "", {}),
    )
    cleanup_ok, cleanup_error = _delete_temp_datasource("127.0.0.1", 3000, 1.0, None, 7, None)
    assert (cleanup_ok, cleanup_error) == (True, None)

    monkeypatch.setattr(
        "redposture_core.stage_grafana._http_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("timed out")),
    )
    cleanup_ok, cleanup_error = _delete_temp_datasource("127.0.0.1", 3000, 1.0, None, None, "uid-9")
    assert cleanup_ok is False
    assert "connection timeout" in str(cleanup_error)

    cleanup_ok, cleanup_error = _delete_temp_datasource("127.0.0.1", 3000, 1.0, None, None, None)
    assert cleanup_ok is None
    assert cleanup_error == "temporary datasource id/uid is missing"


def test_run_temp_prometheus_check_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_http_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        _ = (host, port, timeout, headers, data)
        calls.append((method, path))
        if method == "POST":
            return 200, '{"datasource":{"id":12,"uid":"uid-12"}}', {}
        if method == "DELETE":
            return 200, "", {}
        return 502, "bad gateway", {}

    monkeypatch.setattr("redposture_core.stage_grafana._http_request", fake_http_request)
    result = _run_temp_prometheus_check(
        "127.0.0.1",
        3000,
        1.0,
        None,
        "http://host.docker.internal:9115/debug/vars?x=1",
    )
    assert result["create_ok"] is True
    assert result["datasource_id"] == 12
    assert result["probe_ok"] is False
    assert result["probe_status"] == 502
    assert result["cleanup_ok"] is True
    assert ("GET", "/api/datasources/proxy/12/debug/vars?x=1") in calls

    invalid = _run_temp_prometheus_check("127.0.0.1", 3000, 1.0, None, "://bad")
    assert invalid["create_ok"] is False
    assert invalid["create_error"] == "invalid target url"


def test_audit_grafana_defcreds_are_checked_even_with_anonymous_access(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        _ = (host, port, timeout, method, headers, data)
        if path == "/api/health":
            return 200, '{"database":"ok","version":"11.0.0"}', {}
        if path == "/login":
            return 200, "<title>Grafana</title>", {"Content-Type": "text/html"}
        return 404, "", {}

    def fake_verify_credentials(
        host: str, port: int, timeout: float, username: str, password: str
    ) -> tuple[bool, str | None]:
        _ = (host, port, timeout, username, password)
        return False, "invalid credentials"

    def fake_fetch_datasources(
        host: str,
        port: int,
        timeout: float,
        *,
        auth_header: str | None = None,
    ) -> tuple[list[dict[str, str]] | None, str | None, int | None]:
        _ = (host, port, timeout, auth_header)
        return [], None, 200

    monkeypatch.setattr("redposture_core.stage_grafana._http_request", fake_http_request)
    monkeypatch.setattr("redposture_core.stage_grafana._verify_credentials", fake_verify_credentials)
    monkeypatch.setattr("redposture_core.stage_grafana._fetch_datasources", fake_fetch_datasources)

    record = _audit_grafana_host(
        host="127.0.0.1",
        port=3000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        check_urls=None,
    )

    assert record["status"] == "invalid_credentials_anonymous"
    assert int(record["attempted_credentials"]) == 1
    auth_attempts = record.get("auth_attempts")
    assert isinstance(auth_attempts, list)
    assert [f"{item.get('username')}:{item.get('password')}" for item in auth_attempts] == [
        "admin:admin",
    ]
    detail_lines = _format_auth_attempt_detail_records(record, "txt")
    assert any("[-] admin:admin" in line for line in detail_lines)
    line = _format_record(record, "txt")
    assert "[-] credentials invalid (anonymous access)" in line


def test_audit_grafana_prefers_valid_credentials_status_even_if_anonymous(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    verify_calls: list[tuple[str, str]] = []

    def fake_http_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        _ = (host, port, timeout, method, headers, data)
        if path == "/api/health":
            return 200, '{"database":"ok","version":"11.0.0"}', {}
        if path == "/login":
            return 200, "<title>Grafana</title>", {"Content-Type": "text/html"}
        return 404, "", {}

    def fake_verify_credentials(
        host: str, port: int, timeout: float, username: str, password: str
    ) -> tuple[bool, str | None]:
        _ = (host, port, timeout)
        verify_calls.append((username, password))
        if username == "admin" and password == "admin":
            return True, None
        return False, "invalid credentials"

    def fake_fetch_datasources(
        host: str,
        port: int,
        timeout: float,
        *,
        auth_header: str | None = None,
    ) -> tuple[list[dict[str, str]] | None, str | None, int | None]:
        _ = (host, port, timeout, auth_header)
        return (
            [{"name": "prometheus", "type": "prometheus", "url": "http://127.0.0.1:9090", "access": "proxy"}],
            None,
            200,
        )

    monkeypatch.setattr("redposture_core.stage_grafana._http_request", fake_http_request)
    monkeypatch.setattr("redposture_core.stage_grafana._verify_credentials", fake_verify_credentials)
    monkeypatch.setattr("redposture_core.stage_grafana._fetch_datasources", fake_fetch_datasources)

    record = _audit_grafana_host(
        host="127.0.0.1",
        port=3000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=True,
        check_urls=None,
    )

    assert record["status"] == "valid_credentials"
    assert int(record["attempted_credentials"]) == 1
    assert record["credentials_source"] == "default"
    assert record["effective_username"] == "admin"
    assert verify_calls == [("admin", "admin")]
    auth_attempts = record.get("auth_attempts")
    assert isinstance(auth_attempts, list)
    assert len(auth_attempts) == 1
    assert bool(auth_attempts[0].get("ok")) is True


def test_audit_grafana_runs_provided_and_default_creds_in_order(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    verify_calls: list[tuple[str, str]] = []

    def fake_http_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        _ = (host, port, timeout, method, headers, data)
        if path == "/api/health":
            return 200, '{"database":"ok","version":"11.0.0"}', {}
        if path == "/login":
            return 200, "<title>Grafana</title>", {"Content-Type": "text/html"}
        return 404, "", {}

    def fake_verify_credentials(
        host: str, port: int, timeout: float, username: str, password: str
    ) -> tuple[bool, str | None]:
        _ = (host, port, timeout)
        verify_calls.append((username, password))
        return False, "invalid credentials"

    def fake_fetch_datasources(
        host: str,
        port: int,
        timeout: float,
        *,
        auth_header: str | None = None,
    ) -> tuple[list[dict[str, str]] | None, str | None, int | None]:
        _ = (host, port, timeout, auth_header)
        return [], None, 200

    monkeypatch.setattr("redposture_core.stage_grafana._http_request", fake_http_request)
    monkeypatch.setattr("redposture_core.stage_grafana._verify_credentials", fake_verify_credentials)
    monkeypatch.setattr("redposture_core.stage_grafana._fetch_datasources", fake_fetch_datasources)

    record = _audit_grafana_host(
        host="127.0.0.1",
        port=3000,
        timeout=1.0,
        retries=0,
        username="custom-user",
        password="custom-pass",
        defcreds=True,
        check_urls=None,
    )

    assert record["status"] == "invalid_credentials_anonymous"
    assert int(record["attempted_credentials"]) == 2
    assert verify_calls == [
        ("custom-user", "custom-pass"),
        ("admin", "admin"),
    ]


def test_audit_grafana_emits_auth_attempt_lines_before_status(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_audit_host(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        defcreds: bool,
        check_urls: list[str] | None,
    ) -> dict[str, object]:
        _ = (host, port, timeout, retries, username, password, defcreds, check_urls)
        return {
            "timestamp": "2026-03-05T00:00:00Z",
            "host": "127.0.0.1",
            "port": 3000,
            "is_grafana": True,
            "status": "invalid_credentials_anonymous",
            "auth_required": False,
            "server_version": "11.0.0",
            "provided_credentials": False,
            "provided_username": None,
            "provided_credentials_ok": None,
            "default_credentials": False,
            "defcreds_enabled": True,
            "attempted_credentials": 2,
            "credentials_source": None,
            "effective_username": None,
            "effective_password": None,
            "datasource_count": 0,
            "datasources": [],
            "auth_attempts": [
                {
                    "username": "admin",
                    "password": "admin",
                    "source": "default",
                    "ok": False,
                    "error": "invalid credentials",
                },
                {
                    "username": "admin",
                    "password": "prom-operator",
                    "source": "default",
                    "ok": False,
                    "error": "invalid credentials",
                },
            ],
            "check_urls": None,
            "check_results": None,
            "elapsed_ms": 5,
            "error": "invalid credentials",
        }

    monkeypatch.setattr("redposture_core.stage_grafana._audit_grafana_host", fake_audit_host)

    emitted_lines: list[str] = []
    total, open_no_auth, valid, auth_required, failed = audit_grafana_targets(
        hosts=["127.0.0.1"],
        port=3000,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=True,
        check_urls=None,
        show_datasources=False,
        output_path=None,
        output_format="txt",
        emit_line=emitted_lines.append,
        logger=None,
        append_output=False,
        suppress_timeout_status_lines=False,
    )

    assert (total, open_no_auth, valid, auth_required, failed) == (1, 1, 0, 0, 0)
    assert len(emitted_lines) == 3
    assert "[*] Grafana Service" in emitted_lines[0]
    assert "[-] admin:admin" in emitted_lines[1]
    assert "[-] admin:prom-operator" in emitted_lines[2]


def test_audit_grafana_auth_required_after_datasource_denial(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        _ = (host, port, timeout, method, headers, data)
        if path == "/api/health":
            return 200, '{"database":"ok","version":"11.0.0"}', {}
        return 404, "", {}

    def fake_fetch_datasources(
        host: str,
        port: int,
        timeout: float,
        *,
        auth_header: str | None = None,
    ) -> tuple[list[dict[str, str]] | None, str | None, int]:
        _ = (host, port, timeout, auth_header)
        return None, "authentication required", 401

    monkeypatch.setattr("redposture_core.stage_grafana._http_request", fake_http_request)
    monkeypatch.setattr("redposture_core.stage_grafana._fetch_datasources", fake_fetch_datasources)

    record = _audit_grafana_host(
        host="127.0.0.1",
        port=3000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        check_urls=None,
    )

    assert record["status"] == "auth_required"
    assert record["auth_required"] is True
    assert record["datasource_count"] is None


def test_audit_grafana_formats_datasources_and_check_failures(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_request(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        _ = (host, port, timeout, method, headers, data)
        if path == "/api/health":
            return 200, '{"database":"ok","version":"11.0.0"}', {}
        return 404, "", {}

    def fake_fetch_datasources(
        host: str,
        port: int,
        timeout: float,
        *,
        auth_header: str | None = None,
    ) -> tuple[list[dict[str, str]] | None, str | None, int]:
        _ = (host, port, timeout, auth_header)
        return (
            [
                {"name": "prometheus", "type": "prometheus", "url": "http://127.0.0.1:9090", "access": "proxy"},
                "skip-me",  # type: ignore[list-item]
            ],
            None,
            200,
        )

    def fake_check(
        host: str,
        port: int,
        timeout: float,
        auth_header: str | None,
        target_url: str,
    ) -> dict[str, object]:
        _ = (host, port, timeout, auth_header, target_url)
        return {
            "target_url": target_url,
            "probe_proxy_path": "/api/datasources/proxy/9/debug/vars",
            "create_ok": True,
            "probe_ok": False,
            "probe_status": 502,
            "probe_elapsed_ms": 7,
            "probe_error": "bad gateway",
            "probe_sample": "upstream said no",
            "cleanup_ok": False,
            "cleanup_error": "delete failed",
        }

    monkeypatch.setattr("redposture_core.stage_grafana._http_request", fake_http_request)
    monkeypatch.setattr("redposture_core.stage_grafana._fetch_datasources", fake_fetch_datasources)
    monkeypatch.setattr("redposture_core.stage_grafana._run_temp_prometheus_check", fake_check)

    record = _audit_grafana_host(
        host="127.0.0.1",
        port=3000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        check_urls=["http://host.docker.internal:9115/debug/vars"],
    )
    record["show_datasources"] = True

    assert record["status"] == "open_no_auth"
    assert record["datasource_count"] == 2
    datasource_lines = _format_datasources_detail_records(record, "txt")
    assert any("[*] Dump Datasources" in line for line in datasource_lines)
    assert any("name=prometheus" in line for line in datasource_lines)
    check_lines = _format_check_detail_records(record, "txt")
    assert any("probe failed status=502 elapsed=7ms" in line for line in check_lines)
    assert any("sample: upstream said no" in line for line in check_lines)
    assert any("cleanup failed" in line for line in check_lines)
    json_lines = _format_datasources_detail_records(record, "json")
    assert any('"type": "datasources_dump"' in line for line in json_lines)


def test_audit_grafana_marks_non_grafana_and_retries_failures(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_not_grafana(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        _ = (host, port, timeout, method, headers, data)
        return 404, "", {}

    monkeypatch.setattr("redposture_core.stage_grafana._http_request", fake_not_grafana)
    record = _audit_grafana_host(
        host="127.0.0.1",
        port=3000,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        check_urls=None,
    )
    assert record["status"] == "fail"
    assert record["is_grafana"] is False
    assert record["error"] == "service is not grafana"

    attempts = {"count": 0}

    def fake_fail(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        _ = (host, port, path, timeout, method, headers, data)
        attempts["count"] += 1
        raise TimeoutError("timed out")

    monkeypatch.setattr("redposture_core.stage_grafana._http_request", fake_fail)
    monkeypatch.setattr("redposture_core.stage_grafana._retry_delay", lambda _attempt: 0.0)
    failed_record = _audit_grafana_host(
        host="127.0.0.1",
        port=3000,
        timeout=1.0,
        retries=1,
        username=None,
        password=None,
        defcreds=False,
        check_urls=None,
    )
    assert attempts["count"] == 2
    assert failed_record["status"] == "fail"
    assert failed_record["error"] == "connection timeout"


def test_audit_grafana_targets_and_run_stage_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
) -> None:
    def fake_audit_host(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        defcreds: bool,
        check_urls: list[str] | None,
    ) -> dict[str, object]:
        _ = (port, timeout, retries, username, password, defcreds, check_urls)
        if host == "127.0.0.1":
            return {
                "timestamp": "2026-03-27T00:00:00Z",
                "host": host,
                "port": 3000,
                "is_grafana": True,
                "status": "valid_credentials",
                "auth_required": True,
                "server_version": "11.0.0",
                "provided_credentials": True,
                "provided_username": "admin",
                "provided_credentials_ok": True,
                "default_credentials": False,
                "defcreds_enabled": False,
                "attempted_credentials": 1,
                "credentials_source": "provided",
                "effective_username": "admin",
                "effective_password": "secret",
                "datasource_count": 1,
                "datasources": [
                    {"name": "prom", "type": "prometheus", "url": "http://127.0.0.1:9090", "access": "proxy"}
                ],
                "auth_attempts": [{"username": "admin", "password": "secret", "ok": True}],
                "check_urls": None,
                "check_results": None,
                "elapsed_ms": 5,
                "error": None,
            }
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 3000,
            "is_grafana": False,
            "status": "fail",
            "auth_required": None,
            "server_version": None,
            "provided_credentials": False,
            "provided_username": None,
            "provided_credentials_ok": None,
            "default_credentials": None,
            "defcreds_enabled": False,
            "attempted_credentials": 0,
            "credentials_source": None,
            "effective_username": None,
            "effective_password": None,
            "datasource_count": None,
            "datasources": None,
            "auth_attempts": [],
            "check_urls": None,
            "check_results": None,
            "elapsed_ms": None,
            "error": "connection timeout",
        }

    monkeypatch.setattr("redposture_core.stage_grafana._audit_grafana_host", fake_audit_host)
    emitted: list[str] = []
    logged: list[tuple[tuple[object, ...], dict[str, object]]] = []
    output_path = tmp_path / "grafana.txt"
    totals = audit_grafana_targets(
        hosts=["127.0.0.1", "127.0.0.2"],
        port=3000,
        timeout=1.0,
        retries=0,
        workers=2,
        username="admin",
        password="secret",
        defcreds=False,
        check_urls=None,
        show_datasources=True,
        output_path=str(output_path),
        output_format="txt",
        emit_line=emitted.append,
        logger=SimpleNamespace(log=lambda *a, **k: logged.append((a, k))),
        append_output=False,
        suppress_timeout_status_lines=True,
    )
    assert totals == (2, 0, 1, 0, 1)
    assert any("Grafana Service" in line for line in emitted)
    assert any("admin:secret" in line for line in emitted)
    assert not any("connection failed" in line for line in emitted)
    assert len(logged) == 2
    assert output_path.read_text(encoding="utf-8")

    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.infos: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr(grafana_stage, "Console", lambda debug=False: fake_console)
    base_args = dict(
        debug=False,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        port=3000,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        ssrf_target=None,
        ssrf_port=None,
        ssrf_path=None,
        show_datasources=False,
        output=None,
        output_format="txt",
        workers=1,
    )

    assert (
        run_grafana_stage(
            SimpleNamespace(**{**base_args, "timeout": 0}), logger=SimpleNamespace(log=lambda *_a, **_k: None)
        )
        == 2
    )
    assert any("--timeout must be > 0" in msg for msg in fake_console.errors)

    fake_console.errors.clear()
    assert (
        run_grafana_stage(
            SimpleNamespace(**{**base_args, "username": "admin"}), logger=SimpleNamespace(log=lambda *_a, **_k: None)
        )
        == 2
    )
    assert any("--password is required when --username is set" in msg for msg in fake_console.errors)

    monkeypatch.setattr(grafana_stage, "collect_scan_ports", lambda *_args, **_kwargs: [3000])
    monkeypatch.setattr(
        grafana_stage,
        "collect_scan_target_specs",
        lambda *_args, **_kwargs: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        grafana_stage,
        "audit_grafana_targets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("write failed")),
    )
    fake_console.errors.clear()
    assert run_grafana_stage(SimpleNamespace(**base_args), logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2
    assert any("failed to process grafana output" in msg for msg in fake_console.errors)


def test_audit_grafana_targets_emits_stage_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple[str, ...] | None]] = []

    def fake_audit_host(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        defcreds: bool,
        check_urls: list[str] | None,
    ) -> dict[str, object]:
        _ = (port, timeout, retries, username, password, defcreds)
        calls.append((host, tuple(check_urls or [])))
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 3000,
            "is_grafana": True,
            "status": "open_no_auth",
            "auth_required": False,
            "server_version": "11.0.0",
            "provided_credentials": False,
            "provided_username": None,
            "provided_credentials_ok": None,
            "default_credentials": False,
            "defcreds_enabled": False,
            "attempted_credentials": 0,
            "credentials_source": None,
            "effective_username": None,
            "effective_password": None,
            "datasource_count": 0,
            "datasources": [],
            "auth_attempts": [],
            "check_urls": check_urls,
            "check_results": [],
            "elapsed_ms": 5,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.stage_grafana._audit_grafana_host", fake_audit_host)
    debug_lines: list[str] = []
    totals = audit_grafana_targets(
        hosts=["127.0.0.1"],
        port=3000,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        check_urls=["http://127.0.0.1:9090/-/ready"],
        show_datasources=True,
        output_path=None,
        output_format="txt",
        emit_line=None,
        logger=None,
        append_output=False,
        suppress_timeout_status_lines=False,
        show_progress=False,
        debug_emit=debug_lines.append,
    )
    assert totals == (1, 1, 0, 0, 0)
    assert calls == [
        ("127.0.0.1", ()),
        ("127.0.0.1", ("http://127.0.0.1:9090/-/ready",)),
    ]
    assert any(line.startswith("pass=1 detect start total=1") for line in debug_lines)
    assert any("stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=1" in line for line in debug_lines)


def test_run_grafana_stage_uses_single_progress_for_multiple_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def info(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr(grafana_stage, "Console", lambda debug=False: fake_console)

    monkeypatch.setattr(grafana_stage, "collect_scan_ports", lambda *_args, **_kwargs: [3000])
    monkeypatch.setattr(
        grafana_stage,
        "collect_scan_target_specs",
        lambda *_args, **_kwargs: [
            SimpleNamespace(host="host-a", scheme="http", explicit_port=3100),
            SimpleNamespace(host="host-b", scheme="http", explicit_port=3200),
            SimpleNamespace(host="host-c", scheme="http", explicit_port=3200),
        ],
    )
    monkeypatch.setattr(
        grafana_stage,
        "build_scan_execution_groups",
        lambda *_args, **_kwargs: [
            SimpleNamespace(hosts=["host-a"], port=3100),
            SimpleNamespace(hosts=["host-b", "host-c"], port=3200),
        ],
    )

    seen_show_progress: list[bool] = []

    def _fake_audit_grafana_targets(*_args: object, **kwargs: object) -> tuple[int, int, int, int, int]:
        seen_show_progress.append(bool(kwargs.get("show_progress")))
        hosts = list(kwargs.get("hosts") or [])
        return len(hosts), 0, 0, len(hosts), 0

    monkeypatch.setattr(grafana_stage, "audit_grafana_targets", _fake_audit_grafana_targets)

    created_totals: list[int] = []
    advanced_steps: list[int] = []
    closed_count = 0

    class _FakeProgressBar:
        def __init__(
            self,
            _label: str,
            total: int,
            *,
            enabled: bool = True,
            stream=None,
            leave: bool = True,
        ) -> None:
            _ = (enabled, stream, leave)
            created_totals.append(total)

        def advance(self, step: int = 1) -> None:
            advanced_steps.append(step)

        def close(self) -> None:
            nonlocal closed_count
            closed_count += 1

    monkeypatch.setattr(grafana_stage, "ProgressBar", _FakeProgressBar)

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        port=3000,
        ports=None,
        targets="host-a,host-b,host-c",
        hosts=None,
        hosts_file=None,
        ssrf_target=None,
        ssrf_port=None,
        ssrf_path=None,
        show_datasources=False,
        output=None,
        output_format="txt",
        workers=2,
    )
    rc = run_grafana_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))

    assert rc == 0
    assert fake_console.errors == []
    assert seen_show_progress == [False, False]
    assert created_totals == [3]
    assert advanced_steps == [1, 2]
    assert closed_count == 1
