from __future__ import annotations

from redposture_core.stage_grafana import (
    _audit_grafana_host,
    _format_auth_attempt_detail_records,
    _format_check_detail_records,
    _format_record,
    _normalize_check_urls,
    _split_check_target_url,
    audit_grafana_targets,
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
    assert int(record["attempted_credentials"]) == 2
    auth_attempts = record.get("auth_attempts")
    assert isinstance(auth_attempts, list)
    assert [f"{item.get('username')}:{item.get('password')}" for item in auth_attempts] == [
        "admin:admin",
        "admin:prom-operator",
    ]
    detail_lines = _format_auth_attempt_detail_records(record, "txt")
    assert any("[-] admin:admin" in line for line in detail_lines)
    assert any("[-] admin:prom-operator" in line for line in detail_lines)
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
    assert int(record["attempted_credentials"]) == 2
    assert record["credentials_source"] == "default"
    assert record["effective_username"] == "admin"
    assert verify_calls == [("admin", "admin"), ("admin", "prom-operator")]
    auth_attempts = record.get("auth_attempts")
    assert isinstance(auth_attempts, list)
    assert len(auth_attempts) == 2
    assert bool(auth_attempts[0].get("ok")) is True
    assert bool(auth_attempts[1].get("ok")) is False


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
    assert int(record["attempted_credentials"]) == 3
    assert verify_calls == [
        ("custom-user", "custom-pass"),
        ("admin", "admin"),
        ("admin", "prom-operator"),
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
