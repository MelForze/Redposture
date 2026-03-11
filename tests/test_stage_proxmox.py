from __future__ import annotations

import base64
import json

from redposture_core.stage_proxmox import (
    _audit_proxmox_host,
    _format_add_user_detail_records,
    _format_discovered_urls_detail_records,
    _format_record,
    _parse_proxy_config,
)


def _json_payload(data):
    return json.dumps({"data": data}, ensure_ascii=False).encode("utf-8")


def test_audit_proxmox_collects_credential_hits(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
    ):
        assert pve_api_token == "monitor@pve!audit=super-secret-token"
        assert use_https is True
        assert insecure is True
        assert proxy is None

        if path == "/access":
            return 200, _json_payload({"clustername": "lab"}), {}, None
        if path == "/nodes":
            return 200, _json_payload([{"node": "pve1"}]), {}, None
        if path == "/access/permissions?path=/":
            return (
                200,
                _json_payload({"permissions": {"/": {"Sys.Audit": 1, "User.Modify": 0, "VM.Backup": 1}}}),
                {},
                None,
            )
        if path == "/access/users":
            return 200, _json_payload([{"userid": "root@pam"}, {"userid": "audit@pve"}]), {}, None
        if path == "/nodes/pve1/syslog":
            return 200, b"db_password=UltraSecret123\n", {}, None
        if path == "/nodes/pve1/report":
            return 200, b"no secrets here", {}, None
        if path == "/nodes/pve1/tasks":
            return 200, _json_payload([]), {}, None
        if path == "/nodes/pve1/qemu":
            return 200, _json_payload([{"vmid": 100}]), {}, None
        if path == "/nodes/pve1/qemu/100/config":
            return 200, _json_payload({"cipassword": "CloudInitSecret123"}), {}, None
        if path == "/nodes/pve1/lxc":
            return 200, _json_payload([{"vmid": 101}]), {}, None
        if path == "/nodes/pve1/lxc/101/config":
            return 200, _json_payload({"password": "LxcSecret456"}), {}, None
        if path == "/nodes/pve1/storage":
            return 200, _json_payload([{"storage": "local"}]), {}, None
        if path == "/nodes/pve1/storage/local/content":
            return 200, _json_payload([{"volid": "local:backup/vzdump-qemu-100.vma.zst"}]), {}, None
        if path == "/nodes/pve1/storage/local/content?content=backup":
            return 200, _json_payload([{"volid": "local:backup/vzdump-qemu-100.vma.zst"}]), {}, None
        if path.startswith("/nodes/pve1/storage/local/content/"):
            return 200, _json_payload({"password": "BackupVolumeSecret789"}), {}, None
        if path.startswith("/nodes/pve1/storage/local/download?"):
            return 200, b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.xxx.yyy", {}, None
        if path == "/sdn":
            return 200, _json_payload({"dns_api_key": "sdnKeyValue123"}), {}, None
        if path == "/cluster/backup":
            return 200, _json_payload([{"storage": "pbs", "password": "clusterBackupPass123"}]), {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=super-secret-token",
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=True,
        show_nodes=True,
        show_users=True,
    )

    assert record["status"] == "token_ok"
    assert record["is_proxmox"] is True
    assert int(record.get("checked_endpoints") or 0) >= 10
    assert int(record.get("credential_hits") or 0) >= 4
    assert record.get("nodes") == ["pve1"]
    assert record.get("users") == ["root@pam", "audit@pve"]
    assert record.get("cap_adduser") is False
    assert record.get("cap_read") is True
    assert record.get("cap_backup") is True
    findings = record.get("findings")
    assert isinstance(findings, list) and findings
    assert any("password" in str(item.get("reason", "")).lower() for item in findings if isinstance(item, dict))


def test_audit_proxmox_add_user_success(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    created_forms: list[dict[str, str]] = []
    acl_forms: list[dict[str, str]] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
        method: str = "GET",
        form=None,
    ):
        _ = (pve_api_token, use_https, insecure, proxy)
        if path == "/access":
            return 200, _json_payload({"clustername": "lab"}), {}, None
        if path == "/access/permissions?path=/":
            return (
                200,
                _json_payload({"permissions": {"/": {"Sys.Audit": 1, "User.Modify": 1, "VM.Backup": 0}}}),
                {},
                None,
            )
        if path == "/access/users" and method == "POST":
            assert isinstance(form, dict)
            created_forms.append({str(k): str(v) for k, v in form.items()})
            return 200, _json_payload({"userid": str(form.get("userid") or "")}), {}, None
        if path == "/access/acl" and method == "PUT":
            assert isinstance(form, dict)
            acl_forms.append({str(k): str(v) for k, v in form.items()})
            return 200, _json_payload({"path": "/", "roleid": "Administrator"}), {}, None
        if path == "/access/users":
            return 200, _json_payload([{"userid": "root@pam"}, {"userid": "scanner-bot@pve"}]), {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="admin@pve!root=token",
        use_https=True,
        insecure=True,
        proxy=None,
        add_user="scanner-bot",
        show_users=True,
    )

    assert record["status"] == "token_ok"
    assert record.get("added_user") == "scanner-bot@pve"
    generated_password = str(record.get("added_password") or "")
    assert len(generated_password) == 20
    assert generated_password.isalnum()
    assert record.get("add_user_error") is None
    assert created_forms and created_forms[0].get("userid") == "scanner-bot@pve"
    assert created_forms[0].get("password") == generated_password
    assert acl_forms and acl_forms[0].get("users") == "scanner-bot@pve"
    assert acl_forms[0].get("path") == "/"
    assert acl_forms[0].get("roles") == "Administrator"
    assert record.get("add_user_privileges_granted") is True
    assert record.get("add_user_privileges_role") == "Administrator"
    assert record.get("add_user_privileges_error") is None


def test_audit_proxmox_add_user_shows_error_when_creation_fails(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
        method: str = "GET",
        form=None,
    ):
        _ = (pve_api_token, use_https, insecure, proxy, form)
        if path == "/access":
            return 200, _json_payload({"clustername": "lab"}), {}, None
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"permissions": {"/": {"Sys.Audit": 1, "User.Modify": 0}}}), {}, None
        if path == "/access/users" and method == "POST":
            return 403, b'{"errors":"permission check failed"}', {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=token",
        use_https=True,
        insecure=True,
        proxy=None,
        add_user="scanner-bot",
    )

    assert record["status"] == "token_ok"
    assert record.get("added_user") is None
    assert record.get("added_password") is None
    assert "permission" in str(record.get("add_user_error") or "").lower()
    assert record.get("add_user_privileges_granted") is None
    assert record.get("add_user_privileges_role") is None
    assert record.get("add_user_privileges_error") is None


def test_format_add_user_detail_records_success_line() -> None:
    lines = _format_add_user_detail_records(
        {
            "host": "127.0.0.1",
            "port": 8006,
            "add_user": "scanner-bot",
            "added_user": "scanner-bot@pve",
            "added_password": "AbCdEf1234567890ZzYx",
            "add_user_error": None,
            "add_user_privileges_granted": True,
            "add_user_privileges_role": "Administrator",
            "add_user_privileges_error": None,
        },
        "txt",
    )
    assert lines == [
        "PROXMOX \t127.0.0.1\t8006\t [+] User scanner-bot@pve added with password AbCdEf1234567890ZzYx and granted privileges Administrator"
    ]


def test_format_add_user_detail_records_warns_when_privileges_not_granted() -> None:
    lines = _format_add_user_detail_records(
        {
            "host": "127.0.0.1",
            "port": 8006,
            "add_user": "scanner-bot",
            "added_user": "scanner-bot@pve",
            "added_password": "AbCdEf1234567890ZzYx",
            "add_user_error": None,
            "add_user_privileges_granted": False,
            "add_user_privileges_role": None,
            "add_user_privileges_error": "permission check failed",
        },
        "txt",
    )
    assert lines == [
        "PROXMOX \t127.0.0.1\t8006\t [!] User scanner-bot@pve added with password AbCdEf1234567890ZzYx, but privileges were not granted err=permission check failed"
    ]


def test_audit_proxmox_add_user_reports_acl_grant_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
        method: str = "GET",
        form=None,
    ):
        _ = (pve_api_token, use_https, insecure, proxy, form)
        if path == "/access":
            return 200, _json_payload({"clustername": "lab"}), {}, None
        if path == "/access/permissions?path=/":
            return (
                200,
                _json_payload({"permissions": {"/": {"Sys.Audit": 1, "User.Modify": 1, "Permissions.Modify": 1}}}),
                {},
                None,
            )
        if path == "/access/users" and method == "POST":
            return 200, _json_payload({"userid": "scanner-bot@pve"}), {}, None
        if path == "/access/acl" and method == "PUT":
            return 403, b'{"errors":"permission check failed"}', {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="admin@pve!root=token",
        use_https=True,
        insecure=True,
        proxy=None,
        add_user="scanner-bot",
    )

    assert record["status"] == "token_ok"
    assert record.get("added_user") == "scanner-bot@pve"
    assert isinstance(record.get("added_password"), str)
    assert record.get("add_user_error") is None
    assert record.get("add_user_privileges_granted") is False
    assert record.get("add_user_privileges_role") is None
    assert "permission" in str(record.get("add_user_privileges_error") or "").lower()


def test_audit_proxmox_marks_auth_failed_on_401(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_request(*_args, **_kwargs):
        return 401, b'{"errors":"permission denied"}', {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=invalid",
        use_https=True,
        insecure=True,
        proxy=None,
    )

    assert record["status"] == "auth_failed"
    assert record["is_proxmox"] is True


def test_audit_proxmox_marks_insufficient_privileges_on_403(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
    ):
        _ = (pve_api_token, use_https, insecure, proxy)
        if path == "/access":
            return 403, b'{"errors":"permission check failed"}', {}, None
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"permissions": {"/": {"Sys.Audit": 1, "User.Modify": 0}}}), {}, None
        if path == "/access/users":
            return 403, b'{"errors":"permission check failed"}', {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=limited",
        use_https=True,
        insecure=True,
        proxy=None,
        show_nodes=True,
        show_users=True,
    )

    assert record["status"] == "insufficient_privileges"
    assert record["is_proxmox"] is True
    assert record.get("cap_adduser") is False
    assert record.get("cap_read") is True
    assert "permission" in str(record.get("error") or "").lower()


def test_audit_proxmox_marks_insufficient_privileges_on_401_permission_message(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
    ):
        _ = (pve_api_token, use_https, insecure, proxy)
        if path == "/access":
            return 401, b'{"errors":"permission check failed"}', {}, None
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"permissions": {"/": {"Sys.Audit": 1}}}), {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=limited",
        use_https=True,
        insecure=True,
        proxy=None,
    )

    assert record["status"] == "insufficient_privileges"
    assert record["is_proxmox"] is True


def test_audit_proxmox_returns_fail_on_network_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_request(*_args, **_kwargs):
        return 0, b"", {}, "connection refused (service is not listening on target port)"

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=token",
        use_https=True,
        insecure=True,
        proxy=None,
    )

    assert record["status"] == "fail"
    assert record["is_proxmox"] is False


def test_audit_proxmox_skips_credential_discovery_by_default(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    requested_paths: list[str] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
    ):
        _ = (pve_api_token, use_https, insecure, proxy)
        requested_paths.append(path)
        if path == "/access":
            return 200, _json_payload({"clustername": "lab"}), {}, None
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"permissions": {"/": {"Sys.Audit": 1, "User.Modify": 0}}}), {}, None
        raise AssertionError(f"unexpected endpoint when discover creds disabled: {path}")

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=token",
        use_https=True,
        insecure=True,
        proxy=None,
    )

    assert record["status"] == "token_ok"
    assert requested_paths == ["/access", "/access/permissions?path=/"]
    assert int(record.get("checked_endpoints") or 0) == 2
    assert int(record.get("credential_hits") or 0) == 0


def test_audit_proxmox_skips_discovery_crawl_when_caps_are_false(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    requested_paths: list[str] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
    ):
        _ = (pve_api_token, use_https, insecure, proxy)
        requested_paths.append(path)
        if path == "/access":
            return 200, _json_payload({"clustername": "lab"}), {}, None
        if path == "/access/permissions?path=/":
            return (
                200,
                _json_payload({"permissions": {"/": {"User.Modify": 0, "Sys.Audit": 0, "VM.Backup": 0}}}),
                {},
                None,
            )
        raise AssertionError(f"unexpected endpoint when all caps are false: {path}")

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=token",
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=True,
    )

    assert record["status"] == "token_ok"
    assert requested_paths == ["/access", "/access/permissions?path=/"]
    assert int(record.get("checked_endpoints") or 0) == 2
    assert int(record.get("credential_hits") or 0) == 0


def test_audit_proxmox_stream_callbacks_receive_urls_and_findings(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
    ):
        _ = (pve_api_token, use_https, insecure, proxy)
        if path == "/access":
            return 200, _json_payload({"clustername": "lab"}), {}, None
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"permissions": {"/": {"Sys.Audit": 1}}}), {}, None
        if path == "/nodes":
            return 200, _json_payload([{"node": "pve1"}]), {}, None
        if path == "/nodes/pve1/syslog":
            return 200, b"db_password=UltraSecret123\n", {}, None
        if path == "/nodes/pve1/report":
            return 200, b"backup_url=https://backup:pass@pbs.local/api", {}, None
        if path == "/nodes/pve1/tasks":
            return 200, _json_payload([]), {}, None
        if path == "/nodes/pve1/qemu":
            return 200, _json_payload([]), {}, None
        if path == "/nodes/pve1/lxc":
            return 200, _json_payload([]), {}, None
        if path == "/nodes/pve1/storage":
            return 200, _json_payload([]), {}, None
        if path == "/sdn":
            return 200, _json_payload({}), {}, None
        if path == "/cluster/backup":
            return 200, _json_payload([]), {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    discovered_paths: list[str] = []
    streamed_findings: list[dict[str, str]] = []
    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=token",
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=True,
        on_discovered_url=discovered_paths.append,
        on_credential_finding=streamed_findings.append,
    )

    assert record["status"] == "token_ok"
    assert "/access" in discovered_paths
    assert "/nodes/pve1/syslog" in discovered_paths
    assert streamed_findings
    assert any("password" in str(item.get("reason") or "").lower() for item in streamed_findings)


def test_audit_proxmox_denylist_ignores_csrfpreventiontoken(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
    ):
        _ = (pve_api_token, use_https, insecure, proxy)
        if path == "/access":
            return 200, _json_payload({"CSRFPreventionToken": "mock-csrf-token", "clustername": "lab"}), {}, None
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"permissions": {"/": {"Sys.Audit": 1}}}), {}, None
        if path == "/nodes":
            return 200, _json_payload([]), {}, None
        if path == "/sdn":
            return 200, _json_payload({}), {}, None
        if path == "/cluster/backup":
            return 200, _json_payload([]), {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=token",
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=True,
    )

    findings = [item for item in (record.get("findings") or []) if isinstance(item, dict)]
    assert not any("csrfpreventiontoken" in str(item.get("reason") or "").lower() for item in findings)


def test_audit_proxmox_detects_uri_jwt_and_base64_cloud_init(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    cloud_init = "#cloud-config\nchpasswd:\n  list: |\n    root:SuperSecret2026!\n  expire: false\n"
    cloud_init_b64 = base64.b64encode(cloud_init.encode("utf-8")).decode("ascii")

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        *,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
    ):
        _ = (pve_api_token, use_https, insecure, proxy)
        if path == "/access":
            return 200, _json_payload({"clustername": "lab"}), {}, None
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"permissions": {"/": {"Sys.Audit": 1}}}), {}, None
        if path == "/nodes":
            return 200, _json_payload([]), {}, None
        if path == "/sdn":
            return (
                200,
                _json_payload(
                    {
                        "upstream_dsn": "postgresql://app:AppSecret2026@db.internal:5432/app",
                        "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMiLCJyb2xlIjoiYWRtaW4ifQ.c2lnbmF0dXJlVG9rZW5WYWx1ZTIwMjY",
                    }
                ),
                {},
                None,
            )
        if path == "/cluster/backup":
            return 200, _json_payload([{"cloud_init_userdata": cloud_init_b64}]), {}, None
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=token",
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=True,
    )

    reasons = {str(item.get("reason") or "") for item in (record.get("findings") or []) if isinstance(item, dict)}
    assert "uri_with_auth" in reasons
    assert "jwt_token" in reasons
    assert "cloud_init_blob" in reasons


def test_parse_proxy_config_accepts_http_proxy() -> None:
    proxy, error = _parse_proxy_config("http://127.0.0.1:8080")
    assert error is None
    assert proxy is not None
    assert proxy.scheme == "http"
    assert proxy.host == "127.0.0.1"
    assert proxy.port == 8080
    assert proxy.username is None
    assert proxy.password is None


def test_parse_proxy_config_accepts_socks5h_auth_proxy() -> None:
    proxy, error = _parse_proxy_config("socks5h://audit:secret@127.0.0.1:1080")
    assert error is None
    assert proxy is not None
    assert proxy.scheme == "socks5h"
    assert proxy.host == "127.0.0.1"
    assert proxy.port == 1080
    assert proxy.username == "audit"
    assert proxy.password == "secret"


def test_parse_proxy_config_rejects_invalid_scheme() -> None:
    proxy, error = _parse_proxy_config("ftp://127.0.0.1:21")
    assert proxy is None
    assert "unsupported proxy scheme" in str(error or "")


def test_format_record_token_ok_caps_order_and_no_endpoints_findings() -> None:
    line = _format_record(
        {
            "host": "127.0.0.1",
            "port": 8006,
            "status": "token_ok",
            "cap_adduser": False,
            "cap_modify": False,
            "cap_backup": False,
            "cap_read": True,
            "checked_endpoints": 2,
            "credential_hits": 0,
        },
        "txt",
    )
    assert "(endpoints:" not in line
    assert "findings:" not in line
    assert "(adduser:false) (modify:false) (backup:false) (read:true)" in line


def test_format_discovered_urls_detail_records_for_discover_creds() -> None:
    lines = _format_discovered_urls_detail_records(
        {
            "host": "10.10.10.10",
            "port": 8006,
            "discover_creds": True,
            "use_https": True,
            "endpoint_results": [
                {"path": "/access", "status": 200, "error": None},
                {"path": "/nodes", "status": 200, "error": None},
            ],
        },
        "txt",
    )
    assert lines
    assert lines[0].endswith("[*] Discovered Credentials")
    assert any(line.endswith("[*] Discovered URL") for line in lines)
    assert any(line.endswith("[*] https://10.10.10.10:8006/api2/json/access") for line in lines)
    assert any(line.endswith("[*] https://10.10.10.10:8006/api2/json/nodes") for line in lines)
