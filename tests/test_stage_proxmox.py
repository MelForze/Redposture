from __future__ import annotations

import base64
import json
import threading
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.modules.proxmox import policy as proxmox_policy
from redposture_core.modules.proxmox import stage as proxmox_module_stage
from redposture_core.network_proxy import ProxyConfig
from redposture_core.stage_proxmox import (
    _PROXMOX_DEFAULT_CREDENTIALS,
    _audit_proxmox_host,
    _auth_header_value,
    _cap_text,
    _caps_suffix,
    _classify_auth_failure,
    _clean_value_text,
    _collect_nodes,
    _collect_permission_tokens,
    _collect_storage_ids,
    _collect_user_ids,
    _collect_vmids,
    _collect_volids,
    _decode_base64_text,
    _derive_permission_caps,
    _extract_error_message,
    _format_add_user_detail_records,
    _format_credential_attempts_records,
    _format_discovered_urls_detail_records,
    _format_findings_detail_records,
    _format_nodes_detail_records,
    _format_partial_detail_records,
    _format_record,
    _format_users_detail_records,
    _friendly_error_text,
    _generate_random_password,
    _is_connection_refused_error,
    _is_connection_timeout_error,
    _is_invalid_token_message,
    _is_permission_denied_message,
    _key_looks_sensitive,
    _looks_like_cloud_init_secret_blob,
    _looks_like_proxmox_response,
    _normalize_add_user_id,
    _proxmox_request,
    _proxmox_request_once,
    _ssl_context,
    _stream_proxmox_status,
    _value_looks_secret,
    build_proxmox_spec,
    run_proxmox_stage,
)
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun
from tests.stage_runtime_helpers import patch_module_host_stage_for_test, run_module_targets_for_test


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        ({"grant_role": "PVEAuditor", "add_user": None}, "--grant-role requires --add-user"),
        (
            {"grant_role": "PVEAuditor", "add_user": "audit@pve", "grant_path": "nodes"},
            "--grant-path must start with /",
        ),
    ],
)
def test_proxmox_policy_rejects_invalid_grant_options(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], expected_error: str
) -> None:
    monkeypatch.setattr(proxmox_policy, "validate_basic_module_args", lambda *_args, **_kwargs: None)
    errors: list[str] = []

    assert proxmox_policy.validate_args(SimpleNamespace(**overrides), SimpleNamespace(error=errors.append)) == 2
    assert errors == [expected_error]


def test_proxmox_policy_propagates_common_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox_policy, "validate_basic_module_args", lambda *_args, **_kwargs: 2)

    assert proxmox_policy.validate_args(SimpleNamespace(), SimpleNamespace()) == 2


def _proxmox_stage_record(
    kwargs: dict[str, object],
    *,
    status: str,
    detected: bool = True,
    error: str | None = None,
) -> AuditRecord:
    return AuditRecord(
        host=str(kwargs["host"]),
        port=int(kwargs["port"]),
        service="proxmox",
        module="proxmox",
        status=status,
        auth_required=status == "auth_failed",
        extra={
            "is_proxmox": detected,
            "error": error,
            "auth_method": "token" if kwargs.get("pve_api_token") else "password",
            "show_nodes": bool(kwargs.get("show_nodes")),
            "show_users": bool(kwargs.get("show_users")),
        },
    )


def _json_payload(data):
    return json.dumps({"data": data}, ensure_ascii=False).encode("utf-8")


def _proxmox_lifecycle_args(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "timeout": 1.0,
        "retries": 0,
        "workers": 1,
        "debug": False,
        "defcreds": False,
        "username": None,
        "password": None,
        "pve_api_token": None,
        "https": True,
        "insecure": True,
        "proxy": None,
        "discover_creds": False,
        "nodes": True,
        "show_nodes": False,
        "users": False,
        "show_users": False,
        "add_user": None,
        "output": None,
        "output_format": "json",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _run_proxmox_lifecycle(
    args: SimpleNamespace,
    credential_runs: tuple[AuditCredentialRun, ...],
) -> list[dict[str, object]]:
    plan = AuditCommandPlan(
        targets_by_port={8006: ("127.0.0.1",)},
        credential_runs=credential_runs,
        output_format="json",
        workers=1,
    )
    result = AuditCommandRunner(args=args, spec=build_proxmox_spec(args), emit_line=lambda _line: None).run_plan(plan)
    return result.records


def _install_proxmox_lifecycle_request_spy(
    monkeypatch: pytest.MonkeyPatch,
    *,
    valid_password: str,
    calls: list[dict[str, object]],
    deep_error: Exception | None = None,
    anonymous_access: bool = False,
) -> None:
    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        **kwargs: object,
    ):
        auth_headers = dict(kwargs.get("auth_headers") or {})
        form = dict(kwargs.get("form") or {})
        calls.append(
            {
                "path": path,
                "method": str(kwargs.get("method") or "GET"),
                "authenticated": bool(auth_headers),
                "username": form.get("username"),
                "password": form.get("password"),
            }
        )
        if path == "/access/ticket":
            if form.get("password") != valid_password:
                return 401, _json_payload({"message": "authentication failure"}), {}, None
            return (
                200,
                _json_payload({"ticket": "PVE:ticket", "CSRFPreventionToken": "csrf"}),
                {},
                None,
            )
        if path == "/access" and not auth_headers:
            if anonymous_access:
                return 200, _json_payload({}), {}, None
            return 401, _json_payload({"message": "authentication required"}), {}, None
        if path == "/access" and deep_error is not None:
            raise deep_error
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"/": {"Sys.Audit": 1}}), {}, None
        if path == "/nodes":
            return 200, _json_payload([{"node": "pve-a"}]), {}, None
        return 200, _json_payload({}), {}, None

    monkeypatch.setattr("redposture_core.modules.proxmox.actions._proxmox_request", fake_request)


def test_proxmox_lifecycle_direct_credentials_classify_login_and_data_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    _install_proxmox_lifecycle_request_spy(monkeypatch, valid_password="good", calls=calls)
    records = _run_proxmox_lifecycle(
        _proxmox_lifecycle_args(username="root@pam", password="good"),
        (AuditCredentialRun(username="root@pam", password="good", source="provided"),),
    )

    assert [(call["path"], call["authenticated"]) for call in calls] == [
        ("/access", False),
        ("/access/ticket", False),
        ("/access", True),
        ("/access/permissions?path=/", True),
        ("/nodes", True),
    ]
    assert records[0]["status"] == "token_ok"
    assert records[0]["nodes"] == ["pve-a"]


def test_proxmox_lifecycle_anonymous_access_runs_data_once_without_auth_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    _install_proxmox_lifecycle_request_spy(
        monkeypatch,
        valid_password="unused",
        calls=calls,
        anonymous_access=True,
    )
    records = _run_proxmox_lifecycle(
        _proxmox_lifecycle_args(),
        (AuditCredentialRun(source="anonymous"),),
    )

    assert [(call["path"], call["authenticated"]) for call in calls] == [
        ("/access", False),
        ("/access", False),
        ("/access/permissions?path=/", False),
        ("/nodes", False),
    ]
    assert [call["path"] for call in calls].count("/nodes") == 1
    assert records[0]["status"] == "open_no_auth"
    assert records[0]["auth_required"] is False
    assert records[0]["auth_method"] == "anonymous"
    assert records[0]["nodes"] == ["pve-a"]


@pytest.mark.parametrize("source", ["file", "default"])
def test_proxmox_lifecycle_two_candidates_login_each_but_run_data_only_for_selected(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    calls: list[dict[str, object]] = []
    _install_proxmox_lifecycle_request_spy(monkeypatch, valid_password="good", calls=calls)
    records = _run_proxmox_lifecycle(
        _proxmox_lifecycle_args(defcreds=source == "default"),
        (
            AuditCredentialRun(username="first@pam", password="bad", source=source),
            AuditCredentialRun(username="second@pam", password="good", source=source),
        ),
    )

    assert [(call["path"], call["username"], call["password"]) for call in calls[:3]] == [
        ("/access", None, None),
        ("/access/ticket", "first@pam", "bad"),
        ("/access/ticket", "second@pam", "good"),
    ]
    assert [call["path"] for call in calls].count("/access") == 2
    assert [call["path"] for call in calls].count("/access/permissions?path=/") == 1
    assert [call["path"] for call in calls].count("/nodes") == 1
    assert records[0]["status"] == ("weak_default_creds" if source == "default" else "token_ok")
    assert [item["username"] for item in records[0]["auth_attempts"]] == ["first@pam", "second@pam"]


def test_proxmox_lifecycle_preserves_detection_when_authenticated_data_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    _install_proxmox_lifecycle_request_spy(
        monkeypatch,
        valid_password="good",
        calls=calls,
        deep_error=RuntimeError("deep API exploded"),
    )
    records = _run_proxmox_lifecycle(
        _proxmox_lifecycle_args(username="root@pam", password="good"),
        (AuditCredentialRun(username="root@pam", password="good", source="provided"),),
    )

    assert records[0]["status"] == "fail"
    assert records[0]["is_proxmox"] is True
    assert records[0]["detection_preserved"] is True
    assert records[0]["detected_status"] == "auth_failed"
    assert records[0]["deep_error"] == "deep API exploded"


def test_proxmox_lifecycle_auth_failure_preserves_requested_action_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    _install_proxmox_lifecycle_request_spy(monkeypatch, valid_password="good", calls=calls)
    records = _run_proxmox_lifecycle(
        _proxmox_lifecycle_args(
            username="root@pam",
            password="",
            nodes=True,
            users=True,
        ),
        (AuditCredentialRun(username="root@pam", password="", source="provided"),),
    )

    assert [(call["path"], call["username"], call["password"]) for call in calls] == [
        ("/access", None, None),
        ("/access/ticket", "root@pam", ""),
    ]
    assert records[0]["status"] == "auth_failed"
    assert records[0]["is_proxmox"] is True
    assert records[0]["show_nodes"] is True
    assert records[0]["show_users"] is True
    assert records[0]["discover_creds"] is False
    assert records[0]["add_user"] is None


def test_proxmox_default_credentials_are_exact() -> None:
    assert _PROXMOX_DEFAULT_CREDENTIALS == (
        ("admin@pam", "admin"),
        ("admin@pve", "admin"),
        ("admin@pve", "password"),
        ("root@pam", "admin"),
        ("root@pam", "changeme"),
        ("root@pam", "password"),
        ("root@pam", "proxmox"),
        ("root@pam", "Proxmox123"),
        ("root@pam", "root"),
        ("root@pam", "toor"),
    )


def test_proxmox_credential_order_is_token_file_then_defaults(tmp_path) -> None:
    credentials = tmp_path / "proxmox-creds.txt"
    credentials.write_text("file@pam:file-pass\nroot@pam:root\n", encoding="utf-8")
    args = _proxmox_lifecycle_args(
        pve_api_token="audit@pve!scan=token-secret",
        username=str(credentials),
        defcreds=True,
    )

    proxmox_module_stage._prepare_proxmox_credential_runs(args)

    assert [(run.token, run.username, run.password, run.source) for run in args._audit_credential_runs] == [
        ("audit@pve!scan=token-secret", None, None, "provided"),
        (None, "file@pam", "file-pass", "file"),
        (None, "root@pam", "root", "file"),
        *[
            (None, username, password, "default")
            for username, password in _PROXMOX_DEFAULT_CREDENTIALS
            if (username, password) != ("root@pam", "root")
        ],
    ]


def test_proxmox_invalid_token_falls_back_to_basic_without_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    def fake_request(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _retries: int,
        **kwargs: object,
    ):
        auth_headers = dict(kwargs.get("auth_headers") or {})
        form = dict(kwargs.get("form") or {})
        auth_kind = (
            "token" if "Authorization" in auth_headers else "ticket" if "Cookie" in auth_headers else "anonymous"
        )
        calls.append((path, auth_kind))
        if path == "/access" and auth_kind == "anonymous":
            return 401, _json_payload({"message": "authentication required"}), {}, None
        if path == "/access" and auth_kind == "token":
            return 401, _json_payload({"message": "invalid api token"}), {}, None
        if path == "/access/ticket":
            assert form == {"username": "root@pam", "password": "good"}
            return 200, _json_payload({"ticket": "PVE:ticket", "CSRFPreventionToken": "csrf"}), {}, None
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"/": {"Sys.Audit": 1}}), {}, None
        if path == "/nodes":
            return 200, _json_payload([{"node": "pve-a"}]), {}, None
        return 200, _json_payload({}), {}, None

    monkeypatch.setattr("redposture_core.modules.proxmox.actions._proxmox_request", fake_request)
    args = _proxmox_lifecycle_args(
        pve_api_token="audit@pve!scan=bad-token-value",
        username="root@pam",
        password="good",
        defcreds=False,
    )
    proxmox_module_stage._prepare_proxmox_credential_runs(args)

    records = _run_proxmox_lifecycle(args, args._audit_credential_runs)

    assert records[0]["status"] == "token_ok"
    assert records[0]["auth_method"] == "password"
    assert records[0]["auth_username"] == "root@pam"
    assert "bad-token-value" not in json.dumps(records[0], ensure_ascii=False)
    assert calls[:4] == [
        ("/access", "anonymous"),
        ("/access", "token"),
        ("/access/ticket", "anonymous"),
        ("/access", "ticket"),
    ]


def test_proxmox_password_auth_failed_render_mentions_attempts_not_token() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8006,
        "status": "auth_failed",
        "auth_method": "password",
        "auth_attempts": [
            {"username": "root@pam", "password": "root", "source": "defcreds", "ok": "False"},
            {"username": "root@pam", "password": "admin", "source": "defcreds", "ok": "False"},
            {"username": "audit@pve", "password": "audit", "source": "provided", "ok": "False"},
        ],
    }
    assert _format_record(record, "txt") == ""
    lines = _format_credential_attempts_records(record, "txt")
    assert lines == [
        "PROXMOX \t127.0.0.1\t8006\t [-] root@pam:root",
        "PROXMOX \t127.0.0.1\t8006\t [-] root@pam:admin",
        "PROXMOX \t127.0.0.1\t8006\t [-] audit@pve:audit",
    ]
    assert "invalid pve api token" not in "\n".join(lines)


def test_proxmox_token_auth_failed_render_still_mentions_invalid_token() -> None:
    line = _format_record(
        {
            "host": "127.0.0.1",
            "port": 8006,
            "status": "auth_failed",
            "auth_method": "pveapitoken",
        },
        "txt",
    )

    assert "invalid pve api token" in line
    assert "password authentication failed" not in line


def test_proxmox_insufficient_privileges_with_password_auth_is_not_password_failure() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8006,
        "status": "insufficient_privileges",
        "auth_method": "password",
        "auth_attempts": [{"username": "root@pam", "password": "root", "source": "defcreds", "ok": "True"}],
    }
    assert _format_record(record, "txt") == ""
    lines = _format_credential_attempts_records(record, "txt")
    assert lines == ["PROXMOX \t127.0.0.1\t8006\t [+] root@pam:root"]
    assert "password authentication failed" not in "\n".join(lines)


def test_audit_proxmox_defcreds_all_fail_keeps_auth_attempts_and_password_render(monkeypatch) -> None:
    login_calls: list[tuple[str, str]] = []

    def fake_login(
        _host,
        _port,
        _timeout,
        _retries,
        *,
        username,
        password,
        use_https,
        insecure,
        proxy,
    ):
        _ = (use_https, insecure, proxy)
        login_calls.append((username, password))
        return None, "authentication failure"

    def fake_request(_host, _port, path, _timeout, _retries, **_kwargs):
        if path == "/access":
            return 401, b'{"errors":"authentication failure"}', {}, None
        return 401, b'{"errors":"permission denied"}', {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._login_proxmox_password", fake_login)
    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="",
        username=None,
        password=None,
        defcreds=True,
        use_https=True,
        insecure=True,
        proxy=None,
    )

    assert login_calls == list(_PROXMOX_DEFAULT_CREDENTIALS)
    assert record["status"] == "auth_failed"
    assert record["auth_method"] == "password"
    assert record["auth_attempts"] == [
        {"username": username, "password": password, "source": "defcreds", "ok": "False"}
        for username, password in _PROXMOX_DEFAULT_CREDENTIALS
    ]
    assert json.loads(_format_record(record, "json"))["auth_attempts"] == record["auth_attempts"]
    assert _format_record(record, "txt") == ""
    lines = _format_credential_attempts_records(record, "txt")
    assert len(lines) == len(_PROXMOX_DEFAULT_CREDENTIALS)
    for username, password in _PROXMOX_DEFAULT_CREDENTIALS:
        assert sum(f"[-] {username}:{password}" in line for line in lines) == 1
    assert "invalid pve api token" not in "\n".join(lines)


def test_audit_proxmox_defcreds_login_transport_error_is_not_token_failure(monkeypatch) -> None:
    def fake_login(*_args, **_kwargs):
        return None, "connection reset by peer"

    def fake_request(_host, _port, path, _timeout, _retries, **_kwargs):
        assert path == "/access"
        return 0, b"", {}, "connection reset by peer"

    monkeypatch.setattr("redposture_core.stage_proxmox._login_proxmox_password", fake_login)
    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="",
        username=None,
        password=None,
        defcreds=True,
        use_https=True,
        insecure=True,
        proxy=None,
    )

    assert record["status"] == "fail"
    assert record["auth_method"] == "password"
    line = _format_record(record, "txt")
    assert "connection failed err=connection reset by peer" in line
    assert "invalid pve api token" not in line


def test_proxmox_small_helpers_cover_auth_userid_caps_and_ssl() -> None:
    assert _auth_header_value("abc123") == "PVEAPIToken=abc123"
    assert _auth_header_value("PVEAPIToken=abc123") == "PVEAPIToken=abc123"

    generated = _generate_random_password(0)
    assert len(generated) == 1
    assert generated.isalnum()

    assert _normalize_add_user_id("scanner") == "scanner@pve"
    assert _normalize_add_user_id("scanner@pam") == "scanner@pam"
    assert _normalize_add_user_id("bad user") is None
    assert _normalize_add_user_id("") is None

    assert _cap_text(True) == "true"
    assert _cap_text(False) == "false"
    assert _cap_text(None) == "unknown"
    suffix = _caps_suffix({"cap_adduser": True, "cap_read": False, "cap_modify": None, "cap_backup": True})
    assert "(adduser:true)" in suffix
    assert "(read:false)" in suffix
    assert "(modify:unknown)" in suffix
    assert "(backup:true)" in suffix

    assert _ssl_context(use_https=False, insecure=False) is None
    assert _ssl_context(use_https=True, insecure=True) is not None
    assert _ssl_context(use_https=True, insecure=False) is not None


def test_proxmox_error_and_permission_helpers_cover_nested_payloads() -> None:
    payload = json.dumps(
        {"errors": {"token": "invalid token", "perm": "permission check failed"}}, ensure_ascii=False
    ).encode("utf-8")
    assert _extract_error_message(payload) == "invalid token; permission check failed"
    assert _is_invalid_token_message("invalid api token") is True
    assert _is_permission_denied_message("permission check failed") is True
    assert _classify_auth_failure(401, "invalid token") == "auth_failed"
    assert _classify_auth_failure(403, "permission check failed") == "insufficient_privileges"


def test_proxmox_collection_and_secret_helpers_cover_common_paths() -> None:
    nodes_payload = _json_payload([{"node": "pve1"}, {"node": "pve1"}, {"node": "pve2"}])
    assert _collect_nodes(nodes_payload) == ["pve1", "pve2"]
    assert _collect_vmids(_json_payload([{"vmid": 100}, {"vmid": 100}, {"vmid": 101}])) == ["100", "101"]
    assert _collect_storage_ids(_json_payload([{"storage": "local"}, {"storage": "local-lvm"}])) == [
        "local",
        "local-lvm",
    ]
    assert _collect_volids(_json_payload([{"volid": "local:iso/a.iso"}, {"volid": "local:backup/b.vma"}])) == [
        "local:iso/a.iso",
        "local:backup/b.vma",
    ]
    assert _collect_user_ids(_json_payload([{"userid": "root@pam"}, {"user": "audit@pve"}])) == [
        "root@pam",
        "audit@pve",
    ]

    permission_tokens: set[str] = set()
    _collect_permission_tokens(
        {"/": {"Sys.Audit": 1, "User.Modify": True, "nested": ["VM.Backup", {"Permissions.Modify": 1}]}},
        permission_tokens,
    )
    assert permission_tokens == {"Sys.Audit", "User.Modify", "VM.Backup", "Permissions.Modify"}
    assert _derive_permission_caps(permission_tokens) == {
        "adduser": True,
        "read": True,
        "modify": False,
        "backup": True,
    }

    assert _clean_value_text('  "Secret123!"  ') == "Secret123!"
    assert _value_looks_secret("SuperSecret2026!") is True
    assert _value_looks_secret("***") is False
    assert _key_looks_sensitive("db_password") is True
    assert _key_looks_sensitive("CSRFPreventionToken") is False

    cloud_init = "#cloud-config\nchpasswd:\n  list: |\n    root:SuperSecret2026!\n"
    encoded = base64.b64encode(cloud_init.encode("utf-8")).decode("ascii")
    assert _decode_base64_text(encoded) == cloud_init
    assert _looks_like_cloud_init_secret_blob(cloud_init) is True


def test_audit_proxmox_collects_credential_hits(monkeypatch) -> None:
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


def test_audit_proxmox_add_user_success(monkeypatch) -> None:
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
        grant_role="Administrator",
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


def test_audit_proxmox_add_user_shows_error_when_creation_fails(monkeypatch) -> None:
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
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
        add_user="scanner-bot",
        grant_role="Administrator",
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


def test_audit_proxmox_add_user_reports_acl_grant_error(monkeypatch) -> None:
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
        grant_role="Administrator",
    )

    assert record["status"] == "token_ok"
    assert record.get("added_user") == "scanner-bot@pve"
    assert isinstance(record.get("added_password"), str)
    assert record.get("add_user_error") is None
    assert record.get("add_user_privileges_granted") is False
    assert record.get("add_user_privileges_role") is None
    assert "permission" in str(record.get("add_user_privileges_error") or "").lower()


def test_audit_proxmox_marks_auth_failed_on_401(monkeypatch) -> None:
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


def test_audit_proxmox_marks_insufficient_privileges_on_403(monkeypatch) -> None:
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


def test_audit_proxmox_marks_insufficient_privileges_on_401_permission_message(monkeypatch) -> None:
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


def test_audit_proxmox_returns_fail_on_network_error(monkeypatch) -> None:
    def fake_request(*_args, **_kwargs):
        return 0, b"", {}, "connection refused (service is not listening on target port)"

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=token",
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
    )

    assert record["status"] == "fail"
    assert record["is_proxmox"] is False


def test_audit_proxmox_skips_credential_discovery_by_default(monkeypatch) -> None:
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
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
    )

    assert record["status"] == "token_ok"
    assert requested_paths == ["/access", "/access/permissions?path=/"]
    assert int(record.get("checked_endpoints") or 0) == 2
    assert int(record.get("credential_hits") or 0) == 0


def test_audit_proxmox_skips_discovery_crawl_when_caps_are_false(monkeypatch) -> None:
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
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=True,
    )

    assert record["status"] == "token_ok"
    assert requested_paths == ["/access", "/access/permissions?path=/"]
    assert int(record.get("checked_endpoints") or 0) == 2
    assert int(record.get("credential_hits") or 0) == 0


def test_audit_proxmox_stream_callbacks_receive_urls_and_findings(monkeypatch) -> None:
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
        username=None,
        password=None,
        defcreds=False,
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


def test_audit_proxmox_denylist_ignores_csrfpreventiontoken(monkeypatch) -> None:
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
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=True,
    )

    findings = [item for item in (record.get("findings") or []) if isinstance(item, dict)]
    assert not any("csrfpreventiontoken" in str(item.get("reason") or "").lower() for item in findings)


def test_audit_proxmox_detects_uri_jwt_and_base64_cloud_init(monkeypatch) -> None:
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
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=True,
    )

    reasons = {str(item.get("reason") or "") for item in (record.get("findings") or []) if isinstance(item, dict)}
    assert "uri_with_auth" in reasons
    assert "jwt_token" in reasons
    assert "cloud_init_blob" in reasons


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
            "findings": [
                {"endpoint": "/access", "reason": "text_password", "path": "$text", "sample": "password=secret"}
            ],
        },
        "txt",
    )
    assert lines
    assert lines[0].endswith("[*] Discovered Credentials")
    assert any(line.endswith("[*] Discovered URL") for line in lines)
    url_index = next(
        idx for idx, line in enumerate(lines) if line.endswith("[*] https://10.10.10.10:8006/api2/json/access")
    )
    finding_index = next(idx for idx, line in enumerate(lines) if "credential candidate reason=text_password" in line)
    assert finding_index == url_index + 1
    assert not any(line.endswith("[*] https://10.10.10.10:8006/api2/json/nodes") for line in lines)

    debug_lines = _format_discovered_urls_detail_records(
        {
            "host": "10.10.10.10",
            "port": 8006,
            "discover_creds": True,
            "use_https": True,
            "endpoint_results": [
                {"path": "/access", "status": 200, "error": None},
                {"path": "/nodes", "status": 200, "error": None},
            ],
            "findings": [
                {"endpoint": "/access", "reason": "text_password", "path": "$text", "sample": "password=secret"}
            ],
        },
        "txt",
        include_all_urls=True,
    )
    assert any(line.endswith("[*] https://10.10.10.10:8006/api2/json/access") for line in debug_lines)
    assert any(line.endswith("[*] https://10.10.10.10:8006/api2/json/nodes") for line in debug_lines)

    no_urls = _format_discovered_urls_detail_records(
        {
            "host": "10.10.10.10",
            "port": 8006,
            "discover_creds": True,
            "use_https": True,
            "endpoint_results": [],
        },
        "txt",
    )
    assert any(line.endswith("[*] <none>") for line in no_urls)


def test_proxmox_detail_renderers_cover_findings_nodes_users_text_and_json() -> None:
    record = {
        "timestamp": "2026-03-27T00:00:00Z",
        "host": "10.10.10.10",
        "port": 8006,
        "findings": [
            {"endpoint": "/nodes/pve1/syslog", "reason": "text_password", "path": "$text", "sample": "password=secret"}
        ],
        "show_nodes": True,
        "nodes": ["pve1"],
        "nodes_error": None,
        "show_users": True,
        "users": None,
        "users_error": "permission denied",
    }

    finding_lines = _format_findings_detail_records(record, "txt")
    assert any("credential candidate reason=text_password" in line for line in finding_lines)
    assert any('"type": "credential_hit"' in line for line in _format_findings_detail_records(record, "json"))

    node_lines = _format_nodes_detail_records(record, "txt")
    assert any("[*] Nodes" in line for line in node_lines)
    assert any(line.endswith("pve1") for line in node_lines)
    assert any('"type": "nodes_dump"' in line for line in _format_nodes_detail_records(record, "json"))

    user_lines = _format_users_detail_records(record, "txt")
    assert any("<error:permission denied>" in line for line in user_lines)
    assert any('"type": "users_dump"' in line for line in _format_users_detail_records(record, "json"))


def test_proxmox_partial_response_is_visible_in_text_and_renderer_dispatch() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8006,
        "partial": True,
        "responses_truncated": 2,
        "partial_error": "2 endpoint response(s) exceeded the body limit",
    }

    assert _format_partial_detail_records(record, "json") == []
    assert _format_partial_detail_records(record, "txt") == [
        "PROXMOX \t127.0.0.1\t8006\t [!] partial results responses_truncated=2 "
        "err=2 endpoint response(s) exceeded the body limit"
    ]
    assert (
        "_format_partial_detail_records"
        in __import__("redposture_core.modules.proxmox.render", fromlist=["__all__"]).__all__
    )


def test_format_record_covers_auth_and_fail_statuses() -> None:
    assert "token valid but insufficient privileges" in _format_record(
        {"host": "127.0.0.1", "port": 8006, "status": "insufficient_privileges"}, "txt"
    )
    assert "invalid pve api token" in _format_record(
        {"host": "127.0.0.1", "port": 8006, "status": "auth_failed"}, "txt"
    )
    assert "connection failed err=boom" in _format_record(
        {"host": "127.0.0.1", "port": 8006, "status": "fail", "error": "boom"}, "txt"
    )


def test_stream_proxmox_status_emits_detect_once_and_can_suppress_fail_line() -> None:
    lines: list[str] = []
    lock = threading.Lock()
    emitted: set[tuple[str, int]] = set()

    record = {
        "host": "127.0.0.1",
        "port": 8006,
        "is_proxmox": True,
        "status": "fail",
        "error": "connection refused",
    }
    _stream_proxmox_status(
        out_fh=None,
        emit_line=lines.append,
        lock=lock,
        status_emitted=emitted,
        record=record,
        output_format="txt",
        suppress_fail_status_lines=True,
        emit_detect_line=True,
    )
    _stream_proxmox_status(
        out_fh=None,
        emit_line=lines.append,
        lock=lock,
        status_emitted=emitted,
        record=record,
        output_format="txt",
        suppress_fail_status_lines=True,
        emit_detect_line=True,
    )

    assert sum(1 for line in lines if "Proxmox API" in line) == 1
    assert not any("connection failed" in line for line in lines)


def test_audit_proxmox_targets_streams_discovery_and_suppresses_duplicate_status(monkeypatch) -> None:
    def fake_audit(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
        *,
        discover_creds: bool,
        show_nodes: bool,
        show_users: bool,
        add_user: str | None,
        on_discovered_url=None,
        on_status_ready=None,
        on_credential_finding=None,
    ):
        _ = (timeout, retries, pve_api_token, insecure, proxy, show_nodes, show_users, add_user)
        record = {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": port,
            "is_proxmox": True,
            "status": "token_ok",
            "use_https": use_https,
            "discover_creds": discover_creds,
            "endpoint_results": [{"path": "/access"}, {"path": "/access"}],
            "findings": [
                {"endpoint": "/access", "reason": "text_password", "path": "$text", "sample": "password=secret"}
            ],
            "checked_endpoints": 1,
            "successful_endpoints": 1,
            "credential_hits": 1,
            "cap_adduser": False,
            "cap_modify": False,
            "cap_backup": False,
            "cap_read": True,
            "show_nodes": False,
            "show_users": False,
            "add_user": None,
        }
        if on_status_ready is not None:
            on_status_ready(record)
        if on_discovered_url is not None:
            on_discovered_url("/access")
        if on_credential_finding is not None:
            on_credential_finding(record["findings"][0])
        return record

    monkeypatch.setattr("redposture_core.stage_proxmox._audit_proxmox_host", fake_audit)

    lines: list[str] = []
    total, token_ok, insufficient, auth_failed, fail, credential_hits = run_module_targets_for_test(
        "proxmox",
        hosts=["127.0.0.1"],
        port=8006,
        timeout=1.0,
        retries=0,
        workers=1,
        pve_api_token="monitor@pve!audit=token",
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=True,
        show_nodes=False,
        show_users=False,
        add_user=None,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_fail_status_lines=False,
    )

    assert (total, token_ok, insufficient, auth_failed, fail, credential_hits) == (1, 1, 0, 0, 0, 1)
    assert sum(1 for line in lines if "Proxmox API" in line) == 1
    assert sum(1 for line in lines if "Discovered Credentials" in line) == 1
    assert any("/api2/json/access" in line for line in lines)
    assert any("credential candidate reason=text_password" in line for line in lines)


def test_audit_proxmox_targets_can_suppress_fail_status_lines(monkeypatch) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 8006,
            "is_proxmox": False,
            "status": "fail",
            "discover_creds": False,
            "show_nodes": False,
            "show_users": False,
            "add_user": None,
            "credential_hits": 0,
            "error": "connection refused (service is not listening on target port)",
        }

    monkeypatch.setattr("redposture_core.stage_proxmox._audit_proxmox_host", fake_audit)

    lines: list[str] = []
    total, token_ok, insufficient, auth_failed, fail, credential_hits = run_module_targets_for_test(
        "proxmox",
        hosts=["127.0.0.1"],
        port=8006,
        timeout=1.0,
        retries=0,
        workers=1,
        pve_api_token="monitor@pve!audit=token",
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=False,
        show_nodes=False,
        show_users=False,
        add_user=None,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_fail_status_lines=True,
    )

    assert (total, token_ok, insufficient, auth_failed, fail, credential_hits) == (1, 0, 0, 0, 1, 0)
    assert len(lines) == 1
    assert "PROXMOX audit inconclusive" in lines[0]
    assert all("Connection refused" not in line and "timed out" not in line for line in lines)


def test_audit_proxmox_targets_emits_stage_debug_markers(monkeypatch) -> None:
    calls: list[tuple[str, bool, bool, bool, str | None]] = []

    def fake_audit(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        pve_api_token: str,
        use_https: bool,
        insecure: bool,
        proxy,
        *,
        discover_creds: bool = False,
        show_nodes: bool = False,
        show_users: bool = False,
        add_user: str | None = None,
        on_status_ready=None,
        on_discovered_url=None,
        on_credential_finding=None,
    ):
        _ = (
            port,
            timeout,
            retries,
            pve_api_token,
            use_https,
            insecure,
            proxy,
            on_discovered_url,
            on_credential_finding,
        )
        calls.append((host, discover_creds, show_nodes, show_users, add_user))
        record = {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 8006,
            "is_proxmox": True,
            "status": "token_ok",
            "discover_creds": discover_creds,
            "show_nodes": show_nodes,
            "show_users": show_users,
            "add_user": add_user,
            "users": [],
            "users_error": None,
            "nodes": [],
            "nodes_error": None,
            "findings": [],
            "credential_hits": 0,
            "checked_endpoints": 1,
            "successful_endpoints": 1,
            "cap_adduser": False,
            "cap_read": True,
            "cap_modify": False,
            "cap_backup": False,
            "use_https": True,
            "endpoint_results": [],
            "error": None,
        }
        if on_status_ready is not None:
            on_status_ready(record)
        return record

    monkeypatch.setattr("redposture_core.stage_proxmox._audit_proxmox_host", fake_audit)
    debug_lines: list[str] = []
    totals = run_module_targets_for_test(
        "proxmox",
        hosts=["127.0.0.1"],
        port=8006,
        timeout=1.0,
        retries=0,
        workers=1,
        pve_api_token="monitor@pve!audit=token",
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
        discover_creds=False,
        show_nodes=True,
        show_users=False,
        add_user=None,
        output_path=None,
        output_format="txt",
        emit_line=None,
        suppress_fail_status_lines=False,
        debug_emit=debug_lines.append,
        show_progress=False,
    )
    assert totals == (1, 1, 0, 0, 0, 0)
    assert calls == [
        ("127.0.0.1", False, False, False, None),
        ("127.0.0.1", False, True, False, None),
    ]
    assert any(line.startswith("pass=1 detect start total=1") for line in debug_lines)
    assert any("stage2_gate=run reason=status=token_ok" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=1" in line for line in debug_lines)


def test_audit_proxmox_unexpected_http_marks_not_detected(monkeypatch) -> None:
    def fake_request(*_args, **_kwargs):
        return 500, b'{"errors":"internal"}', {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)

    record = _audit_proxmox_host(
        host="127.0.0.1",
        port=8006,
        timeout=1.0,
        retries=0,
        pve_api_token="monitor@pve!audit=token",
        username=None,
        password=None,
        defcreds=False,
        use_https=True,
        insecure=True,
        proxy=None,
    )

    assert record["status"] == "fail"
    assert record["is_proxmox"] is False
    assert "unexpected HTTP 500" in str(record.get("error") or "")


def test_proxmox_error_helpers_cover_tls_and_transport_cases() -> None:
    assert _friendly_error_text("certificate verify failed") == "tls verification failed (try --insecure)"
    assert _friendly_error_text("wrong version number") == "tls/http protocol mismatch"
    assert _friendly_error_text("[Errno 111] Connection refused").startswith("connection refused")
    assert _friendly_error_text("[Errno 110] timed out") == "connection timeout"
    assert _friendly_error_text("[Errno -2] Name or service not known") == "dns lookup failed"
    assert _friendly_error_text("[Errno 101] network is unreachable") == "network unreachable"
    assert _is_connection_refused_error("connection refused (service is not listening on target port)") is True
    assert _is_connection_timeout_error("connection timeout") is True


def test_run_proxmox_stage_validation_and_group_scheme_override(monkeypatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.infos: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def warn(self, message: str) -> None:
            self.infos.append(message)

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def _paint(self, text: str, _color: str, _stream) -> str:
            return text

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole(debug=True)
    monkeypatch.setattr("redposture_core.stage_proxmox.Console", lambda debug=False: fake_console)

    base_args = dict(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        pve_api_token="",
        proxy=None,
        port=8006,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        output=None,
        output_format="txt",
        discover_creds=False,
        nodes=False,
        show_nodes=False,
        users=False,
        show_users=False,
        add_user="",
        https=False,
        insecure=True,
    )

    rc = run_proxmox_stage(SimpleNamespace(**base_args), logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 1
    assert not any("--pveapitoken, -u/-p, or --defcreds is required" in item for item in fake_console.errors)

    fake_console.errors.clear()
    calls: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        calls.append(dict(kwargs))
        status = "token_ok" if kwargs.get("pve_api_token") else "auth_failed"
        return _proxmox_stage_record(kwargs, status=status)

    patch_module_host_stage_for_test(monkeypatch, "proxmox", fake_audit_targets)

    rc = run_proxmox_stage(
        SimpleNamespace(
            **{
                **base_args,
                "debug": True,
                "pve_api_token": "monitor@pve!audit=token",
                "targets": "http://host-http:8006,https://host-https:8443",
                "https": True,
            }
        ),
        logger=SimpleNamespace(log=lambda *_a, **_k: None),
    )
    assert rc == 0
    assert [
        (call["host"], call["use_https"])
        for call in calls
        if not call["pve_api_token"] and call["run_deep_checks"] is False
    ] == [("host-http", False), ("host-https", True)]
    assert {
        (call["host"], call["use_https"]) for call in calls if call["pve_api_token"] == "monitor@pve!audit=token"
    } == {("host-http", False), ("host-https", True)}
    for host in ("host-http", "host-https"):
        host_calls = [call for call in calls if call["host"] == host]
        assert not host_calls[0]["pve_api_token"]
        assert host_calls[0]["run_deep_checks"] is False
        assert host_calls[1]["pve_api_token"] == "monitor@pve!audit=token"
        assert host_calls[1]["run_deep_checks"] is True
    assert any("proxmox audit started:" in item for item in fake_console.infos)


def test_run_proxmox_stage_username_password_and_defcreds(monkeypatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def info(self, _message: str) -> None:
            return

        def warn(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def _paint(self, text: str, _color: str, _stream) -> str:
            return text

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr("redposture_core.stage_proxmox.Console", lambda debug=False: fake_console)
    monkeypatch.setattr("redposture_core.stage_proxmox.collect_scan_ports", lambda *_a, **_k: [8006])
    monkeypatch.setattr(
        "redposture_core.stage_proxmox.collect_scan_target_specs",
        lambda *_a, **_k: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        "redposture_core.stage_proxmox.build_scan_execution_groups",
        lambda *_a, **_k: [SimpleNamespace(hosts=["127.0.0.1"], port=8006, scheme_hint=None)],
    )

    calls: list[dict[str, object]] = []
    retained: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        calls.append(dict(kwargs))
        status = "token_ok" if kwargs.get("username") else "auth_failed"
        record = _proxmox_stage_record(kwargs, status=status)
        record.extra["winner_marker"] = kwargs.get("password")
        return record

    patch_module_host_stage_for_test(monkeypatch, "proxmox", fake_audit_targets)

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        pve_api_token=None,
        username="root@pam",
        password="proxmox",
        defcreds=True,
        proxy=None,
        port=8006,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        output=None,
        output_format="txt",
        discover_creds=False,
        nodes=False,
        show_nodes=False,
        users=False,
        show_users=False,
        add_user="",
        https=True,
        insecure=True,
        _record_callback=lambda record: retained.append(record),
    )

    rc = run_proxmox_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))

    assert rc == 0
    assert not fake_console.errors
    assert [(call["username"], call["password"], call["defcreds"], call["run_deep_checks"]) for call in calls] == [
        (None, None, False, False),
        ("root@pam", "proxmox", False, True),
        *[
            (username, password, False, True)
            for username, password in _PROXMOX_DEFAULT_CREDENTIALS
            if (username, password) != ("root@pam", "proxmox")
        ],
    ]
    assert len(retained) == 1
    assert retained[0]["status"] == "token_ok"
    assert retained[0]["winner_marker"] == "proxmox"
    attempts = retained[0]["attempted_credentials"]
    assert isinstance(attempts, list)
    assert len(attempts) == len(_PROXMOX_DEFAULT_CREDENTIALS)


def test_run_proxmox_stage_multi_instance_uses_single_global_progress(monkeypatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def info(self, _message: str) -> None:
            return

        def warn(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def _paint(self, text: str, _color: str, _stream) -> str:
            return text

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr("redposture_core.stage_proxmox.Console", lambda debug=False: fake_console)
    monkeypatch.setattr("redposture_core.stage_proxmox.collect_scan_ports", lambda *_a, **_k: [8006, 18061, 18062])
    monkeypatch.setattr(
        "redposture_core.stage_proxmox.collect_scan_target_specs",
        lambda *_a, **_k: [SimpleNamespace(host="127.0.0.1", scheme="https", explicit_port=8006)],
    )
    monkeypatch.setattr(
        "redposture_core.stage_proxmox.build_scan_execution_groups",
        lambda *_a, **_k: [
            SimpleNamespace(hosts=["127.0.0.1"], port=8006, scheme_hint="https"),
            SimpleNamespace(hosts=["127.0.0.1"], port=18061, scheme_hint="https"),
            SimpleNamespace(hosts=["127.0.0.1"], port=18062, scheme_hint="https"),
        ],
    )

    calls: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        calls.append(dict(kwargs))
        return _proxmox_stage_record(
            kwargs,
            status="fail",
            detected=False,
            error="connection refused",
        )

    patch_module_host_stage_for_test(monkeypatch, "proxmox", fake_audit_targets)

    progress_totals: list[int] = []
    progress_advances: list[int] = []

    class _FakeProgressBar:
        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            progress_totals.append(int(total))

        def advance(self, amount: int = 1) -> None:
            progress_advances.append(int(amount))

        def close(self) -> None:
            return

    monkeypatch.setattr(
        "redposture_core.stage_proxmox.start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        pve_api_token="monitor@pve!audit=token",
        proxy=None,
        port=8006,
        ports="8006,18061,18062",
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        output=None,
        output_format="txt",
        discover_creds=False,
        nodes=True,
        show_nodes=False,
        users=False,
        show_users=False,
        add_user="",
        https=True,
        insecure=True,
    )
    rc = run_proxmox_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 1
    assert not fake_console.errors
    assert [call["port"] for call in calls] == [8006, 18061, 18062]
    assert all(call["run_deep_checks"] is False for call in calls)
    assert all(call["show_nodes"] is False for call in calls)
    assert progress_totals == [3]
    assert progress_advances == [1, 1, 1]


def test_proxmox_request_once_and_retry_paths(monkeypatch) -> None:
    proxy = ProxyConfig(
        scheme="http",
        host="127.0.0.1",
        port=8080,
        username=None,
        password=None,
        raw_url="http://127.0.0.1:8080",
    )

    class _FakeHttpClient:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def request(self, *_args, **_kwargs):
            return SimpleNamespace(status=200, body=b"{}", headers={}, error=None)

    monkeypatch.setattr("redposture_core.stage_proxmox.HttpApiClient", _FakeHttpClient)
    status, payload, _headers, error = _proxmox_request_once(
        "127.0.0.1",
        8006,
        "/access",
        1.0,
        pve_api_token="monitor@pve!audit=token",
        use_https=False,
        insecure=True,
        proxy=proxy,
    )
    assert (status, payload, error) == (200, b"{}", None)

    retry_calls = {"count": 0}

    def fake_once(*_args, **_kwargs):
        retry_calls["count"] += 1
        if retry_calls["count"] == 1:
            return 0, b"", {}, "connection timeout"
        return 200, b'{"ok":1}', {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request_once", fake_once)
    monkeypatch.setattr("redposture_core.stage_proxmox._retry_delay", lambda _attempt: 0.0)
    status, payload, _headers, error = _proxmox_request(
        "127.0.0.1",
        8006,
        "/access",
        1.0,
        1,
        pve_api_token="monitor@pve!audit=token",
        use_https=False,
        insecure=True,
        proxy=None,
    )
    assert retry_calls["count"] == 2
    assert (status, payload, error) == (200, b'{"ok":1}', None)


def test_proxmox_add_user_does_not_grant_global_acl_implicitly(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_request(_host, _port, path, _timeout, _retries, **kwargs):
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path))
        if path == "/access":
            return 200, _json_payload({"clustername": "lab"}), {}, None
        if path == "/access/permissions?path=/":
            return 200, _json_payload({"permissions": {"/": {"User.Modify": 1}}}), {}, None
        if path == "/access/users" and method == "POST":
            return 200, _json_payload(None), {}, None
        if path == "/access/acl":
            raise AssertionError("ACL endpoint must require explicit --grant-role")
        return 404, b"{}", {}, None

    monkeypatch.setattr("redposture_core.stage_proxmox._proxmox_request", fake_request)
    record = _audit_proxmox_host(
        "127.0.0.1",
        8006,
        1.0,
        0,
        "monitor@pve!audit=token",
        True,
        True,
        None,
        add_user="scanner-bot",
    )

    assert record["added_user"] == "scanner-bot@pve"
    assert record["grant_role"] is None
    assert record["add_user_privileges_granted"] is None
    assert not any(path == "/access/acl" for _method, path in calls)
    assert _looks_like_proxmox_response(200, b"<html>login</html>", {}) is False
