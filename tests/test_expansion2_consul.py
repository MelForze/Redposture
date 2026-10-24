"""Consul orchestration, inventory failures, and cleanup contracts without services."""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core.modules.consul import actions as consul


def _options(**changes: Any) -> dict[str, Any]:
    options: dict[str, Any] = dict(
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
    options.update(changes)
    return options


def _scopes(ok: bool) -> dict[str, Any]:
    return {
        name: {"ok": ok, "status": 200 if ok else 403, "count": 1 if ok else None, "error": None if ok else "Forbidden"}
        for name in ("kv", "services", "agents")
    }


@pytest.fixture
def consul_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consul, "_probe_consul_scheme", Mock(return_value=(True, "http", False, False, "leader", None)))
    monkeypatch.setattr(consul, "_consul_access_matrix", Mock(return_value=_scopes(True)))
    monkeypatch.setattr(consul, "_agent_self_probe", Mock(return_value={"ok": True}))


@pytest.mark.parametrize("scope", ["kv", "members", "nodes"])
@pytest.mark.parametrize(
    ("response", "error"),
    [
        ((0, None, "timeout", False, False), "timeout"),
        ((401, None, None, False, False), "Unauthorized"),
        ((403, None, None, False, False), "Forbidden"),
        ((503, None, None, False, False), "status=503"),
        ((200, {}, None, False, False), "invalid"),
    ],
)
def test_requested_inventory_preserves_denial_and_malformed_response(
    monkeypatch: pytest.MonkeyPatch, scope: str, response: Any, error: str
) -> None:
    monkeypatch.setattr(consul, "_consul_get_json_any", Mock(return_value=response))
    function = {
        "kv": consul._consul_kv_dump,
        "members": consul._consul_agent_members_list,
        "nodes": consul._consul_catalog_nodes_list,
    }[scope]
    rows, result_error = function("h", 8500, 1, scheme="http", insecure=False)
    assert rows is None and result_error and error in result_error


@pytest.mark.parametrize("token_identity", [True, False, None])
def test_acl_identity_controls_authentication_without_hiding_anonymous_keys(
    consul_api: None, monkeypatch: pytest.MonkeyPatch, token_identity: bool | None
) -> None:
    monkeypatch.setattr(
        consul,
        "_acl_token_self_probe",
        Mock(
            return_value={"ok": token_identity, "error": "identity unavailable" if token_identity is not True else None}
        ),
    )
    keys = Mock(return_value=(["app/key"], None))
    monkeypatch.setattr(consul, "_consul_kv_keys_list", keys)
    record = consul._audit_consul_host_core("h", 8500, 1, 0, **_options(token="supplied", show_keys=True))
    assert record["auth_valid"] is token_identity
    assert record["kv_keys_list"] == ["app/key"]
    assert keys.call_args.kwargs["headers"] == ({"X-Consul-Token": "supplied"} if token_identity is True else None)


def test_failed_authenticated_keys_retry_anonymous_only_when_scope_is_open(
    consul_api: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(consul, "_acl_token_self_probe", Mock(return_value={"ok": True}))
    keys = Mock(side_effect=[(None, "Forbidden"), (["fallback/key"], None)])
    monkeypatch.setattr(consul, "_consul_kv_keys_list", keys)
    result = consul._audit_consul_host_core("h", 8500, 1, 0, **_options(token="token", show_keys=True))
    assert result["kv_keys_list"] == ["fallback/key"] and result["kv_keys_error"] is None
    assert [call.kwargs["headers"] for call in keys.call_args_list] == [{"X-Consul-Token": "token"}, None]


@pytest.mark.parametrize("error", ["Forbidden", None])
def test_explicit_service_dump_continues_when_catalog_unavailable(
    consul_api: None, monkeypatch: pytest.MonkeyPatch, error: str | None
) -> None:
    monkeypatch.setattr(consul, "_consul_catalog_services_list", Mock(return_value=(None, "catalog forbidden")))
    monkeypatch.setattr(consul, "_consul_get_checks", Mock(return_value=(403, None, "checks forbidden")))
    details = Mock(return_value=(None, error))
    monkeypatch.setattr(consul, "_consul_health_service_instances", details)
    result = consul._audit_consul_host_core(
        "h", 8500, 1, 0, **_options(show_services=True, dump_requested=True, service_dump_name="payments")
    )
    assert details.call_args.args[2] == "payments"
    assert result["services_list_error"] == "catalog forbidden"
    assert result["service_instances"] == {}
    assert result["service_instances_errors"] == ({"payments": error} if error else {})


@pytest.mark.parametrize("basic_case", ["denied", "unknown", "proved"])
def test_basic_credential_verdict_requires_changed_access(
    consul_api: None, monkeypatch: pytest.MonkeyPatch, basic_case: str
) -> None:
    anonymous = _scopes(False)
    authenticated = _scopes(basic_case == "proved")
    if basic_case == "unknown":
        authenticated = {name: {"ok": False, "error": None} for name in anonymous}
    monkeypatch.setattr(consul, "_consul_access_matrix", Mock(side_effect=[anonymous, authenticated]))
    monkeypatch.setattr(
        consul,
        "_agent_self_probe",
        Mock(
            side_effect=[{"ok": False}, {"ok": False if basic_case == "denied" else None, "error": "self unavailable"}]
        ),
    )
    result = consul._audit_consul_host_core("h", 8500, 1, 0, **_options(username="u", password="p"))
    assert result["auth_mode"] == "basic"
    assert result["auth_valid"] is {"denied": None, "unknown": None, "proved": True}[basic_case]
    assert result["auth_error"] == "self unavailable"


@pytest.mark.parametrize("capable", [False, True])
@pytest.mark.parametrize("operation", ["cleanup", "payload", "target"])
def test_active_action_dispatch_uses_safe_doubles_and_capability_flags(
    consul_api: None, monkeypatch: pytest.MonkeyPatch, capable: bool, operation: str
) -> None:
    monkeypatch.setattr(
        consul,
        "_agent_self_probe",
        Mock(return_value={"ok": True, "local_script_checks": capable, "remote_script_checks": capable}),
    )
    cleanup = Mock(return_value={"action": "delete", "deleted": 0})
    register = Mock(return_value={"registered": True})
    monkeypatch.setattr(consul, "_consul_script_revshell_cleanup", cleanup)
    monkeypatch.setattr(consul, "_consul_script_revshell", register)
    changes = (
        dict(delete_revshell=True, revshell_check_id="selected")
        if operation == "cleanup"
        else dict(
            revshell_enabled=True,
            revshell_payload="true" if operation == "payload" else None,
            revshell_host=None if operation == "payload" else "127.0.0.1",
            revshell_port=None if operation == "payload" else 4444,
        )
    )
    result = consul._audit_consul_host_core("h", 8500, 1, 0, **_options(**changes))
    assert result["rce"] is capable
    if operation == "cleanup":
        cleanup.assert_called_once()
        assert cleanup.call_args.kwargs["check_id"] == "selected"
        register.assert_not_called()
    elif capable:
        register.assert_called_once()
        assert register.call_args.kwargs["payload_cmd"] == ("true" if operation == "payload" else None)
    else:
        register.assert_not_called()
        assert result["script_revshell"] is None


@pytest.mark.parametrize(
    ("response", "queried", "error"),
    [((0, None, "timeout"), False, "timeout"), ((200, [], None), True, "invalid checks response")],
)
def test_cleanup_query_failures_never_attempt_deregistration(
    monkeypatch: pytest.MonkeyPatch, response: Any, queried: bool, error: str
) -> None:
    monkeypatch.setattr(consul, "_consul_get_checks", Mock(return_value=response))
    delete = Mock(side_effect=AssertionError("no valid check inventory"))
    monkeypatch.setattr(consul, "_consul_put_no_body", delete)
    result = consul._consul_script_revshell_cleanup("h", 8500, 1, scheme="http", insecure=False, headers=None)
    assert result["queried"] is queried and result["query_error"] == error
    assert result["matched"] == result["deleted"] == 0


@pytest.mark.parametrize("selected", ["exact/id", "missing"])
def test_cleanup_exact_selector_preserves_sibling_checks(monkeypatch: pytest.MonkeyPatch, selected: str) -> None:
    monkeypatch.setattr(
        consul,
        "_consul_get_checks",
        Mock(return_value=(200, {"exact/id": {}, "exact/id-sibling": {}, "rev-rp-other": {}}, None)),
    )
    delete = Mock(return_value=(204, None))
    monkeypatch.setattr(consul, "_consul_put_no_body", delete)
    result = consul._consul_script_revshell_cleanup(
        "h", 8500, 1, scheme="http", insecure=False, headers=None, check_id=selected
    )
    assert result["target_mode"] == "id"
    assert result["deleted"] == result["matched"] == (1 if selected == "exact/id" else 0)
    if selected == "exact/id":
        assert delete.call_args.args[2] == "/v1/agent/check/deregister/exact%2Fid"
    else:
        delete.assert_not_called()


@pytest.mark.parametrize("error", [None, "write timeout"])
def test_service_delete_resolves_name_to_id_after_first_denial(
    monkeypatch: pytest.MonkeyPatch, error: str | None
) -> None:
    monkeypatch.setattr(
        consul,
        "_consul_get_json_any",
        Mock(
            return_value=(
                200,
                {"invalid": None, "x": {"Service": "other"}, "id/1": {"Service": "web", "ID": "id/1"}},
                None,
                False,
                False,
            )
        ),
    )
    delete = Mock(side_effect=[(403, "Forbidden"), (204 if error is None else 0, error)])
    monkeypatch.setattr(consul, "_consul_put_no_body", delete)
    result = consul._consul_service_action(
        "h", 8500, 1, scheme="http", insecure=False, headers=None, service_name=" web ", delete=True
    )
    assert [call.args[2] for call in delete.call_args_list] == [
        "/v1/agent/service/deregister/web",
        "/v1/agent/service/deregister/id%2F1",
    ]
    assert result["ok"] is (error is None)
    assert result["error"] == error


@pytest.mark.parametrize(
    "response", [(0, None, "offline"), (403, "denied", None), (400, {"error": "Args unsupported"}, None)]
)
def test_script_registration_failure_returns_evidence_without_waiting(
    monkeypatch: pytest.MonkeyPatch, response: Any
) -> None:
    write = Mock(return_value=response)
    monkeypatch.setattr(consul, "_consul_put_json", write)
    sleep = Mock(side_effect=AssertionError("failed registration cannot wait"))
    monkeypatch.setattr(consul.time, "sleep", sleep)
    result = consul._consul_script_revshell(
        "h",
        8500,
        1,
        scheme="http",
        insecure=False,
        headers=None,
        lhost=None,
        lport=None,
        payload_cmd="true",
        check_id="safe-double",
    )
    assert result["registered"] is False
    assert result["register_status"] == response[0]
    assert result["register_error"]
    assert write.call_count == (2 if response[0] == 400 else 1)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"keys_requested": True, "kv_keys_list": []}, "<no keys>"),
        ({"keys_requested": True, "kv_keys_list": ["a", "", None]}, " a"),
        ({"keys_requested": True}, "[-] keys unavailable"),
        ({"dump_requested": True, "dump_all_requested": True, "kv_dump_items": []}, "<no keys>"),
        ({"dump_requested": True, "kv_key_requested": "missing", "kv_dump_items": []}, "<key not found>"),
        (
            {
                "dump_requested": True,
                "dump_all_requested": True,
                "kv_dump_items": [None, {}, {"key": "a", "value": ""}],
            },
            "a=<empty>",
        ),
        (
            {"dump_requested": True, "dump_all_requested": True, "kv_dump_error": "Forbidden"},
            "kv dump unavailable err=Forbidden",
        ),
        ({"dump_requested": True, "dump_all_requested": True}, "[-] kv dump unavailable"),
        ({"services_list_requested": True, "services_list": [], "service_dump_name": "absent"}, "<service not found>"),
        ({"services_list_requested": True, "services_list": [None, {}, {"name": "web"}]}, " web"),
        ({"services_list_requested": True}, "[-] services unavailable"),
        ({"services_list_requested": True, "services_list_error": "Forbidden"}, "services unavailable err=Forbidden"),
        (
            {
                "services_list_requested": True,
                "dump_requested": True,
                "services_list": [{"name": "web"}],
                "service_instances": {"web": []},
            },
            "<no service instances>",
        ),
        (
            {
                "services_list_requested": True,
                "dump_requested": True,
                "services_list": [{"name": "web"}],
                "service_instances_errors": {"web": "timeout"},
            },
            "service details unavailable err=timeout",
        ),
        ({"agents_list_requested": True, "agents_list": [], "agent_dump_name": "absent"}, "<agent not found>"),
        ({"agents_list_requested": True, "agents_list": [None, {}, {"name": "member"}]}, " member"),
        ({"agents_list_requested": True}, "[-] agents unavailable"),
        ({"agents_list_requested": True, "agents_list_error": "Forbidden"}, "agents unavailable err=Forbidden"),
        ({"nodes_list_requested": True, "nodes_list": [], "node_dump_name": "absent"}, "<node not found>"),
        ({"nodes_list_requested": True, "nodes_list": [None, {}, {"name": "node"}]}, " node"),
        ({"nodes_list_requested": True}, "[-] nodes unavailable"),
        ({"nodes_list_requested": True, "nodes_list_error": "Forbidden"}, "nodes unavailable err=Forbidden"),
        ({"checks_list_requested": True, "checks_list": [], "check_dump_id": "absent"}, "<check not found>"),
        (
            {
                "checks_list_requested": True,
                "checks_list": [
                    None,
                    {},
                    {"check_id": "c", "name": "health", "status": "passing", "service_id": "web"},
                ],
            },
            "c (status:passing) (service:web) (name:health)",
        ),
        ({"checks_list_requested": True}, "[-] checks unavailable"),
        ({"checks_list_requested": True, "checks_list_error": "Forbidden"}, "checks unavailable err=Forbidden"),
        (
            {"ssrf_results": [{"registered": False, "register_error": "Forbidden", "poll_error": "timeout"}]},
            "probe failed err=timeout",
        ),
        ({"script_revshell": {"registered": False, "register_status": 403}}, "check register failed err=status=403"),
        (
            {"script_revshell": {"action": "delete", "target_check_id": "absent", "queried": True, "items": []}},
            "<check not found>",
        ),
        ({"script_revshell": {"action": "delete", "queried": True, "items": []}}, "<no revshell checks>"),
        (
            {
                "script_revshell": {
                    "action": "delete",
                    "queried": True,
                    "items": [None, {"check_id": "c", "status": 503}],
                }
            },
            "check deregister failed id=c err=status=503",
        ),
    ],
)
def test_detail_output_distinguishes_empty_missing_denied_and_partial(changes: dict[str, Any], expected: str) -> None:
    record = {"host": "h", "port": 8500, "is_consul": True, **changes}
    lines = consul._detail_lines(record, "txt")
    assert any(expected in line for line in lines)
    assert all("\x1b" not in line for line in lines)
    assert consul._detail_lines(record, "json") == []


def test_service_dump_preserves_nested_definition_and_ignores_malformed_siblings() -> None:
    instance = {
        "node_name": "n",
        "service_id": "web-1",
        "meta": {"": "skip", "redposture_args": "--safe", "owner": "qa"},
        "checks": [
            None,
            {
                "check_id": "c",
                "name": "ready",
                "status": "passing",
                "script": "true",
                "args": ["sh", "-c", "true"],
                "notes": "line\nnotes",
                "definition_raw": '{"TTL":"1m"}',
                "output": "is\nready",
            },
        ],
    }
    record = {
        "is_consul": True,
        "host": "h",
        "port": 8500,
        "services_list_requested": True,
        "dump_requested": True,
        "services_list": [{"name": "web"}],
        "service_instances": {"web": [None, instance, {"service_id": "web-2"}]},
    }
    text = "\n".join(consul._detail_lines(record, "txt"))
    for expected in (
        "args=--safe",
        "meta.owner=qa",
        "arg[2]=true",
        "notes=line notes",
        'definition={"TTL":"1m"}',
        "output=is ready",
        "<no checks>",
    ):
        assert expected in text
    assert "\x1b" not in text


@pytest.mark.parametrize("deregistration", [(204, None), (503, None), (0, "cleanup timeout")])
def test_ssrf_poll_continues_after_unavailable_checks_and_always_cleans_up(
    monkeypatch: pytest.MonkeyPatch, deregistration: tuple[int, str | None]
) -> None:
    registered: dict[str, Any] = {}

    def register(*args: Any, **kwargs: Any) -> tuple[int, None, None]:
        registered.update(args[4])
        return 204, None, None

    replies = iter(["error", "invalid", "missing", "initial", "complete"])

    def checks(*args: Any, **kwargs: Any) -> Any:
        phase = next(replies)
        if phase == "error":
            return 503, None, "poll timeout"
        if phase == "invalid":
            return 200, [], None
        if phase == "missing":
            return 200, {registered["ID"]: None}, None
        return (
            200,
            {registered["ID"]: {"Status": "critical", "Output": "" if phase == "initial" else " connection refused "}},
            None,
        )

    monkeypatch.setattr(consul, "_consul_put_json", register)
    monkeypatch.setattr(consul, "_consul_get_checks", checks)
    delete = Mock(return_value=deregistration)
    monkeypatch.setattr(consul, "_consul_put_no_body", delete)
    monkeypatch.setattr(consul.time, "sleep", Mock())
    monkeypatch.setattr(consul.time, "monotonic", Mock(return_value=0))
    result = consul._consul_ssrf_probe(
        "h", 8500, 1, scheme="http", insecure=False, headers=None, target_url="http://127.0.0.1:1/"
    )
    assert result["registered"] is True and result["output"] == "connection refused"
    assert result["status"] == "critical"
    assert registered["HTTP"] == "http://127.0.0.1:1/"
    assert delete.call_args.args[2].endswith(registered["ID"])
    if deregistration == (204, None):
        assert result["deregistered"] is True
    else:
        assert result["deregister_error"] == (deregistration[1] or "status=503")


def test_ssrf_poll_exception_still_deregisters_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consul, "_consul_put_json", Mock(return_value=(204, None, None)))
    monkeypatch.setattr(consul, "_consul_get_checks", Mock(side_effect=RuntimeError("interrupted")))
    delete = Mock(return_value=(204, None))
    monkeypatch.setattr(consul, "_consul_put_no_body", delete)
    monkeypatch.setattr(consul.time, "sleep", Mock())
    monkeypatch.setattr(consul.time, "monotonic", Mock(return_value=0))
    with pytest.raises(RuntimeError, match="interrupted"):
        consul._consul_ssrf_probe(
            "h", 8500, 1, scheme="http", insecure=False, headers=None, target_url="http://127.0.0.1:1/"
        )
    delete.assert_called_once()


@pytest.mark.parametrize("response", [(0, None, "offline"), (403, None, None)])
def test_ssrf_registration_failure_never_polls_or_deletes(monkeypatch: pytest.MonkeyPatch, response: Any) -> None:
    monkeypatch.setattr(consul, "_consul_put_json", Mock(return_value=response))
    checks = Mock(side_effect=AssertionError("no registered check"))
    monkeypatch.setattr(consul, "_consul_get_checks", checks)
    result = consul._consul_ssrf_probe(
        "h", 8500, 1, scheme="http", insecure=False, headers=None, target_url="http://127.0.0.1:1/"
    )
    assert result["registered"] is False
    assert result["register_error"] == (response[2] or "status=403")


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ((0, b"", {}, "offline", False, False), (0, None, "offline")),
        ((204, b"", {}, None, False, False), (204, None, None)),
        ((400, b'{"error":"invalid"}', {}, None, False, False), (400, {"error": "invalid"}, None)),
        ((403, b"permission denied", {}, None, False, False), (403, "permission denied", None)),
    ],
)
def test_consul_json_write_preserves_structured_and_text_errors(
    monkeypatch: pytest.MonkeyPatch, response: Any, expected: Any
) -> None:
    request = Mock(return_value=response)
    monkeypatch.setattr(consul, "_request_with_tls_fallback", request)
    assert (
        consul._consul_put_json(
            "h", 8501, "/endpoint", 1, {"Name": "name"}, scheme="https", insecure=True, headers={"X-Consul-Token": "t"}
        )
        == expected
    )
    assert request.call_args.kwargs["headers"] == {"Content-Type": "application/json", "X-Consul-Token": "t"}
    assert request.call_args.kwargs["use_https"] is True


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ((0, b"", {}, "timeout", False, False), (0, "timeout")),
        ((204, b"", {}, None, False, False), (204, None)),
        ((403, b" permission denied ", {}, None, False, False), (403, "permission denied")),
        ((503, b"", {}, None, False, False), (503, "unexpected status=503")),
    ],
)
def test_consul_bodyless_write_preserves_denial_reason(
    monkeypatch: pytest.MonkeyPatch, response: Any, expected: Any
) -> None:
    monkeypatch.setattr(consul, "_request_with_tls_fallback", Mock(return_value=response))
    assert consul._consul_put_no_body("h", 8500, "/endpoint", 1, scheme="http", insecure=False) == expected


@pytest.mark.parametrize("placement", ["direct", "metadata", "definition", "definition_metadata"])
def test_agent_checks_preserve_enterprise_scope_from_supported_shapes(placement: str) -> None:
    scope = {"Namespace": "payments", "Partition": "edge"}
    fields = (
        scope
        if placement == "direct"
        else {"EnterpriseMeta": scope}
        if placement == "metadata"
        else {"Definition": scope}
        if placement == "definition"
        else {"Definition": {"EnterpriseMeta": scope}}
    )
    rows = consul._consul_agent_checks_list({"c": {"Name": "ready", **fields}, "invalid": None})
    assert len(rows) == 1
    assert rows[0]["namespace"] == "payments" and rows[0]["partition"] == "edge"
