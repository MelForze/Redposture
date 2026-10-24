"""Consul identity, selected data, and fallback contracts without live services."""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core.modules.consul import actions as consul


@pytest.mark.parametrize(
    ("status", "payload", "error", "verdict", "message"),
    [
        (200, {"AccessorID": " id ", "Description": 8, "Local": "true"}, None, True, None),
        (200, {"SecretID": "secret"}, None, None, "unexpected token identity response"),
        (200, [], None, None, "unexpected status=200"),
        (401, "proxy", None, False, "Unauthorized"),
        (403, " Token does not exist: ACL not found ", None, False, "Consul ACL token not found"),
        (403, {"error": "Token does not exist: ACL not found"}, None, None, "Forbidden"),
        (403, "proxy forbidden", None, None, "Forbidden"),
        (502, "bad gateway", None, None, "unexpected status=502"),
        (0, None, "connection timeout", None, "connection timeout"),
    ],
)
def test_token_identity_never_infers_validity_from_inventory(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    payload: Any,
    error: str | None,
    verdict: bool | None,
    message: str | None,
) -> None:
    request = Mock(return_value=(status, payload, error, True, False))
    monkeypatch.setattr(consul, "_consul_get_json_any", request)
    result = consul._acl_token_self_probe("h", 8501, 1, scheme="https", insecure=True, headers={"X-Consul-Token": "t"})
    assert result["ok"] is verdict
    assert result["error"] == message
    assert result["insecure_effective"] is True
    assert request.call_args.args[2] == "/v1/acl/token/self"
    if verdict is True:
        assert result["accessor_id"] == "id"
        assert result["description"] is None and result["local"] is None


def test_auth_cache_changes_identity_without_discarding_anonymous_evidence() -> None:
    state = consul.ConsulLifecycleState(
        anonymous_self={"ok": True},
        anonymous_scopes={"kv": {"ok": True}},
        auth_headers={"X-Consul-Token": "old"},
        auth_self={"ok": True},
        auth_scopes={"kv": {"ok": True}},
        auth_identity={"ok": True},
        deep_record={"kv_dump_items": ["old-secret"]},
    )
    new_headers = {"X-Consul-Token": "new"}
    consul._prepare_auth_cache(state, new_headers)
    new_headers["X-Consul-Token"] = "mutated"
    assert state.auth_headers == {"X-Consul-Token": "new"}
    assert (state.auth_self, state.auth_scopes, state.auth_identity, state.deep_record) == (None, None, None, None)
    assert state.anonymous_self == {"ok": True}
    assert state.anonymous_scopes == {"kv": {"ok": True}}
    state.deep_record = {"retained": True}
    consul._prepare_auth_cache(state, {"X-Consul-Token": "new"})
    assert state.deep_record == {"retained": True}


@pytest.mark.parametrize(
    ("status", "payload", "error", "expected"),
    [
        (0, None, "timeout", (None, "timeout")),
        (401, [], None, (None, "Unauthorized")),
        (403, [], None, (None, "Forbidden")),
        (500, [], None, (None, "status=500")),
        (200, {}, None, (None, "invalid kv keys response")),
        (200, ["z", "  A  ", "", "  "], None, (["A", "z"], None)),
    ],
)
def test_kv_inventory_preserves_unknown_denied_and_empty_states(
    monkeypatch: pytest.MonkeyPatch, status: int, payload: Any, error: str | None, expected: Any
) -> None:
    monkeypatch.setattr(consul, "_consul_get_json_any", Mock(return_value=(status, payload, error, False, False)))
    assert consul._consul_kv_keys_list("h", 8500, 1, scheme="http", insecure=False) == expected


def test_kv_dump_quotes_selector_and_ignores_malformed_siblings(monkeypatch: pytest.MonkeyPatch) -> None:
    request = Mock(
        return_value=(
            200,
            [
                None,
                {"Key": " "},
                {"Key": "z", "Value": None},
                {"Key": " A ", "Value": base64.b64encode(b"secret\n").decode(), "Flags": 4, "ModifyIndex": 9},
            ],
            None,
            False,
            False,
        )
    )
    monkeypatch.setattr(consul, "_consul_get_json_any", request)
    rows, error = consul._consul_kv_dump("h", 8500, 1, scheme="http", insecure=False, key_name="a/b?x &y")
    assert request.call_args.args[2] == "/v1/kv/a/b%3Fx%20%26y"
    assert error is None
    assert rows == [
        {"key": "A", "value": "secret", "flags": 4, "modify_index": 9},
        {"key": "z", "value": "", "flags": None, "modify_index": None},
    ]


@pytest.mark.parametrize("selected", [True, False])
def test_missing_kv_selector_is_empty_but_missing_tree_is_error(
    monkeypatch: pytest.MonkeyPatch, selected: bool
) -> None:
    monkeypatch.setattr(consul, "_consul_get_json_any", Mock(return_value=(404, None, None, False, False)))
    result = consul._consul_kv_dump(
        "h", 8500, 1, scheme="http", insecure=False, key_name="missing" if selected else None
    )
    assert result == (([], None) if selected else (None, "status=404"))


def _audit_options(**overrides: Any) -> dict[str, Any]:
    result: dict[str, Any] = dict(
        token="token",
        username=None,
        password=None,
        do_ssrf=False,
        ssrf_urls=[],
        show_keys=True,
        kv_key=None,
        dump_requested=True,
        dump_all_requested=True,
        show_services=True,
        show_agents=True,
        show_checks=True,
        check_dump_id=None,
        show_nodes=True,
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
        dump_limit=1,
    )
    result.update(overrides)
    return result


@pytest.mark.parametrize("selectors", [False, True])
def test_dump_falls_back_per_scope_and_filters_before_applying_limit(
    monkeypatch: pytest.MonkeyPatch, selectors: bool
) -> None:
    monkeypatch.setattr(consul, "_probe_consul_scheme", Mock(return_value=(True, "http", False, False, "leader", None)))
    monkeypatch.setattr(
        consul,
        "_consul_access_matrix",
        Mock(return_value={name: {"ok": True} for name in ("kv", "services", "agents")}),
    )
    monkeypatch.setattr(consul, "_agent_self_probe", Mock(return_value={"ok": True}))
    monkeypatch.setattr(consul, "_acl_token_self_probe", Mock(return_value={"ok": True}))
    calls: dict[str, list[Any]] = {}

    def fallback(name: str, rows: Any):
        def request(*_args: Any, **kwargs: Any):
            calls.setdefault(name, []).append(kwargs.get("headers"))
            if name == "_consul_kv_dump":
                assert kwargs.get("key_name") == ("b" if selectors else None)
                selected_rows = [row for row in rows if row["key"] == kwargs["key_name"]] if selectors else rows
            else:
                selected_rows = rows
            return (None, "auth endpoint denied") if kwargs.get("headers") else (selected_rows, None)

        return request

    for name, rows in (
        ("_consul_kv_dump", [{"key": "a"}, {"key": "b"}]),
        ("_consul_catalog_services_list", [{"name": "a"}, {"name": "b"}]),
        ("_consul_agent_members_list", [{"name": "a"}, {"name": "b"}]),
        ("_consul_catalog_nodes_list", [{"name": "a"}, {"name": "b"}]),
        ("_consul_health_service_instances", [{"service_id": "retained"}]),
    ):
        monkeypatch.setattr(consul, name, fallback(name, rows))

    def checks(*_args: Any, **kwargs: Any):
        calls.setdefault("checks", []).append(kwargs.get("headers"))
        return (403, None, "denied") if kwargs.get("headers") else (200, {"a": {"Name": "a"}, "b": {"Name": "b"}}, None)

    monkeypatch.setattr(consul, "_consul_get_checks", checks)
    selection = (
        dict(kv_key="b", service_dump_name="b", agent_dump_name="b", check_dump_id="b", node_dump_name="b")
        if selectors
        else {}
    )
    result = consul._audit_consul_host_core("h", 8500, 1, 0, **_audit_options(**selection))
    selected_name = "b" if selectors else "a"
    assert result["auth_valid"] is True
    assert result["kv_dump_error"] is None
    assert result["kv_dump_items"] == [{"key": selected_name}]
    for key in ("services", "agents", "nodes", "checks"):
        assert result[f"{key}_list_source"] == "anonymous"
        assert result[f"{key}_list_error"] is None
    for key in ("services", "agents", "nodes"):
        assert result[f"{key}_list"] == [{"name": selected_name}]
    assert [row["check_id"] for row in result["checks_list"]] == [selected_name]
    assert result["service_instances"] == {selected_name: [{"service_id": "retained"}]}
    assert result["service_instances_errors"] == {}
    for requests in calls.values():
        assert requests[0] == {"X-Consul-Token": "token"}
        assert requests[1] is None


def test_cleanup_retains_individual_errors_and_escapes_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        consul, "_consul_get_checks", Mock(return_value=(200, {"rp/a": {}, "other": {}, "rp/b": {}}, None))
    )
    delete = Mock(side_effect=[(204, None), (503, None)])
    monkeypatch.setattr(consul, "_consul_put_no_body", delete)
    result = consul._consul_script_revshell_cleanup(
        "h", 8500, 1, scheme="http", insecure=False, headers=None, check_id_prefix="rp/"
    )
    assert (result["matched"], result["deleted"]) == (2, 1)
    assert result["items"] == [
        {"check_id": "rp/a", "ok": True, "status": 204, "error": None},
        {"check_id": "rp/b", "ok": False, "status": 503, "error": "status=503"},
    ]
    assert [call.args[2] for call in delete.call_args_list] == [
        "/v1/agent/check/deregister/rp%2Fa",
        "/v1/agent/check/deregister/rp%2Fb",
    ]


@pytest.mark.parametrize("placement", ["direct", "enterprise", "definition", "definition_enterprise"])
def test_health_service_selects_related_checks_and_recovers_agent_definition(
    monkeypatch: pytest.MonkeyPatch, placement: str
) -> None:
    enterprise = {"Namespace": "payments", "Partition": "edge"}
    metadata: dict[str, Any] = (
        enterprise
        if placement == "direct"
        else {"EnterpriseMeta": enterprise}
        if placement == "enterprise"
        else {"Definition": enterprise}
        if placement == "definition"
        else {"Definition": {"EnterpriseMeta": enterprise}}
    )
    request = Mock(
        return_value=(
            200,
            [
                "malformed",
                {
                    "Node": {"Node": "node", "Address": "10.0.0.1"},
                    "Service": {"ID": "svc-1", "Port": "invalid", "ServiceAddress": "10.0.0.2", "Meta": {"count": 7}},
                    "Checks": [
                        None,
                        {"CheckID": "unrelated", "ServiceID": "other"},
                        {"CheckID": "service:svc-1", "Status": "passing", **metadata},
                    ],
                },
            ],
            None,
            False,
            False,
        )
    )
    monkeypatch.setattr(consul, "_consul_get_json_any", request)
    definition = {"Args": ["sh", "-c", "echo ok", ""], "HTTP": "http://health/", "Interval": "10s"}
    result, error = consul._consul_health_service_instances(
        "h",
        8500,
        "svc /?",
        1,
        scheme="http",
        insecure=False,
        agent_checks={"service:svc-1": {"Notes": "retained notes", "Definition": definition}},
    )
    assert error is None and result and len(result) == 1
    assert request.call_args.args[2] == "/v1/health/service/svc%20%2F%3F"
    instance = result[0]
    assert instance["service_port"] is None and instance["service_address"] == "10.0.0.2"
    assert instance["meta"] == {"count": "7"}
    assert len(instance["checks"]) == 1
    check = instance["checks"][0]
    assert check["namespace"] == "payments" and check["partition"] == "edge"
    assert check["args"] == ["sh", "-c", "echo ok"]
    assert check["http"] == "http://health/" and check["interval"] == "10s"
    assert check["notes"] == "retained notes"
    assert check["script"] == "<from args> sh -c 'echo ok'"


@pytest.mark.parametrize(
    ("status", "payload", "error", "expected"),
    [
        (0, None, "timeout", "timeout"),
        (401, [], None, "Unauthorized"),
        (403, [], None, "Forbidden"),
        (503, [], None, "status=503"),
        (200, {}, None, "invalid health service response"),
    ],
)
def test_service_health_errors_do_not_become_empty_success(
    monkeypatch: pytest.MonkeyPatch, status: int, payload: Any, error: str | None, expected: str
) -> None:
    monkeypatch.setattr(consul, "_consul_get_json_any", Mock(return_value=(status, payload, error, False, False)))
    assert consul._consul_health_service_instances("h", 8500, "service", 1, scheme="http", insecure=False) == (
        None,
        expected,
    )
