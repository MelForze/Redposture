"""Proxmox scoped denials retain independent inventory and verified capabilities."""

from __future__ import annotations

import json
from typing import Any

import pytest

from redposture_core.modules.proxmox import actions as proxmox


def test_proxmox_denied_access_root_keeps_independent_users_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = []

    def request(host: str, port: int, path: str, *args: Any, **kwargs: Any) -> Any:
        paths.append(path)
        if path == "/access":
            return (
                403,
                b'{"data":null,"errors":{"perm":"Permission check failed"}}',
                {"server": "pve-api-daemon/3.0"},
                None,
            )
        if path.startswith("/access/permissions"):
            return 200, b'{"data":{"/":{"Sys.Audit":1,"VM.Audit":1}}}', {}, None
        assert path == "/access/users"
        return 200, b'{"data":[{"userid":"read-only@pve"}]}', {}, None

    monkeypatch.setattr(proxmox, "_proxmox_request", request)
    result = proxmox._audit_proxmox_host("qa", 8006, 1, 0, "token", True, True, None, show_users=True)
    assert result["is_proxmox"] is True and result["status"] == "insufficient_privileges"
    assert result["users"] == ["read-only@pve"] and result["users_error"] is None
    assert result["cap_read"] is True and result["cap_adduser"] is False
    assert paths == ["/access", "/access/permissions?path=/", "/access/users"]


@pytest.mark.parametrize(
    "fault", ["permission_transport", "permission_status", "users_transport", "users_status", "nodes_status"]
)
def test_proxmox_independent_inventory_faults_do_not_erase_access_success(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    paths = []

    def request(host: str, port: int, path: str, *args: Any, **kwargs: Any) -> Any:
        paths.append(path)
        if path == "/access":
            return 200, b'{"data":[]}', {}, None
        surface = (
            "permission" if path.startswith("/access/permissions") else "users" if path == "/access/users" else "nodes"
        )
        if fault == surface + "_transport":
            return 0, b"", {}, "reset"
        if fault == surface + "_status":
            return 503, b"{}", {}, None
        data: Any = (
            {"/": {"Sys.Audit": 1}}
            if surface == "permission"
            else [{"userid": "alice@pve"}]
            if surface == "users"
            else [{"node": "pve-a"}]
        )
        return 200, json.dumps({"data": data}).encode(), {}, None

    monkeypatch.setattr(proxmox, "_proxmox_request", request)
    result = proxmox._audit_proxmox_host("qa", 8006, 1, 0, "token", True, True, None, show_users=True, show_nodes=True)
    assert result["is_proxmox"] is True and result["status"] == "token_ok"
    assert result["cap_read"] is (None if fault.startswith("permission") else True)
    if fault.startswith("users"):
        assert result["users"] is None and result["users_error"]
    else:
        assert result["users"] == ["alice@pve"] and result["users_error"] is None
    if fault == "nodes_status":
        assert result["nodes"] == [] and result["nodes_error"] == "unexpected HTTP 503 from /nodes"
    else:
        assert result["nodes"] == ["pve-a"] and result["nodes_error"] is None
    assert paths == ["/access", "/access/permissions?path=/", "/access/users", "/nodes"]
