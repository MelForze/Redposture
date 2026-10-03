"""Proxmox discovery evidence survives malformed records and duplicate paths."""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.modules.proxmox import actions


@given(
    st.lists(st.text(alphabet="abc123_-", min_size=1, max_size=8), unique=True, max_size=20),
    st.booleans(),
)
def test_proxmox_discovery_urls_include_each_finding_once_and_remain_read_only(names: list[str], https: bool) -> None:
    findings = [
        {"endpoint": f"/nodes/{name}/config", "reason": "json_password", "path": "$.password", "sample": "secret"}
        for name in names
    ]
    endpoints = [{"path": finding["endpoint"], "status": 200} for finding in findings]
    record = {
        "host": "127.0.0.1",
        "port": 8006,
        "discover_creds": True,
        "use_https": https,
        "findings": findings,
        "endpoint_results": endpoints + endpoints + [{"path": "invalid", "status": 200}],
    }
    lines = actions._format_discovered_urls_detail_records(record, "txt")
    for name in names:
        url = f"{'https' if https else 'http'}://127.0.0.1:8006/api2/json/nodes/{name}/config"
        assert sum(url in line for line in lines) == 1
    assert len([line for line in lines if "Value=" in line]) == len(names)
    assert actions._format_discovered_urls_detail_records(record, "json") == []
    assert actions._credential_finding_endpoints(record) == {finding["endpoint"] for finding in findings}


@given(st.text(alphabet="abc123_-", min_size=8, max_size=30), st.sampled_from(("password", "api_key", "token")))
def test_proxmox_secret_scanner_marks_only_sensitive_json_values(value: str, key: str) -> None:
    findings: list[dict[str, str]] = []
    actions._scan_endpoint_payload(
        "/nodes/pve/config", json.dumps({key: value, "version": value}).encode(), findings, set()
    )
    assert any(finding["sample"] == value and finding["path"].endswith(key) for finding in findings)
    assert all(not finding["path"].endswith("version") for finding in findings)


@pytest.mark.parametrize(
    ("reason", "kind"),
    [
        ("json_password", "Pass"),
        ("api_token", "Token"),
        ("api_key", "ApiKey"),
        ("private_key", "Key"),
        ("credential", "Credentials"),
    ],
)
def test_proxmox_compact_finding_type_is_stable(reason: str, kind: str) -> None:
    line = actions._format_single_finding_detail_line(
        {"host": "127.0.0.1", "port": 8006},
        {"reason": reason, "endpoint": "/nodes/pve/config", "path": "$.secret", "sample": "secret123"},
    )
    assert f"[!] {kind} Value=" in line
    assert "Place=" in line


def test_proxmox_discovery_handles_malformed_rows_without_fabricating_urls() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8006,
        "discover_creds": True,
        "findings": [None, {}, {"endpoint": "relative/path"}],
        "endpoint_results": [None, {}, {"path": "relative/path", "status": 200}],
    }
    lines = actions._format_discovered_urls_detail_records(record, "txt")
    assert any("<none>" in line for line in lines)
    assert actions._credential_finding_endpoints(record) == set()
    assert actions._credential_finding_endpoints({"findings": "not-a-list"}) == set()


@pytest.mark.parametrize("users", [None, [], ["root@pam", "auditor@pve"]])
def test_proxmox_users_dump_matches_json_and_txt_scope(users: list[str] | None) -> None:
    record = {"host": "127.0.0.1", "port": 8006, "show_users": True, "users": users}
    txt = actions._format_users_detail_records(record, "txt")
    data = json.loads(actions._format_users_detail_records(record, "json")[0])
    assert data["users"] == (users or [])
    if users:
        assert all(any(user in line for line in txt) for user in users)
    else:
        assert any("<no users>" in line for line in txt)
