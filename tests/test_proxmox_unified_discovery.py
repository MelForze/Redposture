"""PVE is a source adapter, with the same extracted Value policy as Elastic."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.proxmox.actions import _scan_endpoint_payload
from redposture_core.modules.proxmox.discovery import stream_proxmox_response


def text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


def scan(endpoint, document, streamed):
    body = json.dumps({"data": document}).encode()
    if not streamed:
        findings = []
        assert _scan_endpoint_payload(endpoint, body, findings, set())
        return findings

    class Pool:
        def request_stream(self, _method, _url, *, on_response, on_chunk, **kwargs):
            on_response(200, {})
            for i in range(0, len(body), 37):
                on_chunk(body[i : i + 37])
            return HttpResponse(200, b"", {})

    _, payload, headers, error = stream_proxmox_response(
        Pool(),
        "http://qa/api2/json" + endpoint,
        endpoint,
        headers={},
        timeout=1,
        deadline=time.monotonic() + 30,
    )
    assert error is None and "x-redposture-discovery-error" not in headers
    return payload.findings


@pytest.mark.parametrize("streamed", [False, True])
@pytest.mark.parametrize("size", [20, 100_000])
def test_pve_cipassword_alias_keeps_full_value_and_not_its_metadata(streamed, size):
    secret = "GitLabCloudInit!2026" + "Ab0_" * (size // 4)
    rows = scan("/nodes/pve/qemu/101/config", {"cipassword": secret, "cipassword_count": "not-a-password"}, streamed)
    assert [(r["reason"], text(r["sample"]), text(r["path"])) for r in rows] == [("password", secret, "$.cipassword")]


@pytest.mark.parametrize("streamed", [False, True])
@pytest.mark.parametrize("endpoint", ["/access", "/access/ticket", "/nodes/pve/qemu/101/config"])
def test_pve_auth_protocol_csrf_is_not_a_stored_config_secret(streamed, endpoint):
    rows = scan(endpoint, {"CSRFPreventionToken": "mock-csrf-token", "password": "stored-password"}, streamed)
    expected = {"stored-password"} if endpoint.startswith("/access") else {"stored-password", "mock-csrf-token"}
    assert {text(r["sample"]) for r in rows} == expected


@pytest.mark.parametrize("streamed", [False, True])
def test_pve_uses_shared_extracted_passwords_and_semantic_context(streamed):
    findings: list[dict[str, Any]]
    body = json.dumps(
        {
            "data": {
                "database_url": "postgres://qa:uri%40password@db.invalid/app",
                "authorization": "Basic " + base64.b64encode(b"qa:basic-password").decode(),
                "setting": {"name": "password", "value": "context-password"},
            }
        }
    ).encode()
    if streamed:

        class Pool:
            def request_stream(self, _method, _url, *, on_response, on_chunk, **_kwargs):
                on_response(200, {})
                for i in range(0, len(body), 13):
                    on_chunk(body[i : i + 13])
                return HttpResponse(200, b"", {})

        _, payload, headers, error = stream_proxmox_response(
            Pool(),
            "http://qa/api2/json/nodes/pve/config",
            "/nodes/pve/config",
            headers={},
            timeout=1,
            deadline=time.monotonic() + 30,
        )
        assert error is None and "x-redposture-discovery-error" not in headers
        findings = payload.findings
    else:
        findings = []
        _scan_endpoint_payload("/nodes/pve/config", body, findings, set())
    assert {text(row["sample"]) for row in findings} == {
        "postgres://qa:uri%40password@db.invalid/app",
        "Basic " + base64.b64encode(b"qa:basic-password").decode(),
        "context-password",
    }


def test_pve_all_locations_survive_merging_source_catalogs_and_live_output():
    from redposture_core.discovery_rendering import iter_discovery_location_lines
    from redposture_core.modules.proxmox.discovery import ProxmoxFindings

    incoming = ProxmoxFindings()
    for i in range(150):
        incoming.append(
            {
                "endpoint": "/nodes/pve/config",
                "reason": "password",
                "path": f"$[{i}].password",
                "sample": "same-password",
            }
        )
    incoming.finish()
    target = ProxmoxFindings()
    target.append(dict(incoming[0]))
    published = list(target.iter_appended(0))
    assert len(published) == 1
    target.append(
        {"endpoint": "/nodes/pve/report", "reason": "password", "path": "$.password", "sample": "same-password"}
    )
    target.append(
        {"endpoint": "/nodes/pve/report", "reason": "password", "path": "$.other", "sample": "other-password"}
    )
    assert len(list(target.iter_appended(1))) == 1
    assert len(target) == 2
    target.finish()
    first = target[0]
    assert first["occurrence_count"] == 151
    assert len(first["locations"]) == 151
    assert first["sample"] == "same-password"
    lines = ["".join(chunks) for chunks in iter_discovery_location_lines("proxmox", "qa", 8006, {"findings": target})]
    assert len(lines) == 151 and all("ValueSHA256=" in line and "\x1b" not in line for line in lines)


def test_pve_disk_failure_keeps_completed_values_and_cleans_pending_context(monkeypatch):
    from redposture_core.modules.proxmox.discovery import ProxmoxFindings

    original = ProxmoxFindings.add

    def add(self, finding, **kwargs):
        if finding.get("sample") == "fault-password":
            raise OSError("qa disk full")
        return original(self, finding, **kwargs)

    monkeypatch.setattr(ProxmoxFindings, "add", add)

    class Pool:
        def request_stream(self, _method, _url, *, on_response, on_chunk, **kwargs):
            on_response(200, {})
            on_chunk(
                b'{"data":{"password":"completed-password","setting":{"name":"password","value":"fault-password"}}}'
            )
            return HttpResponse(200, b"", {})

    _, payload, headers, _error = stream_proxmox_response(
        Pool(), "http://qa/api2/json/nodes", "/nodes", headers={}, timeout=1, deadline=time.monotonic() + 10
    )
    assert [r["sample"] for r in payload.findings] == ["completed-password"]
    assert "storage_failure" in headers["x-redposture-discovery-error"]
