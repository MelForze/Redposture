"""Large PVE responses preserve navigation and complete values incrementally."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path

from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.proxmox.discovery import stream_proxmox_response


class Pool:
    def __init__(self, body: bytes, status=200):
        self.body = body
        self.status = status

    def request_stream(self, method, url, *, on_chunk, on_response, **kwargs):
        on_response(self.status, {})
        for offset in range(0, len(self.body), 113):
            on_chunk(self.body[offset : offset + 113])
        return HttpResponse(status=self.status, body=b"", headers={})


def read(body, endpoint="/nodes", **kwargs):
    return stream_proxmox_response(
        Pool(body, kwargs.pop("status", 200)),
        "http://qa/api2/json" + endpoint,
        endpoint,
        headers={},
        timeout=1,
        deadline=time.monotonic() + 30,
        **kwargs,
    )


def test_large_catalog_retains_all_late_navigation_ids_on_disk():
    body = json.dumps({"data": [{"vmid": index, "name": "ordinary"} for index in range(12_000)]}).encode()
    status, payload, headers, error = read(body, "/nodes/pve/qemu")
    assert status == 200 and error is None
    assert len(payload.ids("vmid")) == 12_000
    assert payload.ids("vmid")[-1] == "11999"
    assert not payload.findings
    assert "x-redposture-discovery-error" not in headers


def test_large_config_keeps_full_secret_and_skips_public_digest():
    value = "full-" + "aB3q" * 80_000 + "λ-tail"
    body = json.dumps({"data": {"digest": "a" * 40, "api_token": value}}).encode()
    emitted = []
    status, payload, headers, error = read(body, "/nodes/pve/qemu/100/config", on_finding=emitted.append)
    assert status == 200 and error is None
    assert len(payload.findings) == len(emitted) == 1
    found = payload.findings[0]
    from redposture_core.modules.proxmox.discovery import finding_type

    assert finding_type(found["reason"]) == "generic_secret"
    assert isinstance(found["sample"], DiskBackedText)
    assert found["sample"].digest == hashlib.sha256(value.encode()).hexdigest()
    assert found["path"].endswith("api_token")
    assert "x-redposture-discovery-error" not in headers


def test_broken_tail_keeps_completed_finding_and_navigation():
    body = b'{"data":[{"node":"pve","password":"real-password"},'
    status, payload, headers, error = read(body)
    assert status == 200 and error is None
    assert list(payload.ids("node")) == ["pve"]
    assert payload.findings[0]["sample"] == "real-password"
    assert "invalid_json" in headers["x-redposture-discovery-error"]


def test_denied_response_is_not_scanned_as_content():
    _status, payload, headers, _error = read(b'{"data":{"password":"not-readable"}}', status=403)
    assert not payload.findings
    assert headers["x-redposture-discovery-error"] == "access_denied"


def test_plain_report_preserves_legacy_uri_and_assignment_findings():
    body = (
        b"backup_url=https://backupsvc:BackupSvc!2026@pbs.lab.internal:8007/api2/json\n"
        b"ceph_mon_secret=ceph-mon-secret-lab-2026\n"
    )
    status, payload, headers, error = read(body, "/nodes/pve-edge-01/report")
    assert status == 200 and error is None
    reasons = {item["reason"] for item in payload.findings}
    assert "connection_string" in reasons
    assert any(
        item["sample"] == "https://backupsvc:BackupSvc!2026@pbs.lab.internal:8007/api2/json"
        for item in payload.findings
    )
    assert "generic_secret" in reasons
    assert any(item["sample"] == "ceph-mon-secret-lab-2026" for item in payload.findings)
    assert "x-redposture-discovery-error" not in headers


def test_json_wrapped_report_preserves_uri_and_assignment_findings():
    report = (
        "backup_url=https://backupsvc:BackupSvc!2026@pbs.lab.internal:8007/api2/json\n"
        "ceph_mon_secret=ceph-mon-secret-lab-2026\n"
    )
    status, payload, headers, error = read(json.dumps({"data": report}).encode(), "/nodes/pve-edge-01/report")
    assert status == 200 and error is None
    reasons = {item["reason"] for item in payload.findings}
    assert "connection_string" in reasons
    assert any(
        item["sample"] == "https://backupsvc:BackupSvc!2026@pbs.lab.internal:8007/api2/json"
        for item in payload.findings
    )
    assert "generic_secret" in reasons
    assert any(item["sample"] == "ceph-mon-secret-lab-2026" for item in payload.findings)
    assert "x-redposture-discovery-error" not in headers


def test_large_report_does_not_promote_unlabelled_certificate_body_to_secret():
    certificate_text = base64.b64encode(b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(20))).decode()
    report = (
        "system status\n"
        + "ordinary note\n" * 7000
        + "-----BEGIN CERTIFICATE-----\n"
        + certificate_text
        + "\n-----END CERTIFICATE-----\n"
        + "API_TOKEN=qa-proxmox-report-token\n"
    )
    status, payload, headers, error = read(json.dumps({"data": report}).encode(), "/nodes/pve-edge-01/report")
    assert status == 200 and error is None
    assert "x-redposture-discovery-error" not in headers
    assert any(
        item["reason"] == "generic_secret" and item["sample"] == "qa-proxmox-report-token" for item in payload.findings
    )
    assert not any(item["reason"] == "high_entropy" for item in payload.findings)


def test_report_unlabelled_machine_id_is_not_a_credential():
    report = "Machine-ID: " + "8d" * 16 + "\n"
    status, payload, headers, error = read(json.dumps({"data": report}).encode(), "/nodes/pve-edge-01/report")
    assert status == 200 and error is None
    assert "x-redposture-discovery-error" not in headers
    assert not payload.findings


def test_report_labelled_hex_and_prefixed_token_remain_findings():
    report = "api_token=" + "8d" * 16 + "\nglpat-" + "A7b9" * 6 + "\n"
    status, payload, headers, error = read(json.dumps({"data": report}).encode(), "/nodes/pve-edge-01/report")
    assert status == 200 and error is None
    assert "x-redposture-discovery-error" not in headers
    assert any(item["sample"] == "8d" * 16 for item in payload.findings)
    assert any(item["sample"] == "glpat-" + "A7b9" * 6 for item in payload.findings)


def test_small_json_wrapped_report_preserves_findings_in_regular_reader():
    from redposture_core.modules.proxmox.actions import _scan_endpoint_payload

    report = "backup_url=https://backupsvc:BackupSvc!2026@pbs.lab.internal:8007/api2/json\n"
    findings = []
    _scan_endpoint_payload(
        "/nodes/pve-edge-01/report",
        json.dumps({"data": report}).encode(),
        findings,
        set(),
    )
    assert len(findings) == 1
    assert (
        findings[0]["reason"] == "connection_string"
        and findings[0]["sample"] == "https://backupsvc:BackupSvc!2026@pbs.lab.internal:8007/api2/json"
    )


def test_long_finding_file_output_uses_airflow_finding_palette(capsys):
    from redposture_core.stage_runtime import LineOutputSink

    class Console:
        def __init__(self):
            self.calls = []

        def _paint(self, text, color, stream):
            self.calls.append((text, color))
            return text

    console = Console()
    sink = LineOutputSink(None, print, console=console)
    sink.emit_text_chunks(('PROXMOX\tqa\t8006\t [!] Token Value="', "full-value", '" Place="$.config"'))
    assert ("[!]", "true_red") in console.calls
    assert ("full-value", "orange") in console.calls
    assert "\x1b[" not in capsys.readouterr().out


def test_audit_continues_large_catalogs_and_reads_late_vm_config(monkeypatch):
    from redposture_core.modules.proxmox import actions

    value = "secret-" + "q" * 400_000 + "-tail"
    large = {
        "/nodes": json.dumps({"data": [{"node": "pve", "notes": "ordinary " * 40_000}]}).encode(),
        "/nodes/pve/qemu": json.dumps({"data": [{"vmid": 100, "notes": "ordinary " * 40_000}, {"vmid": 900}]}).encode(),
        "/nodes/pve/qemu/900/config": json.dumps({"data": {"api_token": value}}).encode(),
    }
    paths = []

    def request(host, port, path, timeout, retries, **kwargs):
        paths.append(path)
        if path in large:
            return 200, large[path][:262144], {"x-redposture-truncated": "true"}, None
        return 200, b'{"data":[]}', {}, None

    class Responses:
        def request_stream(self, method, url, **kwargs):
            path = url.split("/api2/json", 1)[1]
            return Pool(large[path]).request_stream(method, url, **kwargs)

    monkeypatch.setattr(actions, "_proxmox_request", request)
    result = actions._audit_proxmox_host(
        "qa",
        8006,
        1,
        0,
        "qa@pve!qa=token",
        False,
        True,
        None,
        discover_creds=True,
        _discover_time=30,
        _discover_max_bytes=None,
        _resolved_auth=({"Authorization": "PVEAPIToken=qa"}, "pveapitoken", None, None, []),
        _transport_pool=Responses(),
    )
    assert result["partial"] is False, result.get("partial_error")
    assert "/nodes/pve/qemu/900/config" in paths
    assert len(result["findings"]) == 1
    assert result["findings"][0]["sample"].digest == hashlib.sha256(value.encode()).hexdigest()
    assert result["responses_truncated"] == 0
    from redposture_core.modules.proxmox.discovery import write_proxmox_views

    path = Path(write_proxmox_views(result))
    try:
        text = path.read_text()
        assert value in text and "DiskBackedText object" not in text
        assert "\x1b[" not in text
    finally:
        path.unlink()
