"""PVE metadata reads do not imply access to selected VM configurations."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.modules.proxmox import actions
from redposture_core.scheduler import NestedSchedulerCancelled


def run(monkeypatch, *, denied=False, cancelled=False):
    calls = []
    scheduler = SimpleNamespace(cancelled=False)

    def request(host, port, path, *args, **kwargs):
        calls.append(path)
        value: Any = []
        if path == "/nodes":
            value = [{"node": "qa"}]
        elif path == "/nodes/qa/qemu":
            value = [{"vmid": 100}, {"vmid": 101}]
        elif path.endswith("/config"):
            value = {"password": "inactive-" + path.split("/")[-2] + "!42"}
            if denied:
                return 403, b'{"data":null}', {}, None
            if cancelled:
                scheduler.cancelled = True
        return 200, json.dumps({"data": value}).encode(), {}, None

    monkeypatch.setattr(actions, "_proxmox_request", request)
    # Serial facade preserves exactly the production nested cancellation signal.
    if cancelled:

        class Scheduler:
            @property
            def cancelled(self):
                return scheduler.cancelled

            def iter_completed(self, items, worker, **kwargs):
                for item in items:
                    yield item, worker(item)

        nested = Scheduler()
    else:
        nested = None
    kwargs = dict(
        discover_creds=True,
        _discover_time=30,
        _nested_scheduler=nested,
        _resolved_auth=({}, "pveapitoken", None, None, []),
    )
    if cancelled:
        with pytest.raises(NestedSchedulerCancelled):
            actions._audit_proxmox_host("qa", 8006, 1, 0, "", False, True, None, **kwargs)
        assert calls.count("/nodes/qa/qemu/100/config") == 1
        assert "/nodes/qa/qemu/101/config" not in calls
        return None
    return actions._audit_proxmox_host("qa", 8006, 1, 0, "", False, True, None, **kwargs)


@pytest.mark.parametrize("denied", [False, True])
def test_selected_vm_catalog_and_configurations_have_independent_acl(monkeypatch, denied):
    result = run(monkeypatch, denied=denied)
    rows = {r["id"]: r for r in result["discover_sources"]}
    assert rows["proxmox.qemu_catalog"]["read"] == 1 and rows["proxmox.qemu_catalog"]["complete"]
    c = rows["proxmox.qemu_configs"]
    assert c["requested"] == 2 and c["read"] == (0 if denied else 2)
    assert c["denied"] == (2 if denied else 0) and c["complete"] == (not denied)
    assert rows["proxmox.lxc_configs"]["requested"] == 0
    assert result["partial"] == denied


def test_cancel_stops_next_config_request_and_repeat_is_fresh(monkeypatch):
    run(monkeypatch, cancelled=True)
    for _ in range(2):
        result = run(monkeypatch)
        assert not result["partial"]
        assert {f["sample"] for f in result["findings"]} == {"inactive-100!42", "inactive-101!42"}
