"""Workload env is authorized API content, never container execution."""

from __future__ import annotations

import base64
import time
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.discovery_sources import SourceManifest
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.kubeapi import actions
from redposture_core.modules.kubeapi.discover import WORKLOADS, scan_workload_env
from redposture_core.scheduler import NestedSchedulerCancelled
from redposture_core.storage_discovery import DiscoveryCollector


def workload(resource, spec_path, *, value="inactive-inline!42", group="containers"):
    spec: dict[str, Any] = {
        group: [
            {
                "name": "api",
                "env": [
                    {"name": "DB_PASSWORD", "value": value},
                    {"name": "password_count", "value": "42"},
                    {"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "secret-ref", "key": "password"}}},
                ],
                "envFrom": [{"secretRef": {"name": "secret-reference-metadata"}}],
            }
        ]
    }
    for part in reversed(spec_path):
        spec = {part: spec}
    return {
        **spec,
        "kind": resource,
        "metadata": {"name": "payment-api", "namespace": "qa", "uid": "stable-uid", "resourceVersion": "123"},
    }


def collector(**kwargs):
    return DiscoveryCollector(
        "kubeapi",
        SimpleNamespace(host="qa", port=6443, args=SimpleNamespace(discover_time=30), **kwargs),
        {"status": "auth_valid"},
    )


def test_cancelled_workload_source_is_incomplete_and_repeat_has_no_stale_values():
    def attempt(cancel):
        emitted = []
        c, m = collector(live_emit=emitted.extend, cancelled=lambda: cancel and bool(emitted)), SourceManifest()
        calls = []

        def get(base, sink):
            calls.append(base)
            resource, api, path = WORKLOADS[0]
            if base == api + "/namespaces/qa/" + resource:
                sink(workload(resource, path, value="inactive-first!42"))
                sink(workload(resource, path, value="inactive-second!42"))
            return actions.KubeListResult([], 200, None, True, True)

        if cancel:
            with pytest.raises(NestedSchedulerCancelled):
                scan_workload_env(c, namespaces=["qa"], list_items=get, manifest=m)
        else:
            scan_workload_env(c, namespaces=["qa"], list_items=get, manifest=m)
        return c.result(), m.result(), calls, emitted

    result, rows, calls, emitted = attempt(True)
    assert result["status"] == "partial" and not rows[0]["complete"]
    assert len(calls) == len(emitted) == 1
    assert [f["value"] for f in result["findings"]] == ["inactive-first!42"]
    for _ in range(2):
        result, rows, calls, emitted = attempt(False)
        assert result["status"] == "complete" and all(r["complete"] for r in rows)
        assert len(calls) == len(WORKLOADS) and len(emitted) == 2
        assert {f["value"] for f in result["findings"]} == {"inactive-first!42", "inactive-second!42"}


@pytest.mark.parametrize("resource,api,path", WORKLOADS)
@pytest.mark.parametrize("group", ["containers", "initContainers", "ephemeralContainers"])
def test_each_schema_and_container_group_preserves_identity_full_value_and_live_finding(resource, api, path, group):
    emitted = []
    c = collector(live_emit=emitted.extend)
    manifest = SourceManifest()
    calls = []

    def get(base, sink):
        calls.append(base)
        if base == api + "/namespaces/qa/" + resource:
            sink(workload(resource, path, group=group))
            assert emitted, "finding must be published before the next source"
        return actions.KubeListResult([], 200, None, True, True)

    scan_workload_env(c, namespaces=["qa", "qa"], list_items=get, manifest=manifest)
    result = c.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(calls) == len(WORKLOADS)
    assert all("/namespaces/qa/" in p for p in calls)
    assert [r["value"] for r in result["findings"]] == ["inactive-inline!42"]
    finding = result["findings"][0]
    assert finding["object_path"] == (
        f"$.workloads.{resource}.qa.payment-api." + ".".join(path) + f".{group}[0].env[0].value"
    )
    assert finding["locations"][0]["uid"] == "stable-uid"
    assert finding["locations"][0]["resource_version"] == "123"
    assert finding["locations"][0]["env"] == "DB_PASSWORD"
    rows = manifest.result()
    assert sum(row["read"] for row in rows) == 1
    assert all(row["complete"] and row["requested"] == 1 for row in rows)


@pytest.mark.parametrize("status", [401, 403, 404, 405, 429, 500])
def test_unread_or_denied_workloads_cannot_claim_complete(status):
    c, m = collector(), SourceManifest()
    scan_workload_env(
        c,
        namespaces=[],
        list_items=lambda *a: actions.KubeListResult(None, status, "server error", False, False),
        manifest=m,
    )
    report = c.result()
    assert report["status"] == ("unavailable" if status in {401, 403} else "partial")
    assert not report["findings"]
    assert len(m.result()) == len(WORKLOADS)
    assert all(not r["complete"] and r["read"] == 0 for r in m.result())
    assert all(bool(r["denied"]) == (status in {401, 403}) for r in m.result())
    assert all(r["unsupported"] == (status in {404, 405}) for r in m.result())


def test_read_failure_preserves_arrived_env_and_marks_partial():
    c, m = collector(), SourceManifest()

    def get(base, sink):
        if base == "/api/v1/pods":
            sink(workload("pods", ("spec",)))
            return actions.KubeListResult([], 500, "page failure", True, False)
        return actions.KubeListResult([], 200, None, True, True)

    scan_workload_env(c, namespaces=[], list_items=get, manifest=m)
    r = c.result()
    assert r["status"] == "partial" and r["partial_reasons"]
    assert [f["value"] for f in r["findings"]] == ["inactive-inline!42"]
    assert m.result()[0]["read"] == 1 and not m.result()[0]["complete"]


def test_cancel_and_deadline_do_not_start_remaining_sources():
    cancelled = [False]
    c, m = collector(cancelled=lambda: cancelled[0]), SourceManifest()

    def get(base, sink):
        sink(workload("pods", ("spec",)))
        cancelled[0] = True
        return actions.KubeListResult([], 200, None, True, True)

    with pytest.raises(NestedSchedulerCancelled):
        scan_workload_env(c, namespaces=[], list_items=get, manifest=m)
    assert len(c.result()["findings"]) == 1
    assert sum(row["requested"] for row in m.result()) == 1
    assert len(m.result()) == len(WORKLOADS)
    c = collector()
    c.deadline = time.monotonic() - 1
    m = SourceManifest()
    scan_workload_env(c, namespaces=[], list_items=lambda *a: pytest.fail("request after deadline"), manifest=m)
    assert c.result()["status"] == "partial"
    assert all(not row["complete"] and row["requested"] == 0 for row in m.result())


@pytest.mark.parametrize("fault", ["wrong-namespace", "bad-env", "bad-value", "both", "bad-spec"])
def test_malformed_workload_never_makes_manifest_complete(fault):
    c, m = collector(), SourceManifest()
    item = workload("pods", ("spec",))
    if fault == "wrong-namespace":
        item["metadata"]["namespace"] = "outside-selector"
    elif fault == "bad-spec":
        item.pop("spec")
    else:
        env = item["spec"]["containers"][0]["env"]
        if fault == "bad-env":
            env.append(42)
        elif fault == "bad-value":
            env.append({"name": "OTHER_PASSWORD", "value": {"not": "text"}})
        else:
            env[0]["valueFrom"] = {"secretKeyRef": {"name": "ref", "key": "password"}}

    def get(base, sink):
        if base == "/api/v1/namespaces/qa/pods":
            sink(item)
        return actions.KubeListResult([], 200, None, True, True)

    scan_workload_env(c, namespaces=["qa"], list_items=get, manifest=m)
    assert c.result()["status"] == "partial"
    assert not m.result()[0]["complete"]
    if fault in {"wrong-namespace", "bad-spec", "both"}:
        assert not c.result()["findings"]


def test_collect_integration_pages_uses_auth_namespace_and_does_not_exec(monkeypatch):
    calls, emitted = [], []

    def get(host, port, path, timeout, **kw):
        calls.append(path)
        assert host == "qa" and kw["token"] == "token-for-test"
        assert "/namespaces/qa/" in path
        if "/secrets?" in path:
            items = [
                {
                    "metadata": {"namespace": "qa", "name": "db"},
                    "data": {"password": base64.b64encode(b"inactive-stored!42").decode()},
                }
            ]
        elif "/pods?" in path and "continue=" not in path:
            items = [workload("pods", ("spec",))]
            return 200, {"items": items, "metadata": {"continue": "next-page"}}, {}, None
        else:
            items = []
        if "continue=" in path:
            assert any("inactive-inline!42" in line for line in emitted)
        return 200, {"items": items, "metadata": {}}, {}, None

    monkeypatch.setattr(actions, "_api_get_json", get)
    monkeypatch.setattr(actions, "_kube_exec_ws", lambda *a, **kw: pytest.fail("discovery must not exec"))
    ctx = SimpleNamespace(
        host="qa",
        port=6443,
        args=SimpleNamespace(discover=True, discover_time=30, retries=0, timeout=1),
        lifecycle_state=actions.KubeApiLifecycleState(token="token-for-test"),
        live_emit=emitted.extend,
    )
    result = actions.collect_kubeapi_data(
        ctx,
        {"status": "auth_valid"},
        {
            "show_namespaces": False,
            "show_pods": False,
            "show_secrets": True,
            "namespace_filters": ["qa"],
            "exec_pod": None,
            "exec_command": None,
        },
    )["content_discovery"]
    assert result["status"] == "complete", result["partial_reasons"]
    assert {row["value"] for row in result["findings"]} == {"inactive-stored!42", "inactive-inline!42"}
    assert len(result["sources"]) == len(WORKLOADS) + 2
    assert all(row["requested"] == 1 and row["complete"] for row in result["sources"])
    assert len(calls) == len(WORKLOADS) + 3


def test_large_inline_value_keeps_full_disk_value_and_path():
    c, m = collector(), SourceManifest()
    with DiskBackedText() as value:
        value.append_text("inactive-" + "Ab0λ " * 20000)
        value.finish()

        def get(base, sink):
            if base == "/api/v1/pods":
                sink(workload("pods", ("spec",), value=value))
            return actions.KubeListResult([], 200, None, True, True)

        scan_workload_env(c, namespaces=[], list_items=get, manifest=m)
        r = c.result()
        assert r["status"] == "complete"
        found = r["findings"][0]["value"]
        assert "".join(found.iter_text_chunks()) == "inactive-" + "Ab0λ " * 20000
