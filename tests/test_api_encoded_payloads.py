"""Explicit API base64 fields reach format dispatch without lossy decoding."""

from __future__ import annotations

import base64
import gzip
import time
from types import SimpleNamespace

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.consul import actions as consul
from redposture_core.modules.etcd import actions as etcd
from redposture_core.modules.kubeapi import actions as kube
from redposture_core.storage_discovery import DiscoveryCollector


@pytest.mark.parametrize("module", ["etcd", "consul", "kubeapi"])
@pytest.mark.parametrize("kind", ["utf16", "gzip", "binary", "invalid"])
def test_api_encoded_fields_preserve_formats_and_unknown_coverage(monkeypatch, module, kind):
    password = "qa-encoded-source-password-2026"
    body = f'password="{password}"\n'
    raw = {"utf16": body.encode("utf-16"), "gzip": gzip.compress(body.encode()), "binary": b"\xff\0"}
    encoded = "!!!!" if kind == "invalid" else base64.b64encode(raw[kind]).decode()
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=1)
    collector = DiscoveryCollector(module, ctx, {"status": "open_no_auth"})
    if module == "etcd":
        monkeypatch.setattr(
            etcd,
            "_http_json_request",
            lambda *a, **kw: (
                200,
                __import__("json").dumps(
                    {"kvs": [{"key": base64.b64encode(b"/app/config").decode(), "value": encoded}]}
                ),
            ),
        )
        entry, error = etcd._dump_v3_key(
            "qa",
            2379,
            "/app/config",
            1,
            discovery_budget=etcd._EtcdDiscoveryBudget(time.monotonic() + 30, 1_000_000, collector),
        )
        assert entry is not None or error == "invalid_base64_value"
    elif module == "consul":
        monkeypatch.setattr(
            consul,
            "_consul_get_json_any",
            lambda *a, **kw: (200, [{"Key": "app/config", "Value": encoded}], None, False, False),
        )
        with consul._ConsulLifecycleReplay(consul.ConsulLifecycleState(discovery_collector=collector)):
            consul._consul_kv_dump("qa", 8500, 1, scheme="http", insecure=False, key_name="app/config")
    else:
        monkeypatch.setattr(
            kube,
            "_invoke_kube_list_items",
            lambda *a, **kw: kube.KubeListResult(
                [{"metadata": {"namespace": "qa", "name": "config"}, "data": {"config": encoded}}],
                200,
                None,
                True,
                True,
            ),
        )

        def sink(item):
            for error in item.get("data_errors", []):
                collector.partial("secrets.qa.config", error)
            collector.add("secrets.qa.config", item["data"], charge=False)

        kube._list_secrets(
            "qa",
            6443,
            1,
            use_https=True,
            insecure=True,
            ca_file=None,
            namespaces=[],
            discovery_budget=kube.KubeDiscoveryReadBudget(1_000_000, time.monotonic() + 30),
            item_sink=sink,
        )
    result = collector.result()
    values = {
        "".join(row["value"].iter_text_chunks()) if isinstance(row["value"], DiskBackedText) else row["value"]
        for row in result["findings"]
    }
    if kind in {"binary", "invalid"}:
        assert result["status"] == "partial", result
        assert result["partial_reasons"]
        assert not values
    else:
        assert result["status"] == "complete", result["partial_reasons"]
        assert values == {password}
