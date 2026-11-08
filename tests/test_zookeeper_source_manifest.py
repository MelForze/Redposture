"""Native data reads and child catalogs are independent source classes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.modules.zookeeper.discovery import discover_znodes
from redposture_core.scheduler import NestedSchedulerCancelled


def run(module, *, denied=None, cancel=False, selected=False):
    emitted, calls = [], []

    class Client:
        def get_data_discovery(self, path, **kwargs):
            calls.append(("data", path))
            if denied == "data":
                return None, -102, None
            return b'password="inactive-native!42"' if path == "/child" or selected else b"", 0, None

        def read_children_discovery(self, path, sink, **kwargs):
            assert not cancel or not emitted, "network request after cancellation"
            calls.append(("children", path))
            if denied == "children":
                return -102, None
            if path == "/":
                sink("child")
            return 0, None

    ctx = SimpleNamespace(
        host="qa",
        port=2181,
        args=SimpleNamespace(discover_time=30),
        live_emit=emitted.extend,
        cancelled=lambda: cancel and bool(emitted),
    )
    result = discover_znodes(
        ctx, {"module": module, "status": "open_no_auth"}, Client(), {"query_znode": "/child" if selected else None}
    )
    return result["content_discovery"], calls


@pytest.mark.parametrize("module", ["zookeeper", "keeper"])
def test_native_read_counts_empty_values_and_child_responses(module):
    report, _ = run(module)
    assert report["status"] == "complete"
    rows = {r["id"]: r for r in report["sources"]}
    for kind in ("znode_data", "znode_children"):
        assert rows[module + "." + kind]["read"] == 2 and rows[module + "." + kind]["complete"]
    assert [f["value"] for f in report["findings"]] == ["inactive-native!42"]


@pytest.mark.parametrize("module", ["zookeeper", "keeper"])
@pytest.mark.parametrize("denied,kind", [("data", "znode_data"), ("children", "znode_children")])
def test_native_noauth_is_not_an_empty_read(module, denied, kind):
    report, _ = run(module, denied=denied)
    row = next(r for r in report["sources"] if r["id"] == module + "." + kind)
    assert row["denied"] > 0 and not row["complete"] and row["read"] == 0
    assert report["status"] in {"partial", "unavailable"}


@pytest.mark.parametrize("module", ["zookeeper", "keeper"])
def test_selected_znode_does_not_claim_child_traversal(module):
    report, calls = run(module, selected=True)
    row = next(r for r in report["sources"] if r["id"] == module + ".znode_children")
    assert row["requested"] == 0 and not row["complete"]
    assert calls == [("data", "/child")]


@pytest.mark.parametrize("module", ["zookeeper", "keeper"])
def test_cancellation_is_not_swallowed_as_runtime_error_before_child_request(module):
    with pytest.raises(NestedSchedulerCancelled):
        run(module, cancel=True)
    for _ in range(2):
        result, calls = run(module)
        assert result["status"] == "complete" and len(calls) == 4
        assert [f["value"] for f in result["findings"]] == ["inactive-native!42"]


@pytest.mark.parametrize("module", ["zookeeper", "keeper"])
def test_interrupted_graph_cannot_report_completed_data_class(monkeypatch, module):
    from redposture_core.modules.zookeeper import discovery
    from redposture_core.storage_discovery import DiscoveryCollector

    collectors = []

    def collect(*args, **kwargs):
        result = DiscoveryCollector(*args, **kwargs)
        collectors.append(result)
        return result

    monkeypatch.setattr(discovery, "DiscoveryCollector", collect)

    class Client:
        def get_data_discovery(self, path, **kwargs):
            return b"", 0, None

        def read_children_discovery(self, path, sink, **kwargs):
            raise NestedSchedulerCancelled("stop before frontier is known")

    ctx = SimpleNamespace(host="qa", port=2181, args=SimpleNamespace(discover_time=30))
    with pytest.raises(NestedSchedulerCancelled):
        discovery.discover_znodes(ctx, {"module": module, "status": "open_no_auth"}, Client(), {})
    row = next(r for r in collectors[0].result()["sources"] if r["id"] == module + ".znode_data")
    assert row["read"] == 1 and not row["complete"]
