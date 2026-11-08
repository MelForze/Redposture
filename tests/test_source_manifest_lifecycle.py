"""Interrupted scopes preserve prior evidence and never claim completion."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.discovery_sources import SourceManifest
from redposture_core.scheduler import NestedSchedulerCancelled
from redposture_core.storage_discovery import DiscoveryCollector


@pytest.mark.parametrize("error", [NestedSchedulerCancelled, KeyboardInterrupt, OSError, ValueError])
def test_aborted_scope_retains_reads_and_does_not_invalidate_other_completed_sources(error):
    m = SourceManifest()
    for source in ("finished", "active", "not_requested"):
        m.declare(source)
    m.request("finished")
    m.read("finished", 2)
    m.finish("finished", complete=True)
    m.request("active")
    with pytest.raises(error):
        with m.guard("active"):
            m.read("active")
            raise error()
    rows = {r["id"]: r for r in m.result()}
    assert rows["finished"]["complete"] and rows["finished"]["read"] == 2
    assert not rows["active"]["complete"] and rows["active"]["read"] == 1
    assert not rows["not_requested"]["complete"] and rows["not_requested"]["requested"] == 0


@pytest.mark.parametrize("error", [KeyboardInterrupt, NestedSchedulerCancelled])
def test_direct_transport_interrupt_cannot_leave_collector_complete(error):
    c = DiscoveryCollector(
        "jenkins", SimpleNamespace(host="qa", port=80, args=SimpleNamespace()), {"status": "open_no_auth"}
    )
    m = SourceManifest()
    c.source_manifest = m
    m.request("logs")
    c.add("before", {"password": "inactive-completed!42"})
    with pytest.raises(error):
        with c.source_guard(m, "logs"):
            raise error()
    result = c.result()
    assert result["status"] == "partial" and not result["sources"][0]["complete"]
    assert [f["value"] for f in result["findings"]] == ["inactive-completed!42"]
    assert any("cancelled" in r for r in result["partial_reasons"])
