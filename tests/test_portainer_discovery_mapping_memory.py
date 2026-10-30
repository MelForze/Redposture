"""Filtering exposed metadata must not rebuild a whole disk-backed JSON tree."""

from __future__ import annotations

import tracemalloc

import pytest

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_json import DiskJSONDocument
from redposture_core.storage_discovery import _portainer_discovery_view


@pytest.mark.parametrize("shape", ["object", "array"])
def test_portainer_discovery_view_keeps_wide_objects_and_arrays_disk_backed(shape):
    document = DiskJSONDocument()
    document.feed(b'{"GraphDriver":{"password":"excluded-secret"},"Spec":')
    document.feed(b"{" if shape == "object" else b"[")
    for index in range(1000):
        document.feed(f'"field_{index:05d}":"'.encode() if shape == "object" else b'"')
        document.feed(b"v" * 50000)
        document.feed(b'",')
    document.feed(b'"password":"kept-secret"}' if shape == "object" else b'{"password":"kept-secret"}]')
    document.feed(b"}")
    value = document.finish()
    document.close()
    tracemalloc.start()
    try:
        filtered = _portainer_discovery_view(value)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert "GraphDriver" not in filtered
    assert len(filtered["Spec"]) == 1001
    matches, _size, complete = _scan_portioned_value(filtered, "$", 65536)
    assert complete
    assert [item.value for item in matches] == ["kept-secret"]
    assert peak < 8_000_000, f"Portainer filter rebuilt {peak} heap bytes from disk metadata"
