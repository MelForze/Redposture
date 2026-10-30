"""Wide JSON objects cannot retain every scalar in memory during discovery."""

from __future__ import annotations

import hashlib
import tracemalloc

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_json import DiskJSONDocument
from redposture_core.discovery_values import DiskBackedText


def test_wide_json_object_keeps_complete_fields_and_final_secret_with_bounded_heap():
    document = DiskJSONDocument()
    block = b"v" * 50000
    count = 1000
    tracemalloc.start()
    try:
        document.feed(b"{")
        for index in range(count):
            document.feed(f'"field_{index:05d}":"'.encode())
            document.feed(block)
            document.feed(b'",')
        document.feed(b'"password":"known-last-secret"}')
        value = document.finish()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    try:
        assert len(value) == count + 1
        expected = hashlib.sha256(block).hexdigest()
        for index in (0, count // 2, count - 1):
            field = value[f"field_{index:05d}"]
            if isinstance(field, DiskBackedText):
                assert field.byte_length == len(block) and field.digest == expected
            else:
                assert field.encode() == block
        assert value["password"] == "known-last-secret"
        matches, _size, complete = _scan_portioned_value(value, "$", 65536)
        assert complete
        assert [(item.value, item.object_path) for item in matches] == [("known-last-secret", "$.password")]
        assert peak < 8_000_000, f"wide JSON retained {peak} heap bytes"
    finally:
        document.close()
