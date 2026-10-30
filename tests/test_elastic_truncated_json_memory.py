"""Adaptive page retries must release rejected JSON before the next request."""

from __future__ import annotations

import gc
import json
import tracemalloc

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.elastic.discover import _load_json


def test_truncated_unicode_pages_do_not_retain_decode_exception_documents() -> None:
    prefix = b'{"hits":{"hits":[{"_source":{"message":"' + ("Ab0λ" * 400_000).encode()
    gc.collect()
    was_enabled = gc.isenabled()
    gc.disable()
    tracemalloc.start()
    try:
        for _ in range(20):
            assert _load_json(prefix) is None
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        if was_enabled:
            gc.enable()
        gc.collect()
    assert peak < 8_000_000, f"rejected page bodies retained through exception tracebacks: {peak} bytes"


def test_valid_unicode_json_still_decodes_and_preserves_scalar_values() -> None:
    assert _load_json('{"message":"Кириллица λ","count":2}'.encode()) == {
        "message": "Кириллица λ",
        "count": 2,
    }


def test_large_json_response_materialization_uses_disk_for_unicode_values() -> None:
    value = "Ab0λ" * 2_000_000
    payload = json.dumps({"message": value}, ensure_ascii=False).encode()
    tracemalloc.start()
    try:
        parsed = _load_json(payload)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert isinstance(parsed["message"], DiskBackedText)
    assert "".join(parsed["message"].iter_text_chunks()) == value
    assert peak < 8_000_000
