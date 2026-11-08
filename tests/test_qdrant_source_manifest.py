"""Scroll completion and HTTP status are evidence, not merely parsed bytes."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.qdrant import actions
from redposture_core.storage_discovery import DiscoveryCollector


def collector():
    return DiscoveryCollector(
        "qdrant",
        SimpleNamespace(host="qa", port=6333, args=SimpleNamespace(discover_time=30)),
        {"status": "open_no_auth"},
    )


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_oversized_point_never_emits_findings_from_http_error_body(monkeypatch, status):
    c = collector()

    class Pool:
        def request_stream(self, method, url, *, on_chunk, **kwargs):
            assert method == "POST"
            if kwargs.get("on_response"):
                kwargs["on_response"](status, {})
            on_chunk(
                json.dumps(
                    {
                        "result": {
                            "points": [{"id": 1, "payload": {"password": "not-a-source!42"}}],
                            "next_page_offset": None,
                        }
                    }
                ).encode()
            )
            return HttpResponse(status, b"", {})

    monkeypatch.setattr(
        actions._THREAD_LOCAL_TRANSPORT,
        "state",
        actions.QdrantLifecycleState(http=Pool(), host="qa", port=6333),
        raising=False,
    )
    point, offset, error = actions._qdrant_stream_oversized_point("qa", 6333, 1, "app", {"limit": 1}, None, c, 1)
    assert error and point is None and not c.result()["findings"]


@pytest.mark.parametrize("status", [200, 403, 500])
def test_scroll_collection_manifest_distinguishes_denied_empty_and_complete(monkeypatch, status):
    c = collector()
    monkeypatch.setattr(
        actions,
        "_http_json_request",
        lambda *a, **kw: (status, {"result": {"points": [], "next_page_offset": None}}, None),
    )
    points, partial = actions._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=c)
    row = next(r for r in c.result()["sources"] if r["id"] == "qdrant.point_payloads")
    assert row["read"] == int(status == 200) and row["complete"] == (status == 200)
    assert row["denied"] == int(status == 403) and partial == (status != 200)
    assert points == []
