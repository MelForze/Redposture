"""HTTP error bodies are not evidence of accessible stored source contents."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.storage_discovery import DiscoveryCollector


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 302])
def test_http_error_body_does_not_publish_findings(status):
    emitted = []
    collector = DiscoveryCollector(
        "jenkins",
        SimpleNamespace(host="qa", port=80, args=SimpleNamespace(discover_time=30), live_emit=emitted.extend),
        {"status": "auth_valid"},
    )

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, **kwargs):
            if callable(kwargs.get("on_response")):
                kwargs["on_response"](status, {})
            on_chunk(b'password="error-body-echo-not-a-source!42"\n')
            return HttpResponse(status, b"", {})

    assert not collector.stream_http_content(Pool(), "http://qa/artifact/config", "artifact", headers={}, timeout=1)
    result = collector.result()
    assert not emitted and not result["findings"]
    assert result["status"] == ("unavailable" if status in {401, 403} else "partial")


def test_http_200_keeps_early_finding_even_when_later_transport_fails():
    emitted = []
    collector = DiscoveryCollector(
        "jenkins",
        SimpleNamespace(host="qa", port=80, args=SimpleNamespace(discover_time=30), live_emit=emitted.extend),
        {"status": "auth_valid"},
    )

    class Pool:
        def request_stream(self, _method, _url, *, on_response, on_chunk, **kwargs):
            on_response(200, {})
            on_chunk(b'password="completed-before-error!42"\n')
            assert any("completed-before-error!42" in line for line in emitted)
            on_chunk(b'password="unfinished')
            return HttpResponse(200, b"", {}, error="read timeout")

    assert not collector.stream_http_content(Pool(), "http://qa/artifact/config", "artifact", headers={}, timeout=1)
    result = collector.result()
    assert result["status"] == "partial"
    assert [row["value"] for row in result["findings"]] == ["completed-before-error!42"]
