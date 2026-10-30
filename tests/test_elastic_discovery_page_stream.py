"""Multi-hit discovery search pages should not be retried as whole byte buffers."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.modules.elastic import actions
from redposture_core.modules.elastic.discover import DiscoverRequest


def test_multi_hit_page_is_decoded_from_stream_without_buffered_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    page = {
        "hits": {
            "hits": [
                {"_id": "one", "_source": {"password": "first-secret"}},
                {"_id": "two", "_source": {"password": "last-secret"}},
            ]
        }
    }
    raw = json.dumps(page).encode()

    class Pool:
        def request(self, *args, **kwargs):
            pytest.fail("a successful discovery page must not be requested through the buffered path")

        def request_stream(self, *args, **kwargs):
            for offset in range(0, len(raw), 7):
                kwargs["on_chunk"](raw[offset : offset + 7])
            return SimpleNamespace(status=200, headers={}, error=None, truncated=False)

    sentinel = object()

    def run(request, **kwargs):
        response = request(DiscoverRequest("POST", "/_search", body=b'{"size":200}'))
        assert response.status == 200
        assert response.payload == b""
        assert response.parsed_payload == page
        return sentinel

    monkeypatch.setattr(actions, "run_discovery", run)
    assert (
        actions._collect_discover_report(
            "127.0.0.1", 9200, 5.0, scheme="http", insecure=False, ca_file=None, auth_headers={}, http_pool=Pool()
        )
        is sentinel
    )


def test_streamed_search_keeps_legacy_error_body_for_negotiation(monkeypatch: pytest.MonkeyPatch) -> None:
    error_body = b'{"error":{"type":"parsing_exception","reason":"unknown field track_total_hits"}}'
    calls = []

    class Pool:
        def request_stream(self, *args, **kwargs):
            calls.append("stream")
            return SimpleNamespace(status=400, headers={}, error=None, truncated=False)

        def request(self, *args, **kwargs):
            calls.append("buffer-error")
            return SimpleNamespace(status=400, body=error_body, headers={}, error=None, truncated=False)

    def run(request, **kwargs):
        response = request(DiscoverRequest("POST", "/_search", body=b'{"size":200}'))
        assert response.status == 400 and response.payload == error_body
        return None

    monkeypatch.setattr(actions, "run_discovery", run)
    actions._collect_discover_report(
        "127.0.0.1", 9200, 5.0, scheme="http", insecure=False, ca_file=None, auth_headers={}, http_pool=Pool()
    )
    assert calls == ["stream", "buffer-error"]


def test_oversized_configuration_retries_as_stream_without_source_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "Sa7-λ/" * 30_000
    raw = json.dumps({"persistent": {"password": secret}}, ensure_ascii=False).encode()

    class Pool:
        def request(self, *args, **kwargs):
            return SimpleNamespace(status=200, body=raw[:256], headers={}, error=None, truncated=True)

        def request_stream(self, *args, **kwargs):
            for offset in range(0, len(raw), 65_536):
                kwargs["on_chunk"](raw[offset : offset + 65_536])
            return SimpleNamespace(status=200, headers={}, error=None, truncated=False)

    def run(request, **kwargs):
        response = request(DiscoverRequest("GET", "/_cluster/settings"))
        assert response.status == 200 and not response.truncated
        value = response.parsed_payload["persistent"]["password"]
        assert "".join(value.iter_text_chunks()) == secret
        return None

    monkeypatch.setattr(actions, "run_discovery", run)
    actions._collect_discover_report(
        "127.0.0.1", 9200, 5.0, scheme="http", insecure=False, ca_file=None, auth_headers={}, http_pool=Pool()
    )


def test_interrupted_configuration_keeps_finished_value_and_transport_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    prefix = b'{"persistent":{"password":"finished-secret","broken":"unfinished'

    class Pool:
        def request(self, *args, **kwargs):
            return SimpleNamespace(status=200, body=prefix, headers={}, error=None, truncated=True)

        def request_stream(self, *args, **kwargs):
            kwargs["on_chunk"](prefix)
            return SimpleNamespace(status=200, headers={}, error="socket timeout", truncated=True)

    def run(request, **kwargs):
        response = request(DiscoverRequest("GET", "/_cluster/settings"))
        assert response.truncated
        assert response.parsed_payload == {"persistent": {"password": "finished-secret"}}
        assert "socket timeout" in response.error
        return None

    monkeypatch.setattr(actions, "run_discovery", run)
    actions._collect_discover_report(
        "127.0.0.1", 9200, 5.0, scheme="http", insecure=False, ca_file=None, auth_headers={}, http_pool=Pool()
    )
