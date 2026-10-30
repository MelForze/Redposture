"""Reproduction for a single accessible search hit larger than an HTTP portion."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from redposture_core.modules.elastic.actions import _collect_discover_report
from redposture_core.modules.elastic.discover import DiscoverOptions


def test_large_single_hit_preserves_late_token_after_transport_portion() -> None:
    token = "glpat-abcdefghijklmnopqrst"
    document = {"message": ("ordinary task output\n" * 500_000) + f"api_key={token}\n"}
    large_page = json.dumps(
        {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [{"_index": "large", "_id": "late-secret", "_source": document, "sort": [1]}],
            },
        }
    ).encode()
    assert len(large_page) > 10 * 1024 * 1024
    empty_page = json.dumps({"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}).encode()
    calls: list[tuple[str, str, int | None, bool]] = []

    class Pool:
        @staticmethod
        def _payload(method: str, url: str, body: bytes | None) -> bytes:
            path = urlsplit(url).path
            parsed_body = json.loads(body) if body else {}
            if path.startswith("/_resolve/index"):
                return b'{"indices":[{"name":"large","attributes":["open"]}]}'
            if path.endswith("/_mapping") or "/_mapping" in path:
                return b'{"large":{"mappings":{"properties":{"message":{"type":"text"}}}}}'
            if "/_settings" in path and not path.startswith(("/_cluster", "/_nodes")):
                return b'{"large":{"settings":{}}}'
            if path.endswith("/_pit") and method == "POST":
                return b'{"id":"pit-qa"}'
            if method == "DELETE":
                return b'{"succeeded":true}'
            if path in {"/_search", "/_search/scroll"}:
                return large_page if not parsed_body.get("search_after") else empty_page
            return b"{}"

        def request(self, method: str, url: str, **kwargs: Any) -> Any:
            data = json.loads(kwargs.get("body") or b"{}")
            calls.append(("buffer", urlsplit(url).path, data.get("size"), bool(data.get("search_after"))))
            payload = self._payload(method, url, kwargs.get("body"))
            cap = int(kwargs["response_size_cap"])
            return type(
                "Response",
                (),
                {
                    "status": 200,
                    "body": payload[:cap],
                    "headers": {},
                    "error": None,
                    "truncated": len(payload) > cap,
                },
            )()

        def request_stream(self, method: str, url: str, **kwargs: Any) -> Any:
            data = json.loads(kwargs.get("body") or b"{}")
            calls.append(("stream", urlsplit(url).path, data.get("size"), bool(data.get("search_after"))))
            payload = self._payload(method, url, kwargs.get("body"))
            if kwargs.get("on_response") is not None:
                kwargs["on_response"](200, {"content-type": "application/json"})
            for offset in range(0, len(payload), int(kwargs.get("chunk_size") or 64 * 1024)):
                kwargs["on_chunk"](payload[offset : offset + int(kwargs.get("chunk_size") or 64 * 1024)])
            return SimpleNamespace(
                status=200, headers={"content-type": "application/json"}, error=None, truncated=False
            )

    report = _collect_discover_report(
        "127.0.0.1",
        9200,
        3.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
        http_pool=Pool(),
        options=DiscoverOptions(max_seconds=180),
        started_at=time.monotonic(),
    )

    assert any(finding.value == token for finding in report.findings), report.to_dict()
    assert "search:large:response_size_cap" not in report.coverage.truncated_reasons, calls
    assert report.to_dict()["discover_coverage"]["complete"], report.coverage.truncated_reasons


def test_interrupted_stream_keeps_completed_early_finding_and_reports_partial() -> None:
    token = "glpat-abcdefghijklmnopqrst"
    prefix = (
        '{"hits":{"total":{"value":1,"relation":"eq"},"hits":['
        '{"_index":"large","_id":"broken","_source":{'
        f'"api_key":"{token}","message":"unfinished line'
    ).encode()

    class Pool:
        def request(self, method: str, url: str, **kwargs: Any) -> Any:
            path = urlsplit(url).path
            if path.startswith("/_resolve/index"):
                body = b'{"indices":[{"name":"large","attributes":["open"]}]}'
            elif path.endswith("/_mapping"):
                body = b'{"large":{"mappings":{"properties":{"api_key":{"type":"keyword"}}}}}'
            elif path.endswith("/_settings"):
                body = b'{"large":{"settings":{}}}'
            elif path.endswith("/_pit") and method == "POST":
                body = b'{"id":"pit-qa"}'
            elif path.endswith("_search"):
                body = prefix
            else:
                body = b"{}"
            return SimpleNamespace(
                status=200,
                body=body,
                headers={},
                error=None,
                truncated=path.endswith("_search"),
            )

        def request_stream(self, _method: str, _url: str, **kwargs: Any) -> Any:
            kwargs["on_chunk"](prefix)
            return SimpleNamespace(status=200, headers={}, error="unexpected EOF", truncated=True)

    report = _collect_discover_report(
        "127.0.0.1",
        9200,
        3.0,
        scheme="http",
        insecure=False,
        ca_file=None,
        auth_headers={},
        http_pool=Pool(),
        options=DiscoverOptions(max_seconds=30),
        started_at=time.monotonic(),
    )
    assert any(finding.value == token for finding in report.findings)
    assert report.to_dict()["discover_coverage"]["status"] == "partial"
