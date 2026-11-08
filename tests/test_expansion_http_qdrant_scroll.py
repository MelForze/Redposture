"""Read-only Qdrant scrolling transport and bounded evidence contracts."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.qdrant import actions as qdrant
from redposture_core.storage_discovery import DiscoveryCollector


def test_discover_streams_one_oversized_qdrant_point_with_full_value(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "glpat-" + "Ab9_" * 25_000
    body = json.dumps(
        {"result": {"points": [{"id": 7, "payload": {"api_token": token}}], "next_page_offset": None}}
    ).encode()
    limits: list[int] = []

    def request(*_args: Any, **kwargs: Any) -> tuple[int, None, str]:
        limits.append(kwargs["payload"]["limit"])
        return 0, None, "byte_budget"

    class StreamPool:
        def request_stream(self, _method: str, _url: str, *, on_chunk: Any, **_kwargs: Any) -> Any:
            _kwargs["on_response"](200, {"content-type": "application/json"})
            for index in range(0, len(body), 257):
                on_chunk(body[index : index + 257])
            return SimpleNamespace(status=200, error=None, truncated=False)

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    monkeypatch.setattr(
        qdrant._THREAD_LOCAL_TRANSPORT,
        "state",
        qdrant.QdrantLifecycleState(http=StreamPool(), scheme="http", host="qa", port=6333),
        raising=False,
    )
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=10, discover_max_bytes=4096), host="qa", port=6333)
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    result = collector.result()
    assert limits == [100, 50, 25, 12, 6, 3, 1]
    assert partial is False
    assert points == [{"id": 7, "payload": None}]
    assert result["status"] == "complete"
    assert any(
        "".join(value.iter_text_chunks()) == token if isinstance(value, DiskBackedText) else value == token
        for value in (finding["value"] for finding in result["findings"])
    )


def test_discover_oversized_qdrant_point_midstream_error_is_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps(
        {
            "result": {
                "points": [{"id": 7, "payload": {"api_token": "glpat-abcdefghijklmnopqrst"}}],
                "next_page_offset": None,
            }
        }
    ).encode()

    class BrokenPool:
        def request_stream(self, _method: str, _url: str, *, on_chunk: Any, **_kwargs: Any) -> Any:
            _kwargs["on_response"](200, {"content-type": "application/json"})
            on_chunk(body[: body.index(b"next_page_offset")])
            return SimpleNamespace(status=200, error="unexpected EOF", truncated=True)

    monkeypatch.setattr(qdrant, "_http_json_request", lambda *_args, **_kwargs: (0, None, "byte_budget"))
    monkeypatch.setattr(
        qdrant._THREAD_LOCAL_TRANSPORT,
        "state",
        qdrant.QdrantLifecycleState(http=BrokenPool(), scheme="http", host="qa", port=6333),
        raising=False,
    )
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=10, discover_max_bytes=4096), host="qa", port=6333)
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    result = collector.result()
    assert points == [] and partial is True
    assert result["status"] == "partial"
    assert any("unexpected EOF" in reason for reason in result["partial_reasons"])
    assert result["findings"][0]["value"] == "glpat-abcdefghijklmnopqrst"


def test_discover_oversized_qdrant_point_continues_with_next_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    first_token = "glpat-" + "Ab9_" * 20_000
    second_token = "glpat-secondabcdefghijklmnopqrst"
    first_body = json.dumps(
        {"result": {"points": [{"id": 7, "payload": {"api_token": first_token}}], "next_page_offset": 7}}
    ).encode()
    seen_offsets: list[int | None] = []

    def request(*_args: Any, **kwargs: Any) -> tuple[int, Any, str | None]:
        body = kwargs["payload"]
        seen_offsets.append(body.get("offset"))
        if body.get("offset") == 7:
            return (
                200,
                {"result": {"points": [{"id": 8, "payload": {"api_token": second_token}}], "next_page_offset": None}},
                None,
            )
        return 0, None, "byte_budget"

    class StreamPool:
        def request_stream(self, _method: str, _url: str, *, on_chunk: Any, **_kwargs: Any) -> Any:
            _kwargs["on_response"](200, {"content-type": "application/json"})
            for position in range(0, len(first_body), 257):
                on_chunk(first_body[position : position + 257])
            return SimpleNamespace(status=200, error=None, truncated=False)

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    monkeypatch.setattr(
        qdrant._THREAD_LOCAL_TRANSPORT,
        "state",
        qdrant.QdrantLifecycleState(http=StreamPool(), scheme="http", host="qa", port=6333),
        raising=False,
    )
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=10, discover_max_bytes=4096), host="qa", port=6333)
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    result = collector.result()
    assert seen_offsets == [None] * 7 + [7]
    assert points == [{"id": 7, "payload": None}, {"id": 8, "payload": None}]
    assert partial is False and result["status"] == "complete"
    values = [
        "".join(item["value"].iter_text_chunks()) if isinstance(item["value"], DiskBackedText) else item["value"]
        for item in result["findings"]
    ]
    assert values.count(first_token) == 1
    assert values.count(second_token) >= 1
    assert len({(item["type"], item["fingerprint"]) for item in result["findings"]}) == len(result["findings"])


def test_discover_caps_buffered_qdrant_scroll_before_large_json_decode(monkeypatch: pytest.MonkeyPatch) -> None:
    caps: list[int] = []

    def request(*_args: Any, **kwargs: Any) -> tuple[int, Any, None]:
        caps.append(kwargs["response_size_cap"])
        return (
            200,
            {
                "result": {
                    "points": [{"id": 1, "payload": {"api_token": "glpat-abcdefghijklmnopqrst"}}],
                    "next_page_offset": None,
                }
            },
            None,
        )

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=10), host="qa", port=6333)
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    result = collector.result()

    assert points == [{"id": 1, "payload": None}]
    assert partial is False and result["status"] == "complete"
    assert result["findings"]
    assert all(item["value"] == "glpat-abcdefghijklmnopqrst" for item in result["findings"])
    assert caps and max(caps) <= 1_048_576


def test_discover_oversized_qdrant_nested_json_string_is_not_false_token(monkeypatch: pytest.MonkeyPatch) -> None:
    nested = json.dumps({"message": "ordinary " * 9000})
    body = json.dumps(
        {"result": {"points": [{"id": 7, "payload": {"api_token": nested}}], "next_page_offset": None}}
    ).encode()

    class StreamPool:
        def request_stream(self, _method: str, _url: str, *, on_chunk: Any, **_kwargs: Any) -> Any:
            _kwargs["on_response"](200, {"content-type": "application/json"})
            for position in range(0, len(body), 257):
                on_chunk(body[position : position + 257])
            return SimpleNamespace(status=200, error=None, truncated=False)

    monkeypatch.setattr(qdrant, "_http_json_request", lambda *_args, **_kwargs: (0, None, "byte_budget"))
    monkeypatch.setattr(
        qdrant._THREAD_LOCAL_TRANSPORT,
        "state",
        qdrant.QdrantLifecycleState(http=StreamPool(), scheme="http", host="qa", port=6333),
        raising=False,
    )
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=10, discover_max_bytes=4096), host="qa", port=6333)
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
    _points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    result = collector.result()
    assert partial is False and result["status"] == "partial"
    assert result["findings"] == []
    assert any("nested_json_string_unscanned" in reason for reason in result["partial_reasons"])


def test_discover_continues_scrolling_after_oversized_collection_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    info_calls: list[str] = []
    scroll_calls: list[str] = []

    def info(_host: str, _port: int, _timeout: float, name: str, **kwargs: Any) -> tuple[int, None, str]:
        info_calls.append(name)
        assert kwargs["response_size_cap"] == 100
        assert callable(kwargs["response_meter"])
        return 0, None, "byte_budget"

    monkeypatch.setattr(qdrant, "_qdrant_get_collection_info", info)

    def scroll(_host: str, _port: int, _timeout: float, name: str, **kwargs: Any) -> tuple[list[Any], bool]:
        scroll_calls.append(name)
        if name == "second":
            kwargs["collector"].add(
                "collection.second.point.7", {"api_token": "glpat-abcdefghijklmnopqrst"}, charge=False
            )
        return [], False

    monkeypatch.setattr(
        qdrant,
        "_qdrant_scroll_payloads",
        scroll,
    )
    monkeypatch.setattr(qdrant, "_qdrant_edit_probe_empty_patch", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(qdrant, "_qdrant_logger_endpoint_probe", lambda *_args, **_kwargs: {})
    ctx = SimpleNamespace(
        lifecycle_state=qdrant.QdrantLifecycleState(),
        args=SimpleNamespace(discover=True, discover_time=5, discover_max_bytes=100, timeout=1),
        host="qa",
        port=6333,
        credential=SimpleNamespace(token=None),
    )
    result = qdrant.collect_qdrant_data(
        ctx,
        {"status": "open_no_auth", "anonymous_access": True, "collections": ["first", "second"]},
        {"dump_requested": True, "dump_limit": None, "collection_name": None, "ssrf_urls": []},
    )
    assert info_calls == ["first", "second"]
    assert scroll_calls == ["first", "second"]
    assert result["content_discovery"]["status"] == "partial"
    assert any(item["value"] == "glpat-abcdefghijklmnopqrst" for item in result["content_discovery"]["findings"])


@pytest.mark.parametrize("fault", ["denied", "transport", "missing_points", "invalid_result"])
def test_scroll_retains_prior_page_when_later_response_is_unusable(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    requests = []

    def request(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        requests.append((args, kwargs))
        if len(requests) == 1:
            return (
                200,
                {
                    "result": {
                        "points": [{"id": 1, "payload": {"secret": "kept"}, "vector": [1]}],
                        "next_page_offset": 0,
                    }
                },
                None,
            )
        return {
            "denied": (403, {}, None),
            "transport": (0, {}, "reset"),
            "missing_points": (200, {"result": {}}, None),
            "invalid_result": (200, {"result": []}, None),
        }[fault]

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "collection/a", headers={"api-key": "key"})
    assert points == [{"id": 1, "payload": {"secret": "kept"}}] and partial is True
    assert len(requests) == 2 and requests[0][0][2:4] == ("POST", "/collections/collection%2Fa/points/scroll")
    assert requests[0][1]["payload"] == {"limit": 100, "with_payload": True, "with_vector": False}
    assert requests[1][1]["payload"]["offset"] == 0
    assert all(kwargs["headers"] == {"api-key": "key"} for _, kwargs in requests)


def test_scroll_repeated_offset_is_partial_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(
        qdrant,
        "_http_json_request",
        lambda *args, **kwargs: (
            calls.append(kwargs)
            or (200, {"result": {"points": [{"id": len(calls)}], "next_page_offset": "same"}}, None)
        ),
    )
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None)
    assert points == [{"id": 1, "payload": None}, {"id": 2, "payload": None}]
    assert partial is True and len(calls) == 2


def test_scroll_empty_collection_is_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(
        qdrant,
        "_http_json_request",
        lambda *args, **kwargs: (
            calls.append(kwargs) or (200, {"result": {"points": [], "next_page_offset": None}}, None)
        ),
    )
    assert qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None) == ([], False)
    assert len(calls) == 1


def test_scroll_page_limit_retains_all_bounded_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(
        qdrant,
        "_http_json_request",
        lambda *args, **kwargs: (
            calls.append(kwargs)
            or (200, {"result": {"points": [{"id": len(calls)}], "next_page_offset": len(calls)}}, None)
        ),
    )
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None)
    assert len(points) == len(calls) == 10 and partial is True
    assert [point["id"] for point in points] == list(range(1, 11))


def test_discover_scroll_continues_past_inventory_page_cap_and_emits_early(monkeypatch: pytest.MonkeyPatch) -> None:
    emitted: list[str] = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=5, discover_max_bytes=4096),
        host="qa",
        port=6333,
        live_emit=lambda lines: emitted.extend(lines),
    )
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
    calls = 0

    def request(*_args: Any, **kwargs: Any) -> tuple[int, dict[str, Any], None]:
        nonlocal calls
        calls += 1
        if calls == 2:
            assert emitted, "first finding should be emitted before the second page"
        body = {
            "result": {
                "points": [
                    {
                        "id": calls,
                        "payload": {"api_token": "glpat-abcdefghijklmnopqrst"} if calls == 1 else {"text": "ordinary"},
                    }
                ],
                "next_page_offset": calls if calls < 11 else None,
            }
        }
        assert kwargs["response_size_cap"] <= 4096
        assert kwargs["response_meter"](len(str(body).encode()))
        return 200, body, None

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    assert len(points) == calls == 11
    assert partial is False
    result = collector.result()
    assert result["status"] == "complete"
    assert result["findings"]
    assert all("ordinary" not in str(item) for item in result["findings"])


def test_discover_scroll_does_not_retain_every_scanned_point(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=60, discover_max_bytes=4096), host="qa", port=6333)
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
    calls = 0

    def request(*_args: Any, **kwargs: Any) -> tuple[int, dict[str, Any], None]:
        nonlocal calls
        calls += 1
        assert kwargs["response_meter"](64)
        return (
            200,
            {
                "result": {
                    "points": [
                        {
                            "id": calls,
                            "payload": {"api_token": "glpat-abcdefghijklmnopqrst"} if calls == 10001 else {},
                        }
                    ],
                    "next_page_offset": calls if calls < 10001 else None,
                }
            },
            None,
        )

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    assert calls == 10001 and partial is False
    assert len(points) <= 1000
    assert any(item["type"] == "gitlab_token" for item in collector.result()["findings"])


def test_discover_scroll_reduces_page_size_after_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=5, discover_max_bytes=4096), host="qa", port=6333)
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
    limits: list[int] = []

    def request(*_args: Any, **kwargs: Any) -> tuple[int, dict[str, Any], str | None]:
        limit = kwargs["payload"]["limit"]
        limits.append(limit)
        if limit > 1:
            return 0, {}, "byte_budget"
        assert kwargs["response_meter"](64)
        return (
            200,
            {
                "result": {
                    "points": [{"id": 1, "payload": {"api_token": "glpat-abcdefghijklmnopqrst"}}],
                    "next_page_offset": None,
                }
            },
            None,
        )

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    assert limits == [100, 50, 25, 12, 6, 3, 1]
    assert len(points) == 1 and partial is False
    assert collector.result()["status"] == "complete"


def test_discover_scroll_keeps_prior_finding_after_bounded_read_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=5, discover_max_bytes=512), host="qa", port=6333)
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
    calls = 0

    def request(*_args: Any, **kwargs: Any) -> tuple[int, dict[str, Any], str | None]:
        nonlocal calls
        calls += 1
        if calls == 1:
            kwargs["response_meter"](64)
            return (
                200,
                {
                    "result": {
                        "points": [{"id": 1, "payload": {"api_token": "glpat-abcdefghijklmnopqrst"}}],
                        "next_page_offset": 1,
                    }
                },
                None,
            )
        return 0, {}, "byte_budget"

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    assert len(points) == 1 and partial is True
    result = collector.result()
    assert result["status"] == "partial"
    assert result["findings"]


def test_discover_scroll_rejects_malformed_point_without_scanning_error_text(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=5, discover_max_bytes=512), host="qa", port=6333)
    collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})

    def request(*_args: Any, **kwargs: Any) -> tuple[int, dict[str, Any], None]:
        kwargs["response_meter"](64)
        return 200, {"result": {"points": [{"id": 1, "payload": {"label": "ordinary"}}, "glpat-should-not-scan"]}}, None

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None, collector=collector)
    assert len(points) == 1 and partial is True
    result = collector.result()
    assert result["status"] == "partial"
    assert result["findings"] == []


def test_scroll_invalid_point_cannot_claim_complete_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        qdrant,
        "_http_json_request",
        lambda *args, **kwargs: (200, {"result": {"points": [{"id": 1, "payload": {}}, "invalid-row"]}}, None),
    )
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None)
    assert points == [{"id": 1, "payload": {}}]
    assert partial is True, "Malformed scroll rows must make retained evidence explicitly incomplete"


def test_scroll_enforces_documented_thousand_point_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{"id": i, "payload": {}} for i in range(1001)]
    monkeypatch.setattr(qdrant, "_http_json_request", lambda *args, **kwargs: (200, {"result": {"points": rows}}, None))
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None)
    assert len(points) <= 1000, "Untrusted server page sizes must obey the documented global point cap"
    assert partial is True


@pytest.mark.parametrize("continued", [False, True])
def test_scroll_exact_global_cap_is_complete_only_without_continuation(monkeypatch, continued: bool) -> None:
    replies = iter(
        [
            (200, {"result": {"points": [{"id": i} for i in range(999)], "next_page_offset": 999}}, None),
            (200, {"result": {"points": [{"id": 999}], "next_page_offset": 1000 if continued else None}}, None),
        ]
    )
    monkeypatch.setattr(qdrant, "_http_json_request", lambda *a, **kw: next(replies))
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None)
    assert [point["id"] for point in points] == list(range(1000))
    assert partial is continued


def test_scroll_global_cap_applies_to_cumulative_oversized_pages(monkeypatch) -> None:
    replies = iter(
        [
            (200, {"result": {"points": [{"id": i} for i in range(750)], "next_page_offset": 750}}, None),
            (200, {"result": {"points": [{"id": i} for i in range(750, 1250)]}}, None),
        ]
    )
    monkeypatch.setattr(qdrant, "_http_json_request", lambda *a, **kw: next(replies))
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None)
    assert [point["id"] for point in points] == list(range(1000))
    assert partial is True


@pytest.mark.parametrize("invalid_page", [[None, "broken"], [{"id": 1}, "broken"]])
def test_scroll_malformed_coverage_stays_partial_after_clean_terminal_page(monkeypatch, invalid_page) -> None:
    replies = iter(
        [
            (200, {"result": {"points": invalid_page, "next_page_offset": 1}}, None),
            (200, {"result": {"points": [{"id": 2}]}}, None),
        ]
    )
    monkeypatch.setattr(qdrant, "_http_json_request", lambda *a, **kw: next(replies))
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "app", headers=None)
    assert points == (
        [{"id": 1, "payload": None}] if len(invalid_page) and isinstance(invalid_page[0], dict) else []
    ) + [{"id": 2, "payload": None}]
    assert partial is True
