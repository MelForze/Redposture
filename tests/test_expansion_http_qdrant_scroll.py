"""Read-only Qdrant scrolling transport and bounded evidence contracts."""

from __future__ import annotations

from typing import Any

import pytest

from redposture_core.modules.qdrant import actions as qdrant


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
