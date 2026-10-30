"""Bounded search-response parsing for a single oversized Elastic hit."""

from __future__ import annotations

import io
import json

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.elastic.search_stream import SearchStreamError, StreamedSearchPage


def _page(source: object, *, inline_limit: int = 128) -> StreamedSearchPage:
    payload = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [{"_index": "logs", "_id": "doc-1", "_source": source, "sort": [9]}],
        }
    }
    return StreamedSearchPage(io.BytesIO(json.dumps(payload).encode()), inline_limit=inline_limit)


def test_large_log_scalar_preserves_late_token_and_json_path() -> None:
    token = "glpat-abcdefghijklmnopqrst"
    page = _page({"nested": [{"message": ("ordinary line\n" * 200) + f"api_key={token}\n"}]})
    assert page.summary()["hits"]["hits"][0]["sort"] == [9]
    assert page.compact_source() == {"nested": [{"message": ""}]}
    found: list[tuple[tuple[str | int, ...], str]] = []
    assert page.scan_large_fields(lambda path, segment: found.append((path, segment)))
    assert sum(token in segment for _path, segment in found) == 1
    assert all(path[-3:] == ("nested", 0, "message") for path, _segment in found)
    page.close()


def test_indivisible_long_scalar_is_not_reported_complete() -> None:
    page = _page({"message": "x" * 2000}, inline_limit=64)
    page.summary()
    page.compact_source()
    segments: list[str] = []
    assert not page.scan_large_fields(lambda _path, segment: segments.append(segment))
    assert segments == []
    page.close()


def test_indivisible_long_scalar_can_be_verified_from_disk() -> None:
    secret = "token-" + "abcdefghi" * 150_000
    page = _page({"api_token": secret}, inline_limit=64)
    page.summary()
    page.compact_source()
    retained: list[DiskBackedText] = []

    def accept(_path: tuple[str | int, ...], value: DiskBackedText) -> bool:
        retained.append(value)
        return True

    assert page.scan_large_fields(lambda _path, _segment: None, on_scalar=accept)
    assert page.resolved_paths == {("hits", "hits", 0, "_source", "api_token")}
    assert "".join(retained[0].iter_text_chunks()) == secret
    retained[0].close()
    page.close()


def test_empty_search_page_is_valid_and_closable() -> None:
    payload = b'{"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}'
    page = StreamedSearchPage(io.BytesIO(payload))
    assert page.summary()["hits"]["hits"] == []
    page.close()


def test_multiple_hits_or_damaged_json_cannot_be_marked_complete() -> None:
    two_hits = b'{"hits":{"hits":[{"_source":{}},{"_source":{}}]}}'
    with pytest.raises(SearchStreamError, match="more than one hit"):
        StreamedSearchPage(io.BytesIO(two_hits)).summary()
    with pytest.raises(ValueError):
        StreamedSearchPage(io.BytesIO(b'{"hits":{"hits":[{"_source":{"value":"unfinished"}]}')).summary()
