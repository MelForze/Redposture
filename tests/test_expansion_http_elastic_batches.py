"""Elastic resource splitting recovers only confirmed per-index evidence."""

from __future__ import annotations

import json
from typing import Any

import pytest

from redposture_core.modules.elastic.discover import DiscoverEngine, DiscoverOptions, DiscoverRequest


def response(value: Any, status: int = 200, truncated: bool = False) -> tuple[Any, ...]:
    return status, json.dumps(value).encode(), {}, None, truncated


@pytest.mark.parametrize("failure", [413, 414, 429, 500, 502, 503, 504, "invalid_shape"])
def test_elastic_failed_multiindex_batch_recovers_by_splitting(failure: int | str) -> None:
    paths = []

    def request(item: DiscoverRequest) -> Any:
        paths.append(item.path)
        indices = item.path.split("/")[1].split(",")
        if len(indices) > 1:
            return response([], 200) if failure == "invalid_shape" else response({"error": "busy"}, int(failure))
        return response({indices[0]: {"mappings": {"properties": {}}}})

    engine = DiscoverEngine(request, options=DiscoverOptions(mapping_batch_size=2))
    result = engine._fetch_index_resource(["a", "b"], suffix="_mapping", surface_name="mappings")
    assert set(result) == {"a", "b"} and paths == ["/a,b/_mapping", "/a/_mapping", "/b/_mapping"]
    surface = engine.coverage.surfaces["mappings"]
    assert surface.status == "complete" and surface.objects_attempted == surface.objects_scanned == 2
    assert not engine.coverage.truncated_reasons


def test_elastic_omitted_index_marks_partial_without_losing_confirmed_mapping() -> None:
    paths = []

    def request(item: DiscoverRequest) -> Any:
        paths.append(item.path)
        return response({"a": {"mappings": {}}})

    engine = DiscoverEngine(request)
    result = engine._fetch_index_resource(["a", "b"], suffix="_mapping", surface_name="mappings")
    assert result == {"a": {"mappings": {}}} and paths == ["/a,b/_mapping"]
    surface = engine.coverage.surfaces["mappings"]
    assert surface.status == "partial" and surface.objects_attempted == 2 and surface.objects_scanned == 1
    assert surface.error == "response omitted index b"
    assert surface.error_detail and surface.error_detail["type"] == "incomplete_index_resource"


def test_elastic_legacy_suffix_reused_for_later_batches_after_confirmation() -> None:
    paths = []

    def request(item: DiscoverRequest) -> Any:
        paths.append(item.path)
        index = item.path.split("/")[1]
        return response({"error": "unsupported"}, 400) if "?" in item.path else response({index: {"settings": {}}})

    engine = DiscoverEngine(request, options=DiscoverOptions(mapping_batch_size=1))
    result = engine._fetch_index_resource(
        ["a", "b"], suffix="_settings?flat_settings=true", surface_name="index_settings", legacy_suffix="_settings"
    )
    assert set(result) == {"a", "b"}
    assert paths == ["/a/_settings?flat_settings=true", "/a/_settings", "/b/_settings"]
    assert engine.coverage.surfaces["index_settings"].objects_scanned == 2


def test_elastic_single_truncated_index_is_never_counted_as_scanned() -> None:
    engine = DiscoverEngine(lambda item: response({"a": {"mappings": {}}}, truncated=True))
    result = engine._fetch_index_resource(["a"], suffix="_mapping", surface_name="mappings")
    assert result == {"a": {"mappings": {}}}
    surface = engine.coverage.surfaces["mappings"]
    assert surface.status == "partial" and surface.objects_attempted == 1 and surface.objects_scanned == 0
    assert "mappings:response_size_cap" in engine.coverage.truncated_reasons
