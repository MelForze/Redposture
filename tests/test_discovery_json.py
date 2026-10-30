"""Disk JSON decoding preserves exact strings and nested catalog structure."""

import json
import weakref

import pytest

from redposture_core.discovery_json import DiskJSONDocument
from redposture_core.discovery_spool import SpoolingValues
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks


def test_close_releases_incomplete_value_and_parser_callbacks():
    decoder = DiskJSONDocument()
    decoder.feed(b'{"secret":"' + b"a" * 100_000)
    unfinished = decoder._disk
    assert unfinished is not None
    path = unfinished.path
    reference = weakref.ref(decoder)
    decoder.close()
    del decoder
    assert reference() is None
    assert not path.exists()


def test_close_after_finish_preserves_transferred_output_values():
    decoder = DiskJSONDocument()
    decoder.feed(b'{"secret":"' + b"a" * 100_000 + b'"}')
    value = decoder.finish()
    decoder.close()
    assert value["secret"].byte_length == 100_000
    assert sum(map(len, value["secret"].iter_text_chunks())) == 100_000


def test_partial_nested_document_contains_only_completed_scalars():
    decoder = DiskJSONDocument()
    decoder.feed(
        b'{"hits":{"hits":[{"_id":"one","_source":{"password":"first-secret"}},'
        b'{"_id":"two","_source":{"password":"second-secret","broken":"unfinished'
    )
    with pytest.raises(ValueError):
        decoder.finish()
    value = decoder.partial_value()
    assert [hit["_source"] for hit in value["hits"]["hits"]] == [
        {"password": "first-secret"},
        {"password": "second-secret"},
    ]
    assert decoder.partial_value() is value
    decoder.close()


def test_disk_json_nested_catalog_and_utf8_fragments():
    original = {"items": [{"value": "секрет\r\n" * 10000, "counts": [1, 2, None]}]}
    encoded = json.dumps(original, ensure_ascii=False).encode()
    decoder = DiskJSONDocument()
    for start in range(0, len(encoded), 127):
        decoder.feed(encoded[start : start + 127])
    decoded = decoder.finish()
    assert isinstance(decoded["items"], SpoolingValues)
    assert isinstance(decoded["items"][0]["value"], DiskBackedText)
    assert json.loads("".join(iter_json_chunks(decoded))) == original


@pytest.mark.parametrize("tail", [b'"unterminated', b'{"password":"incomplete', b"[1,"])
def test_disk_json_rejects_incomplete_document(tail):
    decoder = DiskJSONDocument()
    decoder.feed(tail)
    with pytest.raises(ValueError):
        decoder.finish()


def test_nested_catalogs_keep_both_array_levels_on_disk():
    original = {"groups": [{"members": [{"name": f"item-{index}"} for index in range(5000)]}]}
    decoder = DiskJSONDocument()
    encoded = json.dumps(original).encode()
    for start in range(0, len(encoded), 1024):
        decoder.feed(encoded[start : start + 1024])
    decoded = decoder.finish()
    assert isinstance(decoded["groups"], SpoolingValues)
    assert isinstance(decoded["groups"][0]["members"], SpoolingValues)
    assert json.loads("".join(iter_json_chunks(decoded))) == original


def test_broken_array_exposes_only_completed_items_for_partial_recovery():
    decoder = DiskJSONDocument()
    decoder.feed(b'[{"Id":1},{"Id":2,"items":[true,null]},{"Id":3,"value":"unfinished')
    with pytest.raises(ValueError):
        decoder.finish()
    completed = decoder.completed_array()
    assert isinstance(completed, SpoolingValues)
    assert json.loads("".join(iter_json_chunks(completed))) == [{"Id": 1}, {"Id": 2, "items": [True, None]}]


def test_partial_object_is_not_presented_as_a_completed_catalog():
    decoder = DiskJSONDocument()
    decoder.feed(b'{"items":[{"Id":1}],"incomplete":')
    assert decoder.completed_array() is None
