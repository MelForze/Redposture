"""Long JSON keys retain exact discovery locations without a key-size cutoff."""

import json
import time
from types import SimpleNamespace

import pytest

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_json import DiskJSONDocument
from redposture_core.discovery_paths import json_discovery_path
from redposture_core.discovery_spool import SpoolingRecords
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.json_stream import DiskJSONKey, JSONScalarStream
from redposture_core.storage_discovery import DiscoveryCollector


def _text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize("length", [4096, 4097, 100_000])
def test_parser_accepts_long_key_and_keeps_ordinary_selectors(length):
    key = "catalog_" + "q" * length
    seen = []
    parser = JSONScalarStream(lambda path, text, final: seen.append((path, text, final)))
    payload = json.dumps({key: "known-secret", "name": "ordinary"}).encode()
    for offset in range(0, len(payload), 127):
        parser.feed(payload[offset : offset + 127])
    parser.finish()
    assert len(seen) == 2
    assert _text(seen[0][0][0]) == key
    assert seen[0][1:] == ("known-secret", True)
    assert isinstance(seen[0][0][0], DiskBackedText)
    assert seen[1] == (("name",), "ordinary", True)


@pytest.mark.parametrize("ensure_ascii", [False, True])
def test_long_escaped_unicode_key_survives_every_byte_boundary(ensure_ascii):
    key = ('ключ/😀"\\\n' * 700) + "password"
    decoder = DiskJSONDocument()
    encoded = json.dumps({key: {"items": ["first", "second"]}}, ensure_ascii=ensure_ascii).encode()
    for byte in encoded:
        decoder.feed(bytes([byte]))
    decoded = decoder.finish()
    decoder.close()
    assert json.loads("".join(iter_json_chunks(decoded))) == {key: {"items": ["first", "second"]}}


@pytest.mark.parametrize("as_disk", [False, True])
def test_secret_under_neutral_long_key_has_full_original_place(as_disk):
    key = "catalog_" + "q" * 100_000
    payload = json.dumps({key: {"items": [{"password": "known-secret"}]}})
    value: str | DiskBackedText
    if as_disk:
        value = DiskBackedText()
        value.append_text(payload)
        value.finish()
    else:
        value = payload
    findings, _size, complete = _scan_portioned_value(value, "$", 65536)
    assert complete
    assert any(
        _text(match.value) == "known-secret" and _text(match.object_path) == "$." + key + ".items[0].password"
        for match in findings
    )


def test_neutral_long_json_key_does_not_turn_plain_value_into_secret():
    payload = json.dumps({"catalog_" + "q" * 100_000: "ordinary value"})
    findings, _size, complete = _scan_portioned_value(payload, "$", 65536)
    assert complete
    assert list(findings) == []


def test_long_secret_key_uses_field_context_and_full_place():
    key = "catalog_" + "q" * 100_000 + "_password"
    findings, _size, complete = _scan_portioned_value(json.dumps({key: "known-secret"}), "$", 65536)
    assert complete
    assert any(_text(match.value) == "known-secret" and _text(match.object_path) == "$." + key for match in findings)


def test_completed_finding_preceding_broken_long_key_is_retained_as_partial():
    payload = '{"password":"known-secret","' + "q" * 100_000 + "\\uD800x"
    findings, _size, complete = _scan_portioned_value(payload, "$", 65536)
    assert not complete
    assert any(_text(match.value) == "known-secret" and _text(match.object_path) == "$.password" for match in findings)


def test_partial_document_excludes_unfinished_long_key():
    decoder = DiskJSONDocument()
    decoder.feed(b'{"password":"known-secret","' + b"q" * 100_000)
    with pytest.raises(ValueError):
        decoder.finish()
    assert decoder.partial_value() == {"password": "known-secret"}
    decoder.close()


def test_array_document_and_record_codec_retain_long_mapping_keys():
    key = "catalog_" + "q" * 100_000
    decoder = DiskJSONDocument()
    decoder.feed(json.dumps([{key: {"password": "known-secret"}}]).encode())
    document = decoder.finish()
    decoder.close()
    rows = SpoolingRecords()
    rows.append({"document": document})
    rows.finish()
    assert json.loads("".join(iter_json_chunks(rows[0]["document"]))) == [{key: {"password": "known-secret"}}]


def test_url_and_pointer_paths_escape_complete_long_key_without_object_repr():
    key = DiskJSONKey()
    original = ('folder/é~"\\' * 1000) + "tail"
    key.append_text(original)
    key.finish()
    assert _text(json_discovery_path((key, 0), "source", style="pointer")) == (
        "source/" + original.replace("~", "~0").replace("/", "~1") + "/0"
    )
    assert _text(json_discovery_path((key,), "source", style="url")) == (
        "source/" + "folder%2F%C3%A9~%22%5C" * 1000 + "tail"
    )


def test_storage_collector_preserves_long_ancestor_and_leaf_places():
    key = "catalog_" + "q" * 100_000
    collector = DiscoveryCollector(
        "vault",
        SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=80),
        {"status": "open_no_auth"},
    )
    encoded = json.dumps({key: [{"password": "known-secret"}]}).encode()
    assert collector.scan_json_chunks("source", (encoded[i : i + 127] for i in range(0, len(encoded), 127)))
    result = collector.result()
    assert result["status"] == "complete"
    assert any(_text(f["object_path"]) == "$.source." + key + "[0].password" for f in result["findings"])


def test_key_spool_failure_keeps_completed_findings_and_marks_storage_partial(monkeypatch):
    def fail(_self, _text):
        raise OSError("key spool unavailable")

    monkeypatch.setattr(DiskJSONKey, "append_text", fail)
    payload = '{"password":"known-secret","' + "q" * 100_000 + '":"ordinary"}'
    findings, _size, complete = _scan_portioned_value(payload, "$", 65536)
    assert not complete
    assert getattr(findings, "incomplete_reason", None) == "storage_failure"
    assert any(_text(f.value) == "known-secret" for f in findings)


def test_expired_deadline_interrupts_key_spooling_and_releases_unfinished_file():
    parser = JSONScalarStream(lambda *_args: None)
    parser.feed(b'{"' + b"q" * 10_000)
    unfinished = parser._key
    assert unfinished is not None
    path = unfinished.path
    parser.deadline = time.monotonic() - 1
    with pytest.raises(TimeoutError, match="discover_time"):
        parser.feed(b"q" * 10_000)
    assert not path.exists()


def test_airflow_collection_preserves_long_nested_json_key():
    from redposture_core.modules.airflow.discover import _StreamedCollectionJSON

    key = "catalog_" + "q" * 100_000
    original = {"variables": [{"key": "app", "value": {key: {"password": "known-secret"}}}]}
    decoder = _StreamedCollectionJSON()
    decoder.parser.feed(json.dumps(original).encode())
    decoder.parser.finish()
    assert json.loads("".join(iter_json_chunks(decoder.value))) == original


def test_qdrant_stream_preserves_long_payload_key_in_place():
    from redposture_core.modules.qdrant.actions import _QdrantSinglePointStream

    key = "catalog_" + "q" * 100_000
    collector = DiscoveryCollector(
        "qdrant",
        SimpleNamespace(args=SimpleNamespace(discover_time=900), host="qa", port=6333),
        {"status": "open_no_auth"},
    )
    stream = _QdrantSinglePointStream(collector, "app", 0)
    stream.parser.feed(
        json.dumps(
            {
                "result": {
                    "points": [{"id": 1, "payload": {key: {"password": "known-secret"}}}],
                    "next_page_offset": None,
                }
            }
        ).encode()
    )
    stream.parser.finish()
    result = collector.result()
    assert result["status"] == "complete"
    assert any(_text(f["value"]) == "known-secret" and key in _text(f["object_path"]) for f in result["findings"])


def test_proxmox_stream_preserves_long_json_key_in_legacy_finding_path():
    from redposture_core.modules.proxmox.discovery import _ResponseScanner

    key = "catalog_" + "q" * 100_000
    stream = _ResponseScanner("/nodes/qa/config", time.monotonic() + 900, None)
    stream.feed(json.dumps({"data": {key: {"password": "known-secret"}}}).encode())
    stream.finish()
    assert any(
        _text(f["sample"]) == "known-secret" and _text(f["path"]) == "$." + key + ".password"
        for f in stream.payload.findings
    )
    assert not stream.payload.partial_reasons
    stream.close()


@pytest.mark.parametrize(
    "suffix,want",
    [("_password", "strong"), ("_token", "medium"), ("_password_id", "excluded"), ("_catalog", "neutral")],
)
def test_elastic_long_key_keeps_its_field_classification(suffix, want):
    from redposture_core.modules.elastic.discover import _disk_field_hint, classify_field

    key = DiskJSONKey()
    key.append_text("catalog_" + "q" * 100_000 + suffix)
    key.finish()
    assert classify_field(_disk_field_hint(key)) == want
    assert classify_field("catalog_" + "q" * 100_000 + suffix) == want


def test_elastic_long_key_pointer_survives_accumulator_disk_storage():
    from redposture_core.modules.elastic.discover import FindingAccumulator, scan_value_tree

    key = "catalog/" + "q" * 100_000 + "~_password"
    decoder = DiskJSONDocument()
    decoder.feed(json.dumps({key: "known-secret"}).encode())
    document = decoder.finish()
    result = scan_value_tree(document, source_kind="document", object_name="app/1")
    accumulator = FindingAccumulator(spill_threshold=1)
    for detection, location in result.detections:
        accumulator.add(detection, location)
    findings = list(accumulator.findings())
    assert any(
        _text(f.value) == "known-secret"
        and _text(f.locations[0].path) == "/" + key.replace("~", "~0").replace("/", "~1")
        for f in findings
    )


def test_spool_codec_preserves_source_mapping_with_its_reserved_marker_name():
    original = {"\x00redposture_mapping_value": [["password", "known-secret"]]}
    rows = SpoolingRecords()
    rows.append({"source": original})
    rows.finish()
    assert rows[0]["source"] == original


@pytest.mark.parametrize("padded_alias", ["field", "value"])
def test_elastic_semantic_aliases_keep_long_punctuation_padded_keys(padded_alias):
    from redposture_core.modules.elastic.discover import scan_value_tree

    padded = "!" * 100_000 + padded_alias + "!" * 10
    original = {
        padded if padded_alias == "field" else "field": "password",
        padded if padded_alias == "value" else "value": "known-secret",
    }
    decoder = DiskJSONDocument()
    decoder.feed(json.dumps(original).encode())
    source = decoder.finish()
    result = scan_value_tree(source, source_kind="document", object_name="app/1")
    expected_path = "/" + (padded if padded_alias == "value" else "value")
    assert any(
        _text(d.value) == "known-secret" and _text(location.path) == expected_path for d, location in result.detections
    )


def test_vault_streamed_dynamic_mount_key_is_preserved_or_explicitly_partial():
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.clients.scoped_http import ScopedHttpClient
    from redposture_core.modules.token_api import ReadBudget
    from redposture_core.modules.vault.actions import _inventory_section

    mount = "catalog_" + "q" * 5000 + "/"
    payload = json.dumps({"data": {mount: {"type": "kv", "options": {"version": "2"}}}}).encode()

    class Pool:
        def request(self, _method, _url, **_kwargs):
            return HttpResponse(200, b'{"data":{', {}, truncated=True)

        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for offset in range(0, len(payload), 127):
                on_chunk(payload[offset : offset + 127])
            return HttpResponse(200, b"", {})

    budget = ReadBudget(SimpleNamespace(discover_time=900))
    rows, status = _inventory_section(
        ScopedHttpClient(Pool(), 65536),
        "http://qa",
        "/v1/sys/mounts",
        None,
        budget,
        stream_large_mounts=True,
    )
    if rows is None:
        assert status == "unknown" and budget.partial
    else:
        assert any(_text(row["path"]) == mount for row in rows)
