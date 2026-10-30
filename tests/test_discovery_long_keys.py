from __future__ import annotations

import gc
import hashlib
import json
import weakref
from typing import Any

import pytest

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_rendering import iter_disk_discovery_finding_line_chunks
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.clickhouse.actions import _clickhouse_discovery_place
from redposture_core.modules.clickhouse.discover.native_values import NativeValues
from redposture_core.secret_detection import scan_value


def _disk(text):
    value = DiskBackedText()
    for offset in range(0, len(text), 65536):
        value.append_text(text[offset : offset + 65536])
    value.finish()
    return value


def test_large_native_map_key_keeps_finding_and_complete_path_after_source_cleanup():
    text = "catalog_" + "q" * 100000 + ".end"
    owner = NativeValues()
    mapping = owner.mapping()
    owner.put(mapping.node, owner.scalar(_disk(text)), owner.scalar("password=known-secret"))
    source = weakref.ref(owner)
    matches, _, complete = _scan_portioned_value(mapping, "$", 65536)
    del owner, mapping
    gc.collect()
    assert source() is None
    assert complete
    assert [(m.detector, "".join(m.value.iter_text_chunks())) for m in matches] == [("password", "known-secret")]
    path = matches[0].object_path
    assert isinstance(path, DiskBackedText)
    assert path.digest == hashlib.sha256(("$." + text).encode()).hexdigest()


def test_json_encoder_streams_disk_backed_mapping_key():
    text = "key_" + "q" * 100000
    key = _disk(text)
    assert json.loads("".join(iter_json_chunks({key: "ordinary"}))) == {text: "ordinary"}


def test_disk_finding_writer_keeps_full_disk_place():
    text = "$." + "field/λ" * 20000
    value = _disk("known-secret")
    place = _disk(text)
    line = "".join(
        iter_disk_discovery_finding_line_chunks(
            "CLICKHOUSE", "qa", 9000, finding_type="password", value=value, place=place
        )
    )
    encoded = line.split(" Place=", 1)[1]
    assert json.loads(encoded) == text
    assert "\x1b" not in line


def test_clickhouse_place_keeps_full_disk_object_path():
    text = "$." + "field/λ" * 20000
    place = _clickhouse_discovery_place(
        {"locations": [{"database": "qa", "table": "t", "column": "payload", "object_path": _disk(text)}]}
    )
    assert isinstance(place, DiskBackedText)
    assert place.digest == hashlib.sha256(("qa.t.payload" + text).encode()).hexdigest()


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "apiKey",
        "HTTPAuthToken",
        "clientSecret",
        "token_name",
        "publicKey",
        "accessKeyId",
        "password_hash",
        "hash.note",
        "api.key.id.token",
        "ordinary.password.note",
        "note.session.cookie",
        "note-client-secret-session-password",
        "privateKey",
        "ordinary",
        "nmspcuri",
        "password_contract",
        "paſſword",
        "Σ.password",
        "password.Σ",
        "passwordName",
        "FOOBarPassword",
        "FOOPASSWORDBar",
        "a" * 8190 + "_password",
        "a" * 8191 + "Password",
        "a" * 65530 + "_password_" + "b" * 100,
        "password" + "." * 100000 + "note",
        "hash" + "." * 100000 + "token",
        "PASSWORD" + " " * 100000,
    ],
)
@pytest.mark.parametrize("value", ["qa-field-value", "qR7xN2/pV5tC8+fK3sM9=zD6aL4"])
def test_disk_key_classification_matches_existing_full_key_rules(key, value):
    owner = NativeValues()
    mapping = owner.mapping()
    owner.put(mapping.node, owner.scalar(_disk(key)), owner.scalar(value))
    matches, _, complete = _scan_portioned_value(mapping, "$", 65536)
    expected = {(m.detector, m.value, m.object_path) for m in scan_value({key: value}, object_path="$")}
    actual = {
        (m.detector, "".join(m.value.iter_text_chunks()), "".join(m.object_path.iter_text_chunks())) for m in matches
    }
    assert complete
    assert actual == expected


def test_nested_disk_keys_keep_full_relative_paths_and_values():
    first, second = "outer_" + "a" * 100000, "inner_" + "b" * 100000
    owner = NativeValues()
    inner, outer = owner.mapping(), owner.mapping()
    owner.put(inner.node, owner.scalar(_disk(second)), owner.scalar({"password": "nested-secret"}))
    owner.put(outer.node, owner.scalar(_disk(first)), inner.node)
    matches, _, complete = _scan_portioned_value(outer, "$", 65536)
    assert complete and len(matches) == 1
    assert "".join(matches[0].value.iter_text_chunks()) == "nested-secret"
    assert (
        matches[0].object_path.digest
        == hashlib.sha256(("$." + first + "." + second + ".password").encode()).hexdigest()
    )


def test_long_key_scan_memory_is_independent_of_key_length():
    import tracemalloc

    key = _disk("catalog_" + "q" * 2_000_000)
    owner = NativeValues()
    mapping = owner.mapping()
    owner.put(mapping.node, owner.scalar(key), owner.scalar("password=known-secret"))
    tracemalloc.start()
    try:
        matches, _, complete = _scan_portioned_value(mapping, "$", 65536)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert complete and len(matches) == 1
    assert peak < 4_000_000, peak


def test_joined_path_is_immutable_and_can_be_adopted_as_native_text():
    from redposture_core.discovery_paths import concat_discovery_text, path_suffix

    source = _disk("field/λ" * 20000)
    expected = "$.field/λ" + "field/λ" * 19999
    first = concat_discovery_text("$.", source)
    second = concat_discovery_text("$.", source)
    assert first == second and hash(first) == hash(second)
    assert path_suffix(first, "$.").digest == source.digest
    owner = NativeValues()
    restored = owner.view(owner.scalar(first))
    assert restored.digest == hashlib.sha256(expected.encode()).hexdigest()
    assert "".join(restored.iter_text_chunks()) == expected


def test_resumed_disk_path_does_not_duplicate_same_location():
    from redposture_core.discovery_json import DiskJSONDocument
    from redposture_core.modules.clickhouse.discover.engine import _initial_finding, _scan_rows
    from redposture_core.modules.clickhouse.discover.findings import FindingStore
    from redposture_core.modules.clickhouse.discover.models import ScanChunk

    text = "catalog_" + "q" * 100000
    owner = NativeValues()
    mapping = owner.mapping()
    owner.put(mapping.node, owner.scalar(_disk(text)), owner.scalar("password=known-secret"))
    chunk = ScanChunk("qa", "t", ("payload",), None, 0, 1)
    coverage = {"qa.t.payload": {"rows_scanned": 0, "bytes_scanned": 0}}
    findings = FindingStore()
    assert _scan_rows([[mapping]], chunk, findings, coverage, enabled=("password",), redact=False)
    original = next(iter(findings.values()))
    parser = DiskJSONDocument()
    for part in iter_json_chunks(original):
        parser.feed(part.encode())
    resumed = _initial_finding(parser.finish())
    findings = FindingStore({next(iter(findings)): resumed})
    assert _scan_rows([[mapping]], chunk, findings, coverage, enabled=("password",), redact=False)
    final = next(iter(findings.values()))
    assert len(findings) == final["occurrences"] == final["location_count"] == 1
    assert final["locations"][0]["object_path"].digest == hashlib.sha256(("$." + text).encode()).hexdigest()
    parser.close()


@pytest.mark.parametrize("shape", ["tuple", "array", "map"])
def test_large_composite_native_key_is_scanned_without_materializing_it(shape):
    text = "catalog_" + "q" * 100000
    original = (text, "slot") if shape == "tuple" else [text, "slot"] if shape == "array" else {"section": text}
    owner = NativeValues()
    key: Any
    if shape == "map":
        key = owner.mapping()
        owner.put(key.node, owner.scalar("section"), owner.scalar(_disk(text)))
    else:
        key = owner.sequence(tuple_value=shape == "tuple")
        key.append_node(owner.scalar(_disk(text)))
        key.append("slot")
    mapping = owner.mapping()
    owner.put(mapping.node, key.node, owner.scalar("password=known-secret"))
    matches, _, complete = _scan_portioned_value(mapping, "$", 65536)
    assert complete and len(matches) == 1
    assert "".join(matches[0].value.iter_text_chunks()) == "known-secret"
    assert matches[0].object_path.digest == hashlib.sha256(("$." + repr(original)).encode()).hexdigest()


def test_composite_key_render_obeys_expired_source_deadline():
    import time

    owner = NativeValues()
    key = owner.sequence(tuple_value=True)
    key.append_node(owner.scalar(_disk("q" * 100000)))
    owner.deadline = time.monotonic() - 1
    with pytest.raises(TimeoutError, match="discover_time"):
        owner.display_key(key.node)
