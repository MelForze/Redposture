"""Spools retain shared text sources, not one heavyweight owner per location."""

from __future__ import annotations

import gc
import hashlib
import json
import weakref

import pytest

from redposture_core.discovery_paths import concat_discovery_text, json_discovery_path, path_suffix
from redposture_core.discovery_rendering import iter_disk_discovery_finding_line_chunks
from redposture_core.discovery_spool import SpoolingFindings, SpoolingRecords
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks


def _text(text: str) -> DiskBackedText:
    value = DiskBackedText()
    value.append_text(text)
    value.finish()
    return value


@pytest.mark.parametrize("kind", ["records", "findings"])
def test_many_shared_key_paths_release_original_path_and_small_value_owners(kind: str) -> None:
    spool = SpoolingRecords() if kind == "records" else SpoolingFindings()
    key_text = "long-λ/key~" * 10_000
    key = _text(key_text)
    key_ref = weakref.ref(key)
    path_refs = []
    value_refs = []
    count = 1000
    for number in range(count):
        place = json_discovery_path((key, number, "password"))
        value = _text(f"small-secret-{number:04d}-🔑")
        path_refs.append(weakref.ref(place))
        value_refs.append(weakref.ref(value))
        finding = {"type": "password", "fingerprint": str(number), "value": value, "place": place}
        if kind == "records":
            spool.append(finding)
        else:
            assert spool.add(finding)
    del finding, place, value, key
    gc.collect()

    assert sum(reference() is not None for reference in path_refs) <= 2
    assert sum(reference() is not None for reference in value_refs) <= 2
    assert key_ref() is None, "the arena must release the original shared source owner"
    assert len(spool) == count
    for number in (0, 511, count - 1):
        restored = spool[number]
        expected_place = f"$.{key_text}[{number}].password"
        expected_value = f"small-secret-{number:04d}-🔑"
        assert isinstance(restored["place"], DiskBackedText)
        assert isinstance(restored["value"], DiskBackedText)
        assert restored["place"].digest == hashlib.sha256(expected_place.encode()).hexdigest()
        assert restored["value"].byte_length == len(expected_value.encode())
        encoded = json.loads("".join(iter_json_chunks(restored, max_chars=1024)))
        assert encoded["place"] == expected_place
        assert encoded["value"] == expected_value
        line = "".join(
            iter_disk_discovery_finding_line_chunks(
                "QA", "host", 80, finding_type="password", value=restored["value"], place=restored["place"]
            )
        )
        assert expected_place in line and expected_value in line
    del restored, spool
    gc.collect()
    assert key_ref() is None, "temporary source ownership must end with the spool and restored views"


def test_repeated_large_leaf_uses_bounded_owner_references_and_remains_readable() -> None:
    spool = SpoolingRecords()
    leaf = _text("large-key-" * 12_000)
    source_path = leaf.path
    source_ref = weakref.ref(leaf)
    for number in range(1000):
        spool.append({"place": concat_discovery_text("$.", leaf, f"[{number}]")})
    del leaf
    gc.collect()
    assert len(spool._disk_refs) <= 2, "one shared source must not become 1000 retained owner entries"
    assert source_ref() is None and not source_path.exists()
    restored = spool[-1]["place"]
    assert "".join(restored.iter_text_chunks()) == "$." + "large-key-" * 12_000 + "[999]"
    del spool
    gc.collect()
    assert "".join(restored.iter_text_chunks()) == "$." + "large-key-" * 12_000 + "[999]"
    del restored
    gc.collect()
    assert source_ref() is None and not source_path.exists()


@pytest.mark.parametrize(
    ("text", "placeholder", "uniform"),
    [
        ("", False, False),
        ("XXXX", True, True),
        ("****", True, True),
        (" \t\n ", True, False),
        ("ééé", False, True),
        ('λ🔑\r\n"\\', False, False),
    ],
)
def test_small_spooled_text_retains_scalar_api_without_original_temp_owner(text, placeholder, uniform) -> None:
    spool = SpoolingRecords()
    value = _text(text)
    original_path = value.path
    reference = weakref.ref(value)
    spool.append({"value": value})
    del value
    gc.collect()
    assert reference() is None and not original_path.exists()
    restored = spool[0]["value"]
    assert isinstance(restored, DiskBackedText)
    assert restored.byte_length == len(text.encode())
    assert restored.digest == hashlib.sha256(text.encode()).hexdigest()
    assert restored.obvious_placeholder is placeholder
    assert restored.uniform is uniform
    assert "".join(restored.iter_text_chunks(max_chars=1)) == text
    assert json.loads("".join(restored.iter_json_chunks(max_chars=1))) == text
    assert getattr(restored, "_temporary", None) is None, "reading inline values must not create a temporary file"
    with pytest.raises(ValueError, match="positive"):
        list(restored.iter_text_chunks(max_chars=0))
    with pytest.raises(RuntimeError, match="finished"):
        restored.append_text("more")
    with pytest.raises(RuntimeError, match="finished"):
        restored.finish()
    adopted_path = restored.path
    with adopted_path.open("r", encoding="utf-8", newline="") as reader:
        assert reader.read() == text
    restored.close()
    assert not adopted_path.exists()
    with pytest.raises(RuntimeError, match="closed"):
        list(restored.iter_text_chunks())
    assert "".join(spool[0]["value"].iter_text_chunks()) == text


def test_large_text_keeps_source_lease_and_unicode_sliced_escaped_paths() -> None:
    spool = SpoolingRecords()
    long_value = _text("é" * 2000)
    long_ref = weakref.ref(long_value)
    long_path = long_value.path
    key = _text("é/🔑~" * 20_000)
    pointer = json_discovery_path((key, "password"), source="λ", style="pointer")
    relative = path_suffix(pointer, "λ/")
    place = concat_discovery_text("source:", relative)
    spool.append({"value": long_value, "place": place})
    del long_value, key, pointer, relative, place
    gc.collect()
    assert long_ref() is None and not long_path.exists()
    restored = spool[0]
    expected = "source:" + "é~1🔑~0" * 20_000 + "/password"
    assert restored["place"].byte_length == len(expected.encode())
    assert restored["place"].digest == hashlib.sha256(expected.encode()).hexdigest()
    assert "".join(restored["place"].iter_text_chunks(max_chars=7)) == expected
    assert json.loads("".join(iter_json_chunks(restored))) == {"value": "é" * 2000, "place": expected}


def test_literal_reference_markers_cannot_become_internal_owned_values() -> None:
    spool = SpoolingRecords()
    leaf = _text("a" * 4000)
    spool.append({"value": leaf})
    existing_reference = next(iter(spool._disk_refs), "literal source identity")
    literal = {
        "disk": {"\x00redposture_disk_value": existing_reference},
        "path": {"\x00redposture_path_value": [["literal source", 0, 0]]},
        "inline": {"\x00redposture_inline_value": "literal source"},
        "arena": {"\x00redposture_arena_value": "literal source"},
        "mapping": {"\x00redposture_mapping_value": [["literal", "source"]]},
    }
    spool.append({"value": literal})
    assert spool[1]["value"] == literal


@pytest.mark.parametrize("kind", ["records", "findings"])
def test_failed_spool_write_does_not_pin_encoded_path_or_value_owners(kind: str) -> None:
    spool = SpoolingRecords() if kind == "records" else SpoolingFindings()
    db = spool._db
    table = "records" if kind == "records" else "findings"
    db.execute(f"CREATE TRIGGER fail_insert BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'failed'); END")
    leaf = _text("λ" * 50_000)
    place = concat_discovery_text("$.", leaf, ".password")
    value = _text("small-secret")
    references = [weakref.ref(owner) for owner in (leaf, place, value)]
    finding = {"type": "password", "fingerprint": "failed", "value": value, "place": place}
    with pytest.raises(OSError, match="storage failure"):
        if kind == "records":
            spool.append(finding)
        else:
            spool.add(finding)
    del leaf, place, value, finding
    gc.collect()
    assert all(reference() is None for reference in references)
    assert len(spool) == 0
    assert not spool._disk_refs and not spool._spool_refs


@pytest.mark.parametrize("kind", ["records", "findings"])
def test_many_independent_large_values_release_sources_and_restore_after_spool_gc(kind: str) -> None:
    spool = SpoolingRecords() if kind == "records" else SpoolingFindings()
    references = []
    count = 1000
    for number in range(count):
        text = f"secret-{number:04d}-" + "λ🔑" * 350
        value = _text(text)
        references.append(weakref.ref(value))
        finding = {"type": "password", "fingerprint": str(number), "value": value}
        if kind == "records":
            spool.append(finding)
        else:
            assert spool.add(finding)
    del value, finding
    gc.collect()
    assert all(reference() is None for reference in references)
    assert len(spool._disk_refs) + len(spool._spool_refs) <= 2
    restored = [spool[number]["value"] for number in (0, 511, count - 1)]
    del spool
    gc.collect()
    for number, value in zip((0, 511, count - 1), restored, strict=True):
        expected = f"secret-{number:04d}-" + "λ🔑" * 350
        assert isinstance(value, DiskBackedText)
        assert value.byte_length == len(expected.encode())
        assert value.digest == hashlib.sha256(expected.encode()).hexdigest()
        assert json.loads("".join(iter_json_chunks(value, max_chars=17))) == expected
    restored[0].close()
    assert "".join(restored[-1].iter_text_chunks()) == "secret-0999-" + "λ🔑" * 350


def test_shared_large_source_payload_is_copied_once_into_arena() -> None:
    class ReadOnceText(DiskBackedText):
        def __init__(self) -> None:
            super().__init__()
            self.reads = 0

        def iter_text_chunks(self, *, max_chars=65_536):
            self.reads += 1
            assert self.reads == 1, "a deduplicated long source must not be read again for every path"
            yield from super().iter_text_chunks(max_chars=max_chars)

    spool = SpoolingRecords()
    source = ReadOnceText()
    expected_source = "long-source-λ🔑" * 8000
    source.append_text(expected_source)
    source.finish()
    for number in range(1000):
        spool.append({"place": concat_discovery_text("$.", source, f"[{number}]")})
    assert source.reads == 1
    reference = weakref.ref(source)
    del source
    gc.collect()
    assert reference() is None
    assert "".join(spool[-1]["place"].iter_text_chunks()) == "$." + expected_source + "[999]"


def test_equivalent_large_sources_are_deduplicated_without_reading_second_payload() -> None:
    class UnreadableDuplicate(DiskBackedText):
        def iter_text_chunks(self, *, max_chars=65_536):
            raise AssertionError("identical digest and byte length must reuse the existing arena range")

    spool = SpoolingRecords()
    expected = "duplicate-λ🔑" * 2000
    original = _text(expected)
    spool.append({"value": original})
    duplicate = UnreadableDuplicate()
    duplicate.append_text(expected)
    duplicate.finish()
    spool.append({"value": duplicate})
    reference = weakref.ref(duplicate)
    del duplicate, original
    gc.collect()
    assert reference() is None
    assert "".join(spool[0]["value"].iter_text_chunks()) == expected
    assert "".join(spool[1]["value"].iter_text_chunks()) == expected
