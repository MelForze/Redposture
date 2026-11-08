"""Finding summaries and snapshots must not deserialize every stored value."""

from __future__ import annotations

import gc
from typing import Any

import pytest

from redposture_core.discovery_spool import SpoolingRecords, SpoolingValues
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.clickhouse.discover.findings import FindingStore


def _record(value: Any, *, fingerprint: str, occurrences: int = 1) -> dict[str, Any]:
    return {
        "type": "password",
        "fingerprint": fingerprint,
        "value": value,
        "occurrences": occurrences,
        "locations": [{"row_offset": 7 + offset, "object_path": "$.пароль"} for offset in range(occurrences)],
    }


def test_finding_snapshots_copy_encoded_rows_without_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    store = FindingStore({"one": _record("first", fingerprint="z")})
    store["two"] = _record("second", fingerprint="a")

    def unexpected_decode(_value: Any) -> Any:
        pytest.fail("snapshot must copy existing encoded payloads, not decode/encode them again")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_decode_disk_refs", unexpected_decode)
        added = store.created_after(1)
        ordered = store.sorted_values()
    assert [item["value"] for item in added] == ["second"]
    assert [item["value"] for item in ordered] == ["second", "first"]


def test_finding_occurrence_summary_tracks_replacement_delete_and_failed_write(monkeypatch: pytest.MonkeyPatch) -> None:
    store = FindingStore({"one": _record("first", fingerprint="z", occurrences=2)})
    store["two"] = _record("second", fingerprint="a", occurrences=3)
    store["one"] = _record("updated", fingerprint="z", occurrences=7)
    monkeypatch.setattr(store, "_decode_disk_refs", lambda _value: pytest.fail("must not decode payloads"))
    assert store.occurrence_count() == 10
    del store["two"]
    assert store.occurrence_count() == 7
    pages = store._db.execute("PRAGMA page_count").fetchone()[0]
    store._db.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises(OSError, match="storage failure"):
        store["one"] = _record("Ab0" * 20_000, fingerprint="z", occurrences=99)
    assert store.occurrence_count() == 7
    del store["one"]
    assert store.occurrence_count() == 0


def test_complete_replacement_clears_legacy_missing_location_state():
    incomplete = _record("secret", fingerprint="a", occurrences=2)
    incomplete["locations"] = incomplete["locations"][:1]
    store = FindingStore({"one": incomplete})
    assert store.has_incomplete_locations()
    store["one"] = _record("new-secret", fingerprint="a", occurrences=3)
    assert not store.has_incomplete_locations()
    assert store.occurrence_count() == len(store["one"]["locations"]) == 3


def test_finding_snapshots_own_full_disk_values_and_preserve_reserved_literal_keys() -> None:
    text = "Полный-Sa7/" * 15_000
    value = DiskBackedText()
    value.append_text(text)
    value.finish()
    record = _record(value, fingerprint="a")
    record["extra"] = {"\x00redposture_disk_value": "literal", "nested": ["данные"]}
    store = FindingStore({"one": record})
    ordered = store.sorted_values()
    added = store.created_after(0)
    store["one"] = _record("replaced", fingerprint="a")
    del value, record, store
    gc.collect()
    for snapshot in (ordered, added):
        assert len(snapshot) == 1
        item = snapshot[0]
        assert "".join(item["value"].iter_text_chunks()) == text
        assert item["extra"] == {"\x00redposture_disk_value": "literal", "nested": ["данные"]}
        assert item["locations"] == [{"row_offset": 7, "object_path": "$.пароль"}]


def test_finding_snapshot_keeps_nested_spool_owner_after_source_collection() -> None:
    nested = SpoolingValues()
    nested.extend(["one", "два"])
    record = _record("secret", fingerprint="a")
    record["extra"] = nested
    source = FindingStore({"one": record})
    snapshot = source.sorted_values()
    del source, nested, record
    gc.collect()
    assert list(snapshot[0]["extra"]) == ["one", "два"]


def test_finding_snapshot_detaches_mutable_disk_object_metadata() -> None:
    from redposture_core.discovery_mapping import DiskObjectStore

    metadata = DiskObjectStore().mapping()
    metadata["name"] = "before"
    record = _record("secret", fingerprint="a")
    record["extra"] = metadata
    source = FindingStore({"one": record})
    snapshot = source.sorted_values()
    source["one"]["extra"]["name"] = "after"
    assert snapshot[0]["extra"]["name"] == "before"


def test_encoded_snapshot_failure_is_reported_and_source_stays_readable() -> None:
    class FullRecords(SpoolingRecords):
        def __init__(self) -> None:
            super().__init__()
            db = self._db
            assert db is not None
            pages = db.execute("PRAGMA page_count").fetchone()[0]
            db.execute(f"PRAGMA max_page_count={pages}")

    source = FindingStore({"one": _record("Ab0" * 20_000, fingerprint="a")})
    rows = source._db.execute("SELECT payload FROM findings ORDER BY ordinal")
    with pytest.raises(OSError, match="discovery record storage failure"):
        FullRecords._from_encoded_records((payload for (payload,) in rows), source)
    assert source["one"]["value"] == "Ab0" * 20_000
    assert source.occurrence_count() == 1
