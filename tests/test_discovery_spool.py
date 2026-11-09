"""Disk-backed discovery findings preserve the list and cleanup contracts."""

from __future__ import annotations

import gc
import json
import warnings
from concurrent.futures import ThreadPoolExecutor

import pytest

from redposture_core.discovery_spool import (
    SpoolingFindings,
    SpoolingFingerprints,
    SpoolingRecords,
    SpoolingStrings,
    SpoolingValues,
)
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks


@pytest.mark.parametrize("kind", ["findings", "fingerprints", "names"])
def test_small_spool_prefix_does_not_visit_every_record(monkeypatch, kind) -> None:
    findings = SpoolingFindings()
    for number in range(5):
        findings.add({"type": "password", "fingerprint": str(number), "value": f"secret-{number}"}, emitted=True)
    values = (
        findings
        if kind == "findings"
        else SpoolingFingerprints(findings)
        if kind == "fingerprints"
        else SpoolingStrings(str(i) for i in range(5))
    )
    expected = values[0]
    original = type(values).__iter__
    all_values = list(original(values))
    visited = []

    def counted(self):
        for value in original(self):
            visited.append(value)
            yield value

    monkeypatch.setattr(type(values), "__iter__", counted)
    assert values[:1] == [expected]
    assert len(visited) == 1
    visited.clear()
    assert values[4:1] == []
    assert not visited
    for index in (
        slice(None),
        slice(1, 4, 2),
        slice(None, None, -1),
        slice(4, 0, -2),
        slice(0, None, -1),
        slice(4, 1),
        slice(100, 200),
        slice(-100, 100, 2),
    ):
        assert values[index] == all_values[index]


def test_nested_source_spools_render_after_worker_thread_handoff() -> None:
    values = SpoolingValues()
    values.append("p0@0 " + "q" * 100_000)
    outer = SpoolingRecords()
    outer.append({"topic": "qa", "messages": values})
    with ThreadPoolExecutor(max_workers=1) as pool:
        saved = pool.submit(lambda: json.loads("".join(iter_json_chunks(outer)))).result()
    assert saved == [{"topic": "qa", "messages": ["p0@0 " + "q" * 100_000]}]


def test_source_records_keep_disk_scalar_through_sort_and_json(tmp_path) -> None:
    with DiskBackedText(directory=tmp_path) as value:
        value.append_text("secret-" + "q" * 100_000 + "λ-tail")
        value.finish()
        records = SpoolingRecords()
        records.append({"key": "token", "value": value}, sort_key="b")
        records.append({"key": "first", "value": "small"}, sort_key="a")
        records.finish()
        for restored in (records[1]["value"], list(records)[1]["value"]):
            assert isinstance(restored, DiskBackedText)
            assert (restored.byte_length, restored.digest) == (value.byte_length, value.digest)
        saved = json.loads("".join(iter_json_chunks(records)))
        assert saved[0]["key"] == "first"
        assert saved[1]["value"] == "".join(value.iter_text_chunks())


def test_live_record_spool_index_does_not_prevent_later_appends() -> None:
    records = SpoolingRecords()
    records.append({"name": "first"})
    assert records[0] == {"name": "first"}
    records.append({"name": "second"})
    assert records[1] == {"name": "second"}
    records.finish()
    assert [item["name"] for item in records] == ["first", "second"]


def test_finished_record_spool_closes_short_lived_sqlite_readers() -> None:
    gc.collect()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        records = SpoolingRecords()
        records.append({"name": "first"})
        records.finish()
        assert list(records) == [{"name": "first"}]
        assert records[0] == {"name": "first"}
        del records
        gc.collect()
    assert not [warning for warning in caught if "unclosed database" in str(warning.message)]


def test_unfinished_spool_closes_writer_when_last_reference_is_released() -> None:
    gc.collect()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        records = SpoolingRecords()
        records.append({"name": "first"})
        path = records._path
        del records
        gc.collect()
    assert not path.exists()
    assert not [warning for warning in caught if "unclosed database" in str(warning.message)]


def test_live_record_spool_reads_only_appended_rows_without_sealing() -> None:
    records = SpoolingRecords()
    records.append({"name": "first"})
    records.append({"name": "second"})
    assert list(records.iter_appended(1)) == [{"name": "second"}]
    records.append({"name": "third"})
    assert list(records.iter_appended(2)) == [{"name": "third"}]


def test_record_spool_preserves_order_and_json_without_retaining_rows() -> None:
    spool = SpoolingRecords()
    spool.append({"name": "first", "data": {"key": "secret"}})
    spool.append({"name": "second", "data": {}})
    spool.finish()
    assert len(spool) == 2
    assert spool[0]["name"] == "first"
    assert spool[-1]["name"] == "second"
    assert [item["name"] for item in spool] == ["first", "second"]
    assert spool == json.loads(json.dumps(spool))


def _finding(index: int) -> dict[str, str]:
    return {"type": "token", "fingerprint": f"sha256:{index}", "value": "masked", "object_path": f"$.{index}"}


def test_spool_deduplicates_and_tracks_which_findings_were_emitted() -> None:
    spool = SpoolingFindings()
    assert spool.add(_finding(1)) is True
    assert spool.add(_finding(2), emitted=True) is True
    assert spool.add(_finding(1), emitted=True, merge_emission=True) is False
    spool.finish()
    assert len(spool) == 2
    assert bool(spool)
    assert spool[0] == _finding(1)
    assert spool[-1] == _finding(2)
    assert spool[:] == [_finding(1), _finding(2)]
    assert list(spool.iter_unemitted()) == []
    assert json.loads(json.dumps(spool)) == [_finding(1), _finding(2)]
    fingerprints = spool.emitted_fingerprints()
    assert list(fingerprints) == ["sha256:1", "sha256:2"]
    assert fingerprints[0] == "sha256:1"
    assert json.loads(json.dumps(fingerprints)) == ["sha256:1", "sha256:2"]


def test_spool_retains_disk_backed_finding_without_loading_value(tmp_path) -> None:
    with DiskBackedText(directory=tmp_path) as value:
        value.append_text("glpat-" + "x" * 1_200_000)
        value.finish()
        spool = SpoolingFindings()
        finding = {"type": "token", "fingerprint": value.digest, "value": value, "object_path": "$.token"}
        assert spool.add(finding)
        assert not spool.add(finding)
        spool.finish()
        for restored in (spool[0]["value"], next(iter(spool))["value"]):
            assert isinstance(restored, DiskBackedText)
            assert (restored.byte_length, restored.digest) == (value.byte_length, value.digest)


def test_duplicate_not_emitted_again_does_not_hide_original_pending_finding() -> None:
    spool = SpoolingFindings()
    assert spool.add(_finding(1)) is True
    assert spool.add(_finding(1), emitted=True) is False
    spool.finish()
    assert list(spool.iter_unemitted()) == [_finding(1)]


def test_spool_marks_finding_emitted_only_after_callback_succeeds() -> None:
    spool = SpoolingFindings()
    spool.add(_finding(1))
    spool.mark_emitted("token", "sha256:1")
    spool.finish()
    assert list(spool.iter_unemitted()) == []


def test_spool_list_view_has_truthful_equality_membership_and_copy() -> None:
    spool = SpoolingFindings()
    spool.add(_finding(1))
    spool.finish()
    assert spool == [_finding(1)]
    assert _finding(1) in spool
    assert spool.copy() == [_finding(1)]
    assert "count=1" in repr(spool)


def test_spool_supports_location_identity_and_in_place_redaction() -> None:
    spool = SpoolingFindings()
    first = {**_finding(1), "place": "a", "value": "raw"}
    second = {**_finding(1), "place": "b", "value": "raw"}
    assert spool.add(first, identity=("sha256:1", "a"))
    assert spool.add(second, identity=("sha256:1", "b"))
    assert not spool.add(first, identity=("sha256:1", "a"))
    spool.redact_keys("value")
    assert len(spool) == 2
    assert [item["place"] for item in spool] == ["a", "b"]
    assert all("value" not in item for item in spool)


def test_spooling_strings_preserves_list_and_json_contract() -> None:
    strings = SpoolingStrings(["first", "second"])
    strings.append("third")
    assert len(strings) == 3
    assert strings == ["first", "second", "third"]
    assert strings[1] == "second"
    assert json.loads(json.dumps(strings)) == ["first", "second", "third"]


def test_spool_removes_temporary_database_after_last_reference() -> None:
    spool = SpoolingFindings()
    path = spool._path
    spool.add(_finding(1))
    spool.finish()
    assert path.exists()
    del spool
    gc.collect()
    assert not path.exists()


def test_spooling_values_keeps_nested_disk_values_and_json_shape(tmp_path) -> None:
    from redposture_core.discovery_spool import SpoolingValues
    from redposture_core.discovery_values import DiskBackedText, iter_json_chunks

    value = DiskBackedText(directory=tmp_path)
    value.append_text("qa-full-λ\nvalue")
    value.finish()
    spool = SpoolingValues()
    spool.append([value, None, "ordinary"])
    restored = spool[0][0]
    assert isinstance(restored, DiskBackedText)
    assert (restored.byte_length, restored.digest) == (value.byte_length, value.digest)
    # Small values live in the spool payload; preserving the original temp
    # owner for every scalar would make result-count memory unbounded.
    value.close()
    assert "".join(restored.iter_text_chunks()) == "qa-full-λ\nvalue"
    spool.append(["tail"])
    assert len(spool) == 2
    assert json.loads("".join(iter_json_chunks(spool))) == [["qa-full-λ\nvalue", None, "ordinary"], ["tail"]]


def test_live_record_reverse_window_does_not_finalize_producer() -> None:
    values = SpoolingRecords()
    values.append({"value": 1})
    values.append({"value": 2})
    assert list(values.iter_appended(0, reverse=True)) == [{"value": 2}, {"value": 1}]
    values.append({"value": 3})
    assert list(values.iter_appended(1, reverse=True)) == [{"value": 3}, {"value": 2}]
    assert list(values.iter_appended(1)) == [{"value": 2}, {"value": 3}]


def test_scalar_array_records_skip_reference_reencoding(monkeypatch) -> None:
    records = SpoolingRecords()

    def unexpected(*args):
        pytest.fail("plain scalar arrays entered reference encoder")

    monkeypatch.setattr(records, "_encode_disk_refs", unexpected)
    record = {"value": "exact-secret", "rules": ["sensitive_field", "provider_format"], "span": [0, 12], "empty": []}
    records.append(record)
    assert list(records) == [record]


@pytest.mark.parametrize("shape", ["nested", "disk", "subclass", "marker"])
def test_scalar_array_fast_path_preserves_reference_fallback(shape):
    from redposture_core.discovery_spool import _plain_scalar_record

    class Text(str):
        pass

    value = DiskBackedText()
    value.append_text("retained-secret")
    value.finish()
    try:
        record = {
            "nested": {"items": [{"value": "nested-secret"}]},
            "disk": {"items": [value]},
            "subclass": {"items": [Text("subclass-secret")]},
            "marker": {"\x00redposture_disk_value": ["user-supplied", "text"]},
        }[shape]
        assert not _plain_scalar_record(record)
        records = SpoolingRecords()
        records.append(record)
        actual = list(records)[0]
        if shape == "disk":
            assert actual["items"][0].digest == value.digest
        else:
            assert actual == record
    finally:
        value.close()
