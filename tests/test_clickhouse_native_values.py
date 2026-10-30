from __future__ import annotations

import gc
import hashlib
import weakref
from collections.abc import Mapping

import pytest

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_spool import SpoolingValues
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.clickhouse.discover.native_values import NativeValues


def test_native_disk_value_survives_without_retaining_source_tree() -> None:
    owner = NativeValues()
    original = DiskBackedText()
    original.append_text("Sa7-value/" * 10000)
    original.finish()
    node = owner.scalar(original)
    value = owner.view(node)
    source = weakref.ref(owner)
    del owner
    gc.collect()
    assert source() is None
    assert value.path.exists()
    assert value.digest == hashlib.sha256(("Sa7-value/" * 10000).encode()).hexdigest()
    value.close()
    assert not value.path.exists()


def test_native_tree_keeps_container_ownership_across_result_spool() -> None:
    owner = NativeValues()
    values = owner.sequence()
    values.append("password=first-secret")
    record = owner.mapping()
    owner.put(record.node, owner.scalar("config"), values.node)
    rows = SpoolingValues()
    rows.append([record])
    del record, values, owner
    gc.collect()
    restored = rows[0][0]
    assert isinstance(restored, Mapping)
    assert restored["config"] == ["password=first-secret"]
    assert "".join(iter_json_chunks(restored)) == '{"config":["password=first-secret"]}'
    matches, _, complete = _scan_portioned_value(restored, "$", 65536)
    assert complete
    assert [(m.detector, m.value, m.object_path) for m in matches] == [("password", "first-secret", "$.config[0]")]


def test_native_map_duplicates_keep_last_value_and_first_key_position() -> None:
    owner = NativeValues()
    result = owner.mapping()
    for key, value in [("password", "first"), ("note", "ordinary"), ("password", "last")]:
        owner.put(result.node, owner.scalar(key), owner.scalar(value))
    assert list(result.items()) == [("password", "last"), ("note", "ordinary")]
    assert len(result) == 2
    assert result.byte_length == sum(len(x) for x in ("password", "last", "note", "ordinary"))


def test_native_result_reuses_one_tree_reference_for_many_rows() -> None:
    owner = NativeValues()
    value = owner.sequence()
    value.append("ordinary")
    rows = SpoolingValues()
    for _ in range(1000):
        rows.append([value])
    assert len(rows._records._spool_refs) == 1
    assert rows[0][0] == rows[-1][0] == ["ordinary"]


@pytest.mark.parametrize("failure", ["serialization", "insert", "duplicate"])
def test_unaccepted_container_does_not_retain_source_tree(failure) -> None:
    from redposture_core.discovery_spool import SpoolingFindings, SpoolingRecords

    owner = NativeValues()
    child = owner.sequence()
    child.append("ordinary")
    source = weakref.ref(owner)
    result: SpoolingFindings | SpoolingRecords
    if failure == "duplicate":
        result = SpoolingFindings()
        result.add({"type": "password", "fingerprint": "same", "value": "first"})
        assert not result.add({"type": "password", "fingerprint": "same", "value": child})
    else:
        result = SpoolingRecords()
        if failure == "insert":
            result._db.execute(
                "CREATE TRIGGER fail_insert BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'full'); END"
            )
            with pytest.raises(OSError):
                result.append({"child": child})
        else:
            with pytest.raises(TypeError):
                result.append({"child": child, "bad": object()})
    del child, owner
    gc.collect()
    assert source() is None
