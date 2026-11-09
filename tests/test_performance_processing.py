"""The opt-in processing profile has a fixed known corpus and strict quality."""

from __future__ import annotations

import sys
from argparse import Namespace

import pytest

from scripts.profile_processing_performance import (
    CASES,
    FIRST,
    LAST,
    expected_findings,
    measure,
    payload_parts,
    resources,
    verify_findings,
    write_payload,
)


@pytest.mark.parametrize("case", CASES)
def test_processing_payload_is_exact_length_and_reaches_last_secret(tmp_path, case):
    path = tmp_path / "payload"
    name = write_payload(path, case, 10_003)
    data = path.read_bytes()
    prefix, unit, suffix, expected_name = payload_parts(case)
    assert name == expected_name
    assert len(data) == 10_003
    assert data.startswith(prefix) and data.endswith(suffix)
    assert unit in data and FIRST.encode() in data and LAST.encode() in data


def test_processing_payload_rejects_unknown_or_too_short_case(tmp_path):
    with pytest.raises(ValueError, match="unknown processing"):
        write_payload(tmp_path / "payload", "unknown", 1000)
    with pytest.raises(ValueError, match="too short"):
        write_payload(tmp_path / "payload", "xml-dense", 1)


def test_processing_quality_rejects_missing_extra_duplicate_and_wrong_place():
    rows = [
        {"type": "password", "value": value, "place": "$.benchmark/file/runtime/config.xml.password"}
        for value in (FIRST, LAST)
    ]
    assert verify_findings("xml-dense", "runtime/config.xml", rows)
    assert not verify_findings("xml-dense", "runtime/config.xml", rows[:1])
    assert not verify_findings("xml-dense", "runtime/config.xml", rows + rows[:1])
    assert not verify_findings("xml-dense", "runtime/config.xml", rows[::-1])
    for field, wrong in (("type", "token"), ("value", FIRST[:10]), ("place", "$.wrong")):
        changed = [dict(row) for row in rows]
        changed[0][field] = wrong
        assert not verify_findings("xml-dense", "runtime/config.xml", changed)


def test_processing_profile_does_not_fall_back_to_live_core_for_an_empty_snapshot(tmp_path):
    with pytest.raises(ValueError, match="source must contain"):
        measure(Namespace(source=tmp_path))


def test_json_stream_oracle_keeps_both_distinct_paths():
    rows = expected_findings("json-stream", "runtime/config.json")
    assert [r["place"] for r in rows] == [
        "$.benchmark/file/runtime/config.json.head.password",
        "$.benchmark/file/runtime/config.json.tail.password",
    ]
    assert verify_findings("json-stream", "runtime/config.json", rows)
    for field, wrong in (("type", "token"), ("value", "truncated"), ("place", "$.wrong")):
        changed = [dict(row) for row in rows]
        changed[1][field] = wrong
        assert not verify_findings("json-stream", "runtime/config.json", changed)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc resource contract")
def test_disk_sampler_counts_open_unlinked_files_once_and_excludes_foreign_files(tmp_path):
    sample = tmp_path / "sample"
    sample.mkdir()
    visible = sample / "visible"
    visible.write_bytes(b"a" * 13)
    anonymous = sample / "anonymous"
    anonymous.write_bytes(b"b" * 17)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"x" * 101)
    with visible.open("rb"), anonymous.open("rb"), foreign.open("rb"):
        anonymous.unlink()
        assert resources(sample)[2] == 30
    assert resources(sample)[2] == 13
