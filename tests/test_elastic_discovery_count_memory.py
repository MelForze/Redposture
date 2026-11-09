"""Elastic intermediate detections, catalogs and spill failures stay bounded."""

from __future__ import annotations

import tracemalloc

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.elastic import discover
from scripts.qa_memory_workload import run_memory_workload


def _check_disk_scalar(count: int) -> dict[str, int]:
    value = DiskBackedText()
    for number in range(count):
        value.append_text(f'password="secret-{number:08d}"\n')
    value.finish()
    tracemalloc.start()
    try:
        detections, complete = discover._analyze_disk_value(value, path="message")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        value.close()
    assert complete and len(detections) == count
    assert detections[0].value == "secret-00000000"
    assert detections[-1].value == f"secret-{count - 1:08d}"
    assert peak < 10_000_000, f"Elastic scalar detections retained {peak} bytes"
    return {"count": count, "peak": peak}


def _check_many_fields(count: int) -> dict[str, int]:
    source = {f"password_{i:08d}": f"secret-{i:08d}" for i in range(count)}
    tracemalloc.start()
    try:
        result = discover.scan_value_tree(
            source, source_kind="document", object_name="logs/one", index="logs", document_id="one"
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert not result.truncated_reasons
    assert len(result.detections) == count
    for i, (detection, location) in enumerate(result.detections):
        assert detection.value == f"secret-{i:08d}" and location.path == f"/password_{i:08d}"
    assert peak < 10_000_000, f"Elastic mapping scan retained {peak} bytes"
    return {"count": count, "peak": peak}


def test_elastic_disk_scalar_spill_under_coverage() -> None:
    _check_disk_scalar(4096)


def test_elastic_disk_scalar_many_detections_do_not_rebuild_one_large_list() -> None:
    run_memory_workload(__file__, "_check_disk_scalar", 50_000)


def test_elastic_many_fields_spill_under_coverage() -> None:
    _check_many_fields(4096)


def test_elastic_many_fields_do_not_retain_normalized_catalog_and_detections() -> None:
    run_memory_workload(__file__, "_check_many_fields", 30_000)


def test_elastic_accumulator_spills_medium_values_before_count_threshold() -> None:
    accumulator = discover.FindingAccumulator()
    location = discover.FindingLocation("document", "logs/one", "/password")
    tracemalloc.start()
    try:
        for i in range(400):
            assert accumulator.add(
                discover.DetectedSecret("Sa7/" * 15_000 + str(i), "password", 90, ("sensitive_field",)), location
            )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(accumulator) == 400
    assert peak < 10_000_000, f"Elastic accumulator retained {peak} bytes"


def test_elastic_finding_prefix_slice_does_not_reload_all_medium_values() -> None:
    accumulator = discover.FindingAccumulator(spill_threshold=1)
    location = discover.FindingLocation("document", "logs/one", "/password")
    for i in range(400):
        accumulator.add(
            discover.DetectedSecret("Sa7/" * 15_000 + str(i), "password", 90, ("sensitive_field",)), location
        )
    tracemalloc.start()
    try:
        prefix = accumulator.findings()[:1]
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(prefix) == 1
    assert peak < 3_000_000, f"Elastic prefix read all findings ({peak} bytes)"


def test_elastic_sqlite_full_preserves_accepted_findings_and_count() -> None:
    accumulator = discover.FindingAccumulator(spill_threshold=1)
    location = discover.FindingLocation("document", "logs/one", "/password")
    for value in ("first-secret", "second-secret"):
        accumulator.add(discover.DetectedSecret(value, "password", 90, ("sensitive_field",)), location)
    db = accumulator._db
    assert db is not None
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    db.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises((OSError, discover.sqlite3.Error)):
        accumulator.add(discover.DetectedSecret("Sa7/" * 20_000, "password", 90, ("sensitive_field",)), location)
    actual = list(accumulator.findings())
    assert len(accumulator) == len(actual) == 2
    assert {item.value for item in actual} == {"first-secret", "second-secret"}


@pytest.mark.parametrize("kind", ["payloads", "candidates"])
def test_elastic_document_ledger_spills_even_without_new_seen_documents(kind) -> None:
    ledger = discover._DocumentLedger()
    ledger.mark_seen(("logs", "one"), False)
    count = 50_000
    tracemalloc.start()
    try:
        for i in range(count):
            if kind == "payloads":
                ledger.add_payload(("logs", "one"), f"version-{i:08d}")
            else:
                assert ledger.add_candidate((f"logs-{i:08d}", "one"))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    if kind == "payloads":
        assert ledger.has_payload(("logs", "one"), f"version-{count - 1:08d}")
    else:
        assert ledger.candidate_count(f"logs-{count - 1:08d}") == 1
        assert not ledger.add_candidate(("logs-00000000", "one"))
    assert ledger.seen(("logs", "one")) is False
    assert peak < 8_000_000, f"Elastic {kind} ledger retained {peak} bytes"


def test_elastic_unicode_medium_values_use_real_memory_size() -> None:
    accumulator = discover.FindingAccumulator()
    location = discover.FindingLocation("document", "logs/one", "/password")
    tracemalloc.start()
    try:
        for i in range(120):
            accumulator.add(
                discover.DetectedSecret("Sa7🔑" * 15_000 + str(i), "password", 90, ("sensitive_field",)), location
            )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(accumulator) == 120
    assert peak < 10_000_000, f"Elastic Unicode accumulator retained {peak} bytes"


def test_elastic_document_ledger_full_preserves_previous_completeness() -> None:
    ledger = discover._DocumentLedger(spill_threshold=1)
    ledger.mark_seen(("logs", "first"), True)
    ledger.mark_seen(("logs", "second"), False)
    db = ledger._db
    assert db is not None
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    db.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises((OSError, discover.sqlite3.Error)):
        ledger.mark_seen(("logs", "a" * 100_000), True)
    assert ledger.seen(("logs", "first")) is True
    assert ledger.seen(("logs", "second")) is False


def test_elastic_engine_finding_write_failure_reports_partial_and_keeps_prefix(monkeypatch) -> None:
    engine = discover.DiscoverEngine(lambda request: pytest.fail("no request needed"))
    original = engine.accumulator.add

    def add(detection, location):
        if detection.value == "second-secret":
            raise OSError("database full")
        return original(detection, location)

    monkeypatch.setattr(engine.accumulator, "add", add)
    engine._process_hit(
        "logs",
        {"_index": "logs", "_id": "one", "_source": {"password_one": "first-secret", "password_two": "second-secret"}},
        candidate=True,
        payload_complete=True,
    )
    assert [f.value for f in engine.accumulator.findings()] == ["first-secret"]
    assert any("storage_failure" in r for r in engine.coverage.truncated_reasons)


def test_elastic_detection_sequence_keeps_membership_copy_and_reverse_after_spill() -> None:
    values = discover._detection_list()
    expected = [discover.DetectedSecret(f"secret-{i}", "password", 90, ("sensitive_field",)) for i in range(1100)]
    values.extend(expected)
    assert values[0] in values
    assert values.copy() == expected
    assert list(reversed(values)) == list(reversed(expected))
    assert values[::-1099] == expected[::-1099]
    assert list(values) == expected
    values.append(discover.DetectedSecret("last-secret", "password", 90, ("sensitive_field",)))
    assert values[-1].value == "last-secret"


@pytest.mark.parametrize("shape", ["tree", "disk"])
def test_elastic_intermediate_storage_failure_returns_completed_prefix(monkeypatch, shape) -> None:
    from redposture_core import discovery_sequences as value_stream
    from redposture_core.discovery_spool import SpoolingRecords

    class LimitedRecords(SpoolingRecords):
        def append(self, value, **kwargs):
            if len(self) >= 2100:
                raise OSError("database full")
            super().append(value, **kwargs)

    monkeypatch.setattr(value_stream, "SpoolingRecords", LimitedRecords)
    count = 2300
    if shape == "tree":
        result = discover.scan_value_tree(
            {f"password_{i:08d}": f"secret-{i:08d}" for i in range(count)},
            source_kind="document",
            object_name="logs/one",
        )
        actual = [d.value for d, _ in result.detections]
        assert result.truncated_reasons == ["storage_failure"]
    else:
        value = DiskBackedText()
        for i in range(count):
            value.append_text(f'password="secret-{i:08d}"\n')
        value.finish()
        try:
            detections, complete = discover._analyze_disk_value(value, path="message")
            assert not complete and detections.incomplete_reason == "storage_failure"
            actual = [d.value for d in detections]
        finally:
            value.close()
    assert actual == [f"secret-{i:08d}" for i in range(2100)]


@pytest.mark.parametrize("kind", ["findings", "documents"])
def test_elastic_owner_closes_sqlite_without_waiting_for_gc(kind) -> None:
    owner: discover.FindingAccumulator | discover._DocumentLedger
    if kind == "findings":
        owner = discover.FindingAccumulator(spill_threshold=1)
        location = discover.FindingLocation("document", "logs/one", "/password")
        for value in ("first-secret", "second-secret"):
            owner.add(discover.DetectedSecret(value, "password", 90, ("sensitive_field",)), location)
    else:
        owner = discover._DocumentLedger(spill_threshold=1)
        owner.mark_seen(("logs", "first"), True)
        owner.mark_seen(("logs", "second"), True)
    db = owner._db
    directory = owner._temporary.name
    del owner
    with pytest.raises(discover.sqlite3.ProgrammingError, match="closed"):
        db.execute("SELECT 1")
    from pathlib import Path

    assert not Path(directory).exists()
