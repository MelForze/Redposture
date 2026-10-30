"""Temporary SQLite storage failures must not erase accepted earlier rows."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from redposture_core.discovery_spool import SpoolingRecords


def test_sqlite_full_preserves_previously_accepted_record() -> None:
    values = SpoolingRecords()
    values.append({"value": "first-completed-secret"})
    db = values._db
    assert db is not None
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    db.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises((sqlite3.Error, OSError)):
        values.append({"value": "Ab0" * 20_000})
    assert list(values) == [{"value": "first-completed-secret"}]


@pytest.mark.parametrize("kind", ["findings", "strings"])
def test_sqlite_full_preserves_previously_accepted_other_spools(kind: str) -> None:
    from redposture_core.discovery_spool import SpoolingFindings, SpoolingStrings

    values = SpoolingFindings() if kind == "findings" else SpoolingStrings()
    first = {"type": "password", "fingerprint": "first", "value": "first-secret"}
    if kind == "findings":
        values.add(first)
    else:
        values.append("first-secret")
    db = values._db
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    db.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises((sqlite3.Error, OSError)):
        if kind == "findings":
            values.add({"type": "password", "fingerprint": "large", "value": "Ab0" * 20_000})
        else:
            values.append("Ab0" * 20_000)
    assert list(values) == ([first] if kind == "findings" else ["first-secret"])
    assert len(values) == 1


def test_frontier_full_keeps_previous_queue_and_claims() -> None:
    from redposture_core.discovery_frontier import DiscoveryFrontier

    with DiscoveryFrontier() as frontier:
        frontier.enqueue("first-source")
        db = frontier._database
        pages = db.execute("PRAGMA page_count").fetchone()[0]
        db.execute(f"PRAGMA max_page_count={pages}")
        with pytest.raises((sqlite3.Error, OSError)):
            frontier.enqueue("a" * 100_000)
        assert frontier.contains("first-source")
        assert frontier.pop() == "first-source"
        assert frontier.pop() is None


def test_frontier_queue_failure_does_not_claim_unqueued_source() -> None:
    from redposture_core.discovery_frontier import DiscoveryFrontier

    with DiscoveryFrontier() as frontier:
        frontier.enqueue("first-source")
        frontier._database.execute(
            "CREATE TRIGGER fail_queue BEFORE INSERT ON queue BEGIN SELECT RAISE(ABORT, 'queue failure'); END"
        )
        with pytest.raises((sqlite3.Error, OSError)):
            frontier.enqueue("retry-source")
        assert not frontier.contains("retry-source")
        frontier._database.execute("DROP TRIGGER fail_queue")
        assert frontier.enqueue("retry-source")
        assert frontier.pop() == "first-source"
        assert frontier.pop() == "retry-source"


@pytest.mark.parametrize("shape", ["text", "json", "mapping", "sequence"])
def test_scan_match_spool_failure_returns_accepted_prefix_as_incomplete(monkeypatch, shape: str) -> None:
    from redposture_core import discovery_matches
    from redposture_core.data_discovery import _scan_portioned_value
    from redposture_core.discovery_values import DiskBackedText

    class LimitedRecords(SpoolingRecords):
        def __init__(self):
            super().__init__()
            self.accepted = 0

        def append(self, value, **kwargs):
            if self.accepted >= 2100:
                raise OSError("disk full")
            super().append(value, **kwargs)
            self.accepted += 1

    monkeypatch.setattr(discovery_matches, "SpoolingRecords", LimitedRecords)
    count = 2300
    fields = {f"password_{i:05d}": f"unique-secret-{i:05d}" for i in range(count)}
    disk = None
    value: Any
    if shape == "text":
        value = "".join(f'password="{v}"\n' for v in fields.values())
    elif shape == "json":
        import json

        disk = DiskBackedText()
        disk.append_text(json.dumps(fields))
        disk.finish()
        value = disk
    elif shape == "mapping":
        value = fields
    else:
        value = [{"password": v} for v in fields.values()]
    try:
        matches, _size, complete = _scan_portioned_value(value, "$", 1024)
        assert not complete
        assert matches.incomplete_reason == "storage_failure"
        assert len(matches) == 2100
        assert [item.value for item in matches] == list(fields.values())[:2100]
    finally:
        if disk is not None:
            disk.close()


def test_storage_collector_spool_full_keeps_completed_findings_and_partial(monkeypatch) -> None:
    from types import SimpleNamespace

    from redposture_core import storage_discovery as storage
    from redposture_core.discovery_spool import SpoolingFindings

    class LimitedFindings(SpoolingFindings):
        def add(self, finding, **kwargs):
            if finding["value"] == "second-secret":
                raise OSError("database full")
            return super().add(finding, **kwargs)

    monkeypatch.setattr(storage, "SpoolingFindings", LimitedFindings)
    monkeypatch.setattr(storage, "FINDING_SPOOL_THRESHOLD", 0)
    context = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = storage.DiscoveryCollector("gitlab", context, {"status": "open_no_auth"})
    assert collector.add("one", {"password": "first-secret"})
    assert not collector.add("two", {"password": "second-secret"})
    assert collector.add("three", {"password": "third-secret"})
    report = collector.result()
    assert report["status"] == "partial"
    assert any("storage_failure" in reason for reason in report["partial_reasons"])
    assert [finding["value"] for finding in report["findings"]] == ["first-secret", "third-secret"]
