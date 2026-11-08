"""ClickHouse keeps all value locations, including checkpoint/replay boundaries."""

from __future__ import annotations

import gc
import json

import pytest

from redposture_core.discovery_values import iter_json_chunks
from redposture_core.modules.clickhouse.discover.engine import _initial_finding, _scan_rows
from redposture_core.modules.clickhouse.discover.findings import FindingStore
from redposture_core.modules.clickhouse.discover.models import ScanChunk


@pytest.mark.parametrize("disk_store", [False, True])
def test_every_row_location_is_retained_and_replays_do_not_inflate_count(disk_store):
    findings = FindingStore() if disk_store else {}
    coverage = {"qa.items.password": {"rows_scanned": 0, "bytes_scanned": 0}}
    for offset in [*range(160), 159, 0]:
        assert _scan_rows(
            [["inactive-repeated-password"]],
            ScanChunk("qa", "items", ("password",), None, offset, 1),
            findings,
            coverage,
            enabled=("password",),
            redact=False,
        )
    assert len(findings) == 1
    finding = next(iter(findings.values()))
    assert finding["occurrences"] == finding["location_count"] == len(finding["locations"]) == 160
    assert [place["row_offset"] for place in finding["locations"]] == list(range(160))


def test_equal_value_from_different_columns_is_one_finding():
    findings = FindingStore()
    coverage = {
        f"qa.items.{column}": {"rows_scanned": 0, "bytes_scanned": 0} for column in ("password", "client_secret")
    }
    assert _scan_rows(
        [["inactive-same-value", "inactive-same-value"]],
        ScanChunk("qa", "items", ("password", "client_secret"), None, 0, 1),
        findings,
        coverage,
        enabled=("password", "client_secret"),
        redact=False,
    )
    assert len(findings) == 1
    assert {place["column"] for place in next(iter(findings.values()))["locations"]} == {"password", "client_secret"}


def test_checkpoint_style_import_and_export_preserve_large_location_catalog_after_owner_cleanup():
    first = FindingStore()
    coverage = {"qa.items.password": {"rows_scanned": 0, "bytes_scanned": 0}}
    for offset in range(150):
        assert _scan_rows(
            [["inactive-resume-password"]],
            ScanChunk("qa", "items", ("password",), None, offset, 1),
            first,
            coverage,
            enabled=("password",),
            redact=False,
        )
    resumed = FindingStore({key: _initial_finding(row) for key, row in first.items()})
    del first
    gc.collect()
    for offset in (149, 150):
        assert _scan_rows(
            [["inactive-resume-password"]],
            ScanChunk("qa", "items", ("password",), None, offset, 1),
            resumed,
            coverage,
            enabled=("password",),
            redact=False,
        )
    result = resumed.sorted_values()
    del resumed
    gc.collect()
    output = json.loads("".join(iter_json_chunks(result)))
    assert output[0]["location_count"] == len(output[0]["locations"]) == 151
    assert output[0]["value"] == "inactive-resume-password"


def test_legacy_type_keyed_records_merge_and_previously_lost_locations_stay_explicit():
    target = FindingStore()
    for kind, column in (("password", "password"), ("client_secret", "client_secret")):
        target.import_finding(
            "same-value",
            {
                "type": kind,
                "value": "inactive-checkpoint-secret",
                "fingerprint": "same-value",
                "occurrences": 3,
                "locations": [{"column": column, "row_offset": 0}],
            },
        )
    assert len(target) == 1 and target.has_incomplete_locations()
    result = list(target.sorted_values())[0]
    assert result["location_count"] == 2
    assert result["locations_complete"] is False
    assert {p["column"] for p in result["locations"]} == {"password", "client_secret"}
    imported_again = FindingStore({"same-value": result})
    assert imported_again.has_incomplete_locations()
