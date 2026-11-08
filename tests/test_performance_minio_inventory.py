"""Inventory must contain the seeded objects, not only an advertised count."""

from copy import deepcopy

import pytest

from scripts import performance_contracts as c


def seeded():
    return {
        "buckets": [
            {"name": n, "creation_date": "2026-01-01T00:00:00Z"}
            for n in ("analytics-reports", "pipeline-artifacts", "audit-backups")
        ],
        "credential_capabilities": {"bucket_count": 3},
    }


def test_complete_seeded_bucket_names_and_metadata_pass():
    assert c.minio_inventory_errors(seeded(), limited=False) == []


@pytest.mark.parametrize("change", ["count_only", "missing", "date", "duplicate", "error", "partial"])
def test_count_only_missing_corrupt_or_partial_inventory_does_not_pass(change):
    row = seeded()
    if change == "count_only":
        row["buckets"] = []
    if change == "missing":
        row["buckets"].pop()
    if change == "date":
        row["buckets"][0]["creation_date"] = "unknown"
    if change == "duplicate":
        row["buckets"][1] = deepcopy(row["buckets"][0])
    if change == "error":
        row["listing_errors"] = ["failure"]
    if change == "partial":
        row["inventory_coverage"] = "partial"
    assert c.minio_inventory_errors(row, limited=False)


def test_limited_access_requires_the_actual_denial_and_unknown_count():
    row = {
        "buckets": [],
        "credential_capabilities": {"bucket_count": None},
        "listing_errors": ["ListBuckets: HTTP 403"],
        "inventory_coverage": "partial",
    }
    assert c.minio_inventory_errors(row, limited=True) == []
    row.pop("listing_errors")
    assert c.minio_inventory_errors(row, limited=True)
    assert c.minio_inventory_errors(seeded(), limited=True)
