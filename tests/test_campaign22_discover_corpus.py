"""Exact labelled discovery oracle through scalar scanning and a synthetic backend.

The transport below emulates Elasticsearch responses. It is not a real-server test.
Expected findings are hand-labelled data, never derived from detector output.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from redposture_core.modules.elastic.discover import (
    DiscoverEngine,
    DiscoverOptions,
    DiscoverRequest,
    DiscoverResponse,
    FindingAccumulator,
    scan_value_tree,
)

DATASET = Path(__file__).resolve().parents[1] / "tests/fixtures/campaign22/discover-labelled.json"
CORPUS = json.loads(DATASET.read_text(encoding="utf-8"))


def _expected(records: list[dict[str, Any]]) -> set[tuple[str, str, str, str, str, str, str]]:
    index = CORPUS["index"]
    return {
        (
            entry["secret_type"],
            entry["value"],
            "document",
            f"{index}/{record['id']}",
            index,
            record["id"],
            entry["path"],
        )
        for record in records
        for entry in record["expected"]
    }


def _actual(findings: Any) -> set[tuple[str, str, str, str, str, str, str]]:
    return {
        (finding.secret_type, finding.value, loc.source_kind, loc.object, loc.index, loc.id, loc.path)
        for finding in findings
        for loc in finding.locations
    }


def _assert_exact(actual: set[tuple[str, ...]], expected: set[tuple[str, ...]]) -> None:
    assert actual == expected, {"misses": expected - actual, "unexpected": actual - expected}


@pytest.mark.parametrize("corrupted_field", ["path", "value"])
def test_labelled_oracle_rejects_wrong_location_or_secret_value(corrupted_field: str) -> None:
    record = CORPUS["records"][0]
    scanned = scan_value_tree(
        record["document"],
        source_kind="document",
        object_name=f"{CORPUS['index']}/{record['id']}",
        index=CORPUS["index"],
        document_id=record["id"],
    )
    accumulator = FindingAccumulator()
    for detection, location in scanned.detections:
        accumulator.add(detection, location)
    actual = _actual(accumulator.findings())
    _assert_exact(actual, _expected([record]))
    corrupted = copy.deepcopy(record)
    corrupted["expected"][0][corrupted_field] += "-wrong"
    with pytest.raises(AssertionError):
        _assert_exact(actual, _expected([corrupted]))


@pytest.mark.parametrize("record", CORPUS["records"], ids=lambda item: item["id"])
def test_labelled_scalar_corpus_has_no_misses_extra_findings_or_wrong_locations(record: dict[str, Any]) -> None:
    index = CORPUS["index"]
    scanned = scan_value_tree(
        record["document"],
        source_kind="document",
        object_name=f"{index}/{record['id']}",
        index=index,
        document_id=record["id"],
    )
    accumulator = FindingAccumulator()
    for detection, location in scanned.detections:
        accumulator.add(detection, location)
    assert not scanned.truncated_reasons
    _assert_exact(_actual(accumulator.findings()), _expected([record]))


class LabelledBackendEmulator:
    """PIT pages drawn from the labelled dataset, including empty source objects."""

    def __init__(self, records: list[dict[str, Any]] | None = None) -> None:
        self.records = CORPUS["records"] if records is None else records
        self.requests: list[DiscoverRequest] = []
        self.offsets: list[int] = []

    def __call__(self, request: DiscoverRequest) -> DiscoverResponse:
        self.requests.append(request)
        index = CORPUS["index"]
        value: Any = {}
        if request.path.startswith("/_resolve/"):
            value = {"indices": [{"name": index, "attributes": ["open"]}]}
        elif "/_mapping" in request.path:
            value = {index: {"mappings": {"properties": {}}}}
        elif "/_settings" in request.path and not request.path.startswith(("/_cluster", "/_nodes")):
            value = {index: {"settings": {}}}
        elif "/_pit?" in request.path:
            value = {"id": "campaign22-pit"}
        elif request.path == "/_search":
            body = json.loads(request.body or b"{}")
            assert body["_source"] is True
            assert body["pit"]["id"] == "campaign22-pit"
            offset = body.get("search_after", [0])[0]
            self.offsets.append(offset)
            rows = self.records[offset : offset + body["size"]]
            value = {
                "hits": {
                    "total": {"value": len(self.records), "relation": "eq"},
                    "hits": [
                        {"_index": index, "_id": item["id"], "_source": item["document"], "sort": [offset + n + 1]}
                        for n, item in enumerate(rows)
                    ],
                }
            }
        elif request.method == "DELETE":
            value = {"succeeded": True}
        return DiscoverResponse(200, json.dumps(value, ensure_ascii=False).encode())


def test_labelled_corpus_exact_engine_report_survives_pagination_and_duplicate_values() -> None:
    backend = LabelledBackendEmulator()
    report = DiscoverEngine(backend, options=DiscoverOptions(page_size=3)).run()
    assert report.error is None
    _assert_exact(_actual(report.findings), _expected(CORPUS["records"]))
    assert report.coverage.documents_scanned == len(CORPUS["records"])
    assert report.coverage.to_dict()["complete"] is True
    assert backend.offsets == [0, 3, 6, 9, 12]
    shared = next(item for item in report.findings if item.value == "C22-Shared-Value!")
    assert shared.occurrence_count == 2
    assert backend.requests[-1].method == "DELETE"
    assert backend.requests[-1].path == "/_pit"
    serialized = json.dumps(report.to_dict(), ensure_ascii=False)
    assert "\x1b" not in serialized


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER USER qa IDENTIFIED BY 'C22-Sql-Value!'",
        "CREATE USER qa IDENTIFIED BY 'C22-Sql-Value!'",
    ],
    ids=["alter-user-mysql", "create-user-mysql"],
)
@pytest.mark.parametrize("layer", ["scalar", "engine"])
def test_identified_by_sql_cleartext_secret_recall_limitation(statement: str, layer: str) -> None:
    """Confirmed unsupported-format recall gap; does not assert universal SQL support."""
    record = {
        "id": "identified-by",
        "document": {"body": statement},
        "expected": [
            {"secret_type": "password", "value": "C22-Sql-Value!", "path": "/body"},
        ],
    }
    if layer == "engine":
        report = DiscoverEngine(LabelledBackendEmulator([record]), options=DiscoverOptions(page_size=3)).run()
        assert report.error is None
        assert report.coverage.documents_scanned == 1
        actual = _actual(report.findings)
    else:
        scanned = scan_value_tree(
            record["document"],
            source_kind="document",
            object_name=f"{CORPUS['index']}/identified-by",
            index=CORPUS["index"],
            document_id="identified-by",
        )
        accumulator = FindingAccumulator()
        for detection, location in scanned.detections:
            accumulator.add(detection, location)
        actual = _actual(accumulator.findings())
    _assert_exact(actual, _expected([record]))


@pytest.mark.parametrize("layer", ["scalar", "engine"])
@pytest.mark.parametrize(
    "statement,value",
    [
        ("create user 'qa user'@'localhost' identified by 'C22-quote''value!'", "C22-quote'value!"),
        (r"ALTER USER `qa` IDENTIFIED BY 'C22-quote\'value!'", "C22-quote'value!"),
        ('CREATE USER IF NOT EXISTS qa IDENTIFIED BY "C22-double""value!";', 'C22-double"value!'),
        (r"ALTER USER IF EXISTS qa IDENTIFIED BY 'C22-back\\slash!';", "C22-back\\slash!"),
        ("ALTER\nUSER qa\nIDENTIFIED BY 'C22-space value!';", "C22-space value!"),
    ],
)
def test_identified_by_sql_literals_keep_exact_password_and_origin(statement: str, value: str, layer: str) -> None:
    record = {
        "id": "sql-quoted",
        "document": {"body": statement},
        "expected": [{"secret_type": "password", "value": value, "path": "/body"}],
    }
    if layer == "engine":
        actual = _actual(DiscoverEngine(LabelledBackendEmulator([record])).run().findings)
    else:
        scanned = scan_value_tree(
            record["document"],
            source_kind="document",
            object_name=f"{CORPUS['index']}/sql-quoted",
            index=CORPUS["index"],
            document_id="sql-quoted",
        )
        accumulator = FindingAccumulator()
        for detection, location in scanned.detections:
            accumulator.add(detection, location)
        actual = _actual(accumulator.findings())
    _assert_exact(actual, _expected([record]))


@pytest.mark.parametrize(
    "statement",
    [
        "row IDENTIFIED BY 'C22-Not-A-Password!'",
        "CREATE TABLE qa IDENTIFIED BY 'C22-Not-A-Password!'",
        "RECREATE USER qa IDENTIFIED BY 'C22-Not-A-Password!'",
        "CREATE USER qa UNIDENTIFIED BY 'C22-Not-A-Password!'",
        "CREATE USER qa IDENTIFIED BYPASS 'C22-Not-A-Password!'",
        "CREATE USER qa IDENTIFIED BY 'C22-Not-A-Password!'suffix",
        "CREATE USER qa IDENTIFIED BY 'C22-Unterminated-Value!",
        "CREATE USER qa IDENTIFIED BY '${PASSWORD}'",
        "CREATE USER qa IDENTIFIED BY ''",
        "CREATE USER qa IDENTIFIED BY RANDOM PASSWORD",
        "CREATE USER qa IDENTIFIED WITH mysql_native_password AS 'C22-Hashed-Value!'",
    ],
)
def test_identified_by_sql_requires_account_statement_and_cleartext_literal(statement: str) -> None:
    scanned = scan_value_tree({"body": statement}, source_kind="document", object_name="negative-sql")
    assert scanned.detections == []
