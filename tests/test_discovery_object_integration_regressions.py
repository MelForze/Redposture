"""Lazy JSON must preserve ordinary output and bound independent document owners."""

from __future__ import annotations

import json

from redposture_core.clients.oracle import json_safe
from redposture_core.discovery_json import DiskJSONDocument
from redposture_core.discovery_spool import SpoolingRecords
from redposture_core.discovery_values import iter_json_chunks


def test_oracle_ordinary_native_json_query_remains_standard_json_serializable():
    value = {"password": "ordinary-secret", "nested": ["first", {"number": 2}]}
    actual = json.loads(json.dumps([{"j": json_safe(value)}]))
    assert actual == [{"j": value}]


def test_oracle_ordinary_native_json_array_remains_standard_json_serializable():
    value = ["first", {"number": 2}]
    actual = json.loads(json.dumps([{"j": json_safe(value)}]))
    assert actual == [{"j": value}]


def test_independent_json_documents_share_bounded_result_ownership():
    records = SpoolingRecords()
    for index in range(30):
        document = DiskJSONDocument()
        document.feed(json.dumps({"offset": index, "headers": {}, "password": f"secret-{index}"}).encode())
        value = document.finish()
        document.close()
        records.append(value)
    assert len(records) == 30
    assert len(records._spool_refs) <= 1, f"retained {len(records._spool_refs)} separate SQLite document owners"
    assert json.loads("".join(iter_json_chunks(records))) == [
        {"offset": index, "headers": {}, "password": f"secret-{index}"} for index in range(30)
    ]


def test_oracle_discovery_dump_renders_bounded_lazy_row_preview():
    from redposture_core.modules.oracle.actions import _format_detail_records

    document = DiskJSONDocument()
    document.feed(b'{"password":"ordinary-secret","neutral":"' + b"v" * 100000 + b'"}')
    value = document.finish()
    document.close()
    for tables in ([], [{"owner": "QA", "table_name": "DOCS"}]):
        record = {
            "host": "qa",
            "port": 1521,
            "tables": tables,
            "rows": [{"schema": "QA", "table": "DOCS", "row": {"j": value}}],
            "content_discovery": {"status": "complete", "findings": []},
        }
        lines = _format_detail_records(record, "txt")
        preview = next(line for line in lines if "QA.DOCS:" in line)
        assert '"password":"ordinary-secret"' in preview
        assert len(preview) < 500
        assert "DiskObject" not in preview and "DiskBacked" not in preview


def test_owned_json_containers_select_streaming_output_without_long_text_fields():
    from redposture_core.discovery_values import contains_disk_backed

    document = DiskJSONDocument()
    document.feed(b'{"ordinary":["first",{"value":"plain"}]}')
    value = document.finish()
    document.close()
    assert contains_disk_backed({"value": value})
    assert json.loads("".join(iter_json_chunks(value))) == {"ordinary": ["first", {"value": "plain"}]}
