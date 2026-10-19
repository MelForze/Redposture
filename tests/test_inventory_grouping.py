"""Inventory and dump rows stay adjacent within a single target's TXT report."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core import web_panels
from redposture_core.modules.airflow import render as airflow_render
from redposture_core.modules.clickhouse import render as clickhouse_render
from redposture_core.modules.etcd import actions as etcd_actions
from redposture_core.modules.kafka import actions as kafka_actions
from redposture_core.modules.kafka import render as kafka_render
from redposture_core.modules.minio import actions as minio_actions
from redposture_core.modules.minio import enumerate as minio_enumerate
from redposture_core.modules.minio import render as minio_render
from redposture_core.modules.mongodb import render as mongodb_render
from redposture_core.modules.oracle import actions as oracle_actions
from redposture_core.modules.postgres import render as postgres_render
from redposture_core.modules.qdrant import actions as qdrant_actions
from redposture_core.modules.redis import actions as redis_actions
from redposture_core.modules.zookeeper import actions as zookeeper_actions


def _order(lines: list[str], *fragments: str) -> None:
    indexes = [next(i for i, line in enumerate(lines) if fragment in line) for fragment in fragments]
    assert indexes == sorted(indexes), "\n".join(lines)
    assert all("\x1b[" not in line for line in lines)


def test_kafka_broker_topics_and_messages_are_grouped_without_duplicates() -> None:
    record = {
        "host": "h",
        "port": 9092,
        "show_topics": True,
        "dump": True,
        "topics": ["alpha", "beta"],
        "dump_topics": ["alpha", "beta"],
        "dump_results": {"alpha": ["alpha-message"], "beta": ["beta-message"]},
    }
    lines = kafka_actions._format_topics_detail_records(record, "txt")
    _order(lines, " alpha", "alpha-message", " beta", "beta-message")
    assert sum("alpha-message" in line for line in lines) == 1
    assert len(kafka_actions._format_topics_detail_records(record, "json")) >= 2


def test_kafka_ui_topics_and_messages_are_grouped_without_duplicates() -> None:
    record = {
        "host": "h",
        "port": 8080,
        "is_kafka_ui": True,
        "show_topics": True,
        "dump": True,
        "ui_topics": [{"cluster": "qa", "name": "alpha"}, {"cluster": "qa", "name": "beta"}],
        "ui_dump_records": [
            {"cluster": "qa", "topic": "alpha", "messages": [{"partition": 0, "offset": 1, "value": "A"}]},
            {"cluster": "qa", "topic": "beta", "messages": [{"partition": 0, "offset": 2, "value": "B"}]},
        ],
    }
    lines = kafka_render._format_ui_detail_records(record, "txt")
    _order(lines, " qa/alpha", "value:A", " qa/beta", "value:B")
    assert sum("value:A" in line for line in lines) == 1
    assert kafka_render._format_ui_detail_records(record, "json") == []


@pytest.mark.parametrize(
    "render",
    [postgres_render._format_grouped_table_detail_records, clickhouse_render._format_grouped_table_detail_records],
)
def test_table_inventory_groups_rows_and_preserves_show_limit(
    render: Callable[[dict[str, Any], str], list[str]],
) -> None:
    record = {
        "host": "h",
        "port": 1,
        "show_tables": True,
        "table_names": ["alpha", "beta"],
        "show_tables_limit": 1,
        "table_dump_enabled": True,
        "table_dumps": [{"table": "alpha", "rows": ["first-row"]}, {"table": "beta", "rows": ["second-row"]}],
    }
    lines = render(record, "txt")
    _order(lines, " alpha", "first-row", "Dump Table beta", "second-row")
    assert sum("first-row" in line for line in lines) == 1
    assert len(render(record, "json")) == 3


@pytest.mark.parametrize(
    "render", [redis_actions._format_keys_detail_records, etcd_actions._format_keys_detail_records]
)
def test_key_inventory_groups_values(render: Callable[[dict[str, Any], str], list[str]]) -> None:
    record = {
        "host": "h",
        "port": 1,
        "show_keys": True,
        "dump_keys": True,
        "keys": ["alpha", "beta"],
        "key_value_entries": [
            {"key": "alpha", "value": "first"},
            {"key": "beta", "value": "second"},
        ],
    }
    lines = render(record, "txt")
    _order(lines, " alpha", "first", " beta", "second")
    assert sum("first" in line for line in lines) == 1
    assert len(render(record, "json")) == 2


def test_mongodb_collections_group_documents_and_json_remains_structured() -> None:
    record = {
        "host": "h",
        "port": 27017,
        "database_names": ["db"],
        "collections": [
            {"database": "db", "collection": "alpha", "documents": 1},
            {"database": "db", "collection": "beta", "documents": 1},
        ],
        "documents": [
            {"database": "db", "collection": "alpha", "document": {"value": "first"}},
            {"database": "db", "collection": "beta", "document": {"value": "second"}},
        ],
    }
    lines = mongodb_render._format_grouped_inventory_detail_records(record, "txt")
    _order(lines, "db.alpha (", 'db.alpha:{"value":"first"}', "db.beta (", 'db.beta:{"value":"second"}')
    assert [
        json.loads(line)["type"] for line in mongodb_render._format_grouped_inventory_detail_records(record, "json")
    ] == ["databases", "collections", "documents_dump"]


def test_zookeeper_znodes_group_values_even_when_path_contains_colon() -> None:
    record = {
        "host": "h",
        "port": 2181,
        "show_znodes": True,
        "dump": True,
        "znode_details": [{"path": "/a:x", "state": "readable"}, {"path": "/b", "state": "readable"}],
        "znode_values": ["/a:x:first", "/b:second"],
    }
    lines = zookeeper_actions._format_znodes_detail_records(record, "txt")
    _order(lines, " /a:x", "/a:x:first", " /b", "/b:second")
    assert sum("/a:x:first" in line for line in lines) == 1


def test_keeper_targeted_znode_dump_follows_matching_inventory_entry() -> None:
    record = {
        "host": "h",
        "port": 9181,
        "show_znodes": True,
        "dump": True,
        "znode_details": [{"path": "/a", "state": "readable"}, {"path": "/b", "state": "readable"}],
        "query_znode": "/a",
        "query_znode_value": "metadata",
        "query_znode_dump": "content",
    }
    lines = zookeeper_actions._format_znodes_detail_records(record, "txt")
    _order(lines, " /a", "Znode /a", "content", " /b")
    assert sum("Dump Znode /a" in line for line in lines) == 1


@pytest.mark.parametrize(
    ("product", "inventory", "fragments"),
    [
        (
            "minio_console",
            {
                "show_buckets": {"count": 1, "items": ["bucket"]},
                "show_objects": {"count": 2, "items": ["bucket/a", "bucket/b"]},
                "dump": {
                    "count": 2,
                    "records": [
                        {"object": "bucket/a", "content": "first"},
                        {"object": "bucket/b", "content": "second"},
                    ],
                },
            },
            (" bucket", " bucket/a", "first", " bucket/b", "second"),
        ),
        (
            "mongo_express",
            {
                "show_databases": {"count": 1, "items": ["db"]},
                "show_collections": {"count": 1, "items": ["db/alpha"]},
                "dump": {"count": 1, "records": [{"collection": "db/alpha", "content": {"v": 1}}]},
            },
            (" db", " db/alpha", '"v": 1'),
        ),
        (
            "pgadmin",
            {
                "show_databases": {"count": 1, "items": ["server/db"]},
                "show_tables": {"count": 1, "items": ["server/db/public/alpha"]},
                "dump": {"count": 1, "records": [{"table": "server/db/public/alpha", "row": [1]}]},
            },
            (" server/db", " server/db/public/alpha", "[1]"),
        ),
    ],
)
def test_ui_inventory_groups_resource_values(product: str, inventory: dict, fragments: tuple[str, ...]) -> None:
    record = {"host": "h", "port": 1, "ui_product": product, "ui": {"inventory": inventory}}
    lines = web_panels.render_panel(record, "TEST")
    _order(lines, *fragments)
    assert sum("\x1b[" in line for line in lines) == 0
    assert "\x1b[" not in json.dumps(record)


def test_airflow_inventory_groups_dump_without_delaying_discovery() -> None:
    record = {
        "host": "h",
        "port": 8080,
        "show_dags_requested": True,
        "show_keys_requested": True,
        "dag_ids": ["alpha"],
        "variable_keys": ["key"],
        "dump_requested": True,
        "dump_report": {
            "status": "complete",
            "records": [
                {"kind": "dag", "id": "alpha", "data": {}},
                {"kind": "variable", "id": "key", "data": {"value": "secret"}},
            ],
        },
    }
    lines = airflow_render._format_grouped_inventory_records(record, "txt")
    _order(lines, "DAG Id=", "dag Id=", "Variable Name=", "variable Id=")
    record["discover_requested"] = True
    streamed = airflow_render._format_grouped_inventory_records(record, "txt")
    assert any("Airflow Dump" in line for line in streamed)


def test_oracle_tables_group_dump_rows() -> None:
    record = {
        "host": "h",
        "port": 1521,
        "tables": [{"owner": "QA", "table_name": "ALPHA"}, {"owner": "QA", "table_name": "BETA"}],
        "rows": [
            {"schema": "QA", "table": "ALPHA", "row": {"value": "first"}},
            {"schema": "QA", "table": "BETA", "row": {"value": "second"}},
        ],
    }
    lines = oracle_actions._format_detail_records(record, "txt")
    _order(lines, "QA.ALPHA rows=", 'QA.ALPHA:{"value":"first"}', "QA.BETA rows=", 'QA.BETA:{"value":"second"}')


def test_qdrant_collections_group_dump_and_retain_partial_failure() -> None:
    record = {
        "host": "h",
        "port": 6333,
        "show_collections": True,
        "dump": True,
        "collections": ["alpha", "beta"],
        "collections_count": 2,
        "collection_dump_items": [
            {"name": "alpha", "ok": True, "info_raw": '{"points_count":1}'},
            {"name": "beta", "ok": False, "error": "denied", "status": 403},
        ],
    }
    lines = qdrant_actions._format_detail_records(record, "txt")
    _order(lines, " alpha", "Collection (name:alpha)", " beta", "collection dump failed name=beta")
    assert sum("Collection (name:alpha)" in line for line in lines) == 1
    assert len(qdrant_actions._format_detail_records(record, "json")) == 2


def test_minio_object_stream_groups_buckets_objects_and_dumps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        minio_enumerate,
        "iter_buckets",
        lambda _client: [minio_enumerate.BucketInfo(name="alpha"), minio_enumerate.BucketInfo(name="beta")],
    )
    monkeypatch.setattr(
        minio_enumerate,
        "iter_objects_multi",
        lambda _client, _buckets: iter(
            [
                minio_enumerate.ObjectInfo(bucket="alpha", key="one", size=1),
                minio_enumerate.ObjectInfo(bucket="beta", key="two", size=1),
            ]
        ),
    )
    monkeypatch.setattr(minio_actions, "_client_for", lambda *_args: object())

    def object_op(_client: object, merged: dict, **_kwargs: object) -> None:
        merged["object_dumps"] = [
            {"bucket": "alpha", "key": "one", "content": "first", "size": 5},
            {"bucket": "beta", "key": "two", "content": "second", "size": 6},
        ]
        merged["object_dumps_labeled"] = True

    monkeypatch.setattr(minio_actions, "_run_object_op", object_op)
    ctx = SimpleNamespace(
        host="h",
        port=9000,
        credential=SimpleNamespace(username="a", password="b"),
        args=SimpleNamespace(show_buckets=True, show_objects=True, dump=True, output_format="txt"),
    )
    record = minio_actions.data_record(ctx, {"detection_status": "confirmed"})
    path = record["_stream_lines_file"]
    try:
        streamed = open(path, encoding="utf-8").read().splitlines()
        _order(streamed, " alpha", "alpha/one", "first", " beta", "beta/two", "second")
        static = minio_render._format_minio_detail_records(record, "txt")
        assert not any("first" in line or "second" in line for line in static)
        assert record["objects_count"] == 2
    finally:
        os.remove(path)
