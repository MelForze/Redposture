"""SDK cursor completion and catalog access are distinct from secret count."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients.mongodb import MongoAuditClient, MongoAuthError
from redposture_core.modules.mongodb.actions import _collect_mongodb_data
from redposture_core.scheduler import NestedSchedulerCancelled
from redposture_core.storage_discovery import DiscoveryCollector


def attempt(*, denied=None, cancel=False, explicit=False):
    emitted, calls, cursors = [], [], []

    class Cursor:
        closed = False

        def batch_size(self, size):
            return self

        def __iter__(self):
            if denied == "documents":
                raise MongoAuthError("not authorized")
            yield {"password": "inactive-first!42"}
            yield {"password": "inactive-second!42"}

        def close(self):
            self.closed = True

    class Collection:
        def find(self, *args):
            calls.append("find")
            cursor = Cursor()
            cursors.append(cursor)
            return cursor

    class DB:
        def list_collection_names(self):
            calls.append("catalog")
            if denied == "catalog":
                raise MongoAuthError("not authorized")
            return ["one"]

        def __getitem__(self, name):
            return Collection()

    class Raw:
        def __getitem__(self, name):
            return DB()

    c = DiscoveryCollector(
        "mongodb",
        SimpleNamespace(
            host="qa",
            port=27017,
            args=SimpleNamespace(discover_time=30),
            live_emit=emitted.extend,
            cancelled=lambda: cancel and bool(emitted),
        ),
        {"status": "valid_credentials"},
    )
    kwargs: dict[str, Any] = dict(
        database_names=["qa"],
        selected_database="qa",
        collection_targets=["one"] if explicit else [],
        collection_targets_by_database={"qa": ["one"]} if explicit else {},
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        dump_documents=True,
        dump_limit=None,
        query_filter=None,
        projection=None,
        discovery_collector=c,
    )
    if cancel:
        with pytest.raises(NestedSchedulerCancelled):
            _collect_mongodb_data(MongoAuditClient(Raw()), **kwargs)
        result = {"content_discovery": c.result()}
    else:
        result = _collect_mongodb_data(MongoAuditClient(Raw()), **kwargs)
    return result["content_discovery"], calls, cursors, emitted


@pytest.mark.parametrize("denied", [None, "catalog", "documents"])
def test_database_collection_and_document_sources_use_actual_sdk_evidence(denied):
    result, calls, cursors, emitted = attempt(denied=denied)
    rows = {r["id"]: r for r in result["sources"]}
    assert rows["mongodb.database_catalog"]["read"] == 1
    for kind, denied_kind in (("collection_catalog", "catalog"), ("document_streams", "documents")):
        row = rows["mongodb." + kind]
        if denied == "catalog" and kind == "document_streams":
            assert row["requested"] == 0
        else:
            assert row["read"] == int(denied != denied_kind)
            assert row["denied"] == int(denied == denied_kind)
            assert row["complete"] == (denied != denied_kind)
    if denied is None:
        assert result["status"] == "complete" and len(emitted) == 2
    else:
        assert result["status"] != "complete" and not result["findings"]
    assert all(cursor.closed for cursor in cursors)


def test_explicit_collection_does_not_claim_list_collection_names_was_called():
    result, calls, _, _ = attempt(explicit=True)
    row = next(r for r in result["sources"] if r["id"] == "mongodb.collection_catalog")
    assert row["requested"] == 0 and "catalog" not in calls


def test_cancel_is_propagated_even_for_the_last_collection_and_repeat_is_fresh():
    result, calls, cursors, emitted = attempt(cancel=True)
    assert result["status"] == "partial" and len(emitted) == 1
    assert [f["value"] for f in result["findings"]] == ["inactive-first!42"]
    row = next(r for r in result["sources"] if r["id"] == "mongodb.document_streams")
    assert not row["complete"] and all(cursor.closed for cursor in cursors)
    for _ in range(2):
        result, _, cursors, emitted = attempt()
        assert result["status"] == "complete" and len(emitted) == 2
        assert {f["value"] for f in result["findings"]} == {"inactive-first!42", "inactive-second!42"}
        assert all(cursor.closed for cursor in cursors)
