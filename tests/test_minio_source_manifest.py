"""A listed object, a fetched body and a denied body are different evidence."""

from __future__ import annotations

import pytest

from redposture_core.clients.minio_api import MinioResponse
from redposture_core.modules.minio.discover import Budget, DiscoverResult, _read_and_scan, discover_secrets
from redposture_core.scheduler import NestedSchedulerCancelled
from tests.test_minio_discover import _Client, _obj


@pytest.mark.parametrize("status", [200, 403])
def test_listed_and_fully_read_objects_are_counted_independently(status):
    result = discover_secrets(_Client({"app.env": (status, b'password="inactive-object!42"')}), [_obj("app.env")])
    rows = {r["id"]: r for r in result.source_manifest.result()}
    assert rows["minio.object_catalog"]["read"] == 1 and rows["minio.object_catalog"]["complete"]
    content = rows["minio.object_contents"]
    assert content["read"] == int(status == 200) and content["denied"] == int(status == 403)
    assert content["complete"] == (status == 200)


def test_transport_cancellation_propagates_and_releases_active_read_budget():
    class Client:
        def get_object_range(self, *args, **kwargs):
            raise NestedSchedulerCancelled("cancel at network boundary")

    budget, result = Budget(max_total_bytes=64, chunk_size=64), DiscoverResult()
    with pytest.raises(NestedSchedulerCancelled):
        _read_and_scan(Client(), _obj("app.env"), budget, result, set(), None)
    assert budget._claimed_bytes == budget._active_claims == 0
    assert not result.coverage_complete
    row = next(r for r in result.source_manifest.result() if r["id"] == "minio.object_contents")
    assert not row["complete"] and row["read"] == 0


def test_empty_object_is_fully_read_without_a_finding_and_repeat_is_fresh():
    for _ in range(2):
        result = discover_secrets(_Client({"empty.env": (200, b"")}), [_obj("empty.env", size=0)])
        row = next(r for r in result.source_manifest.result() if r["id"] == "minio.object_contents")
        assert row["read"] == 1 and row["complete"]
        assert result.coverage_complete and not result.findings


def test_short_truncated_response_is_not_an_eof_delimiter_for_unfinished_secret():
    class Client:
        def get_object_range(self, *args, **kwargs):
            return MinioResponse(206, {}, b'password="inactive-completed!42"\npassword="unfinished', truncated=True)

    result = discover_secrets(Client(), [_obj("app.env")], budget=Budget(chunk_size=1024))
    assert not result.coverage_complete
    assert [f["value"] for f in result.findings] == ["inactive-completed!42"]
