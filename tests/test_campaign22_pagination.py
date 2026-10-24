"""Campaign 22: mutable inventories, independent cursors and latest-PIT cleanup."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit
from xml.sax.saxutils import escape

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.minio_api import MinioResponse
from redposture_core.modules.elastic.discover import DiscoverEngine, DiscoverOptions, DiscoverRequest, DiscoverResponse
from redposture_core.modules.kafka import ui
from redposture_core.modules.minio import enumerate as minio_enum
from redposture_core.modules.registry import actions as registry


def _http(value: Any, status: int = 200) -> HttpResponse:
    return HttpResponse(status, json.dumps(value).encode(), {})


@pytest.mark.parametrize("surface,page_size", [("topics", 200), ("consumer-groups", 100)])
@pytest.mark.parametrize("late_fault", [False, True])
def test_kafka_overlapping_inventory_pages_merge_once_per_cluster_and_retain_partial_evidence(
    monkeypatch: pytest.MonkeyPatch, surface: str, page_size: int, late_fault: bool
) -> None:
    calls: list[tuple[str, int]] = []
    field = "name" if surface == "topics" else "groupId"

    def get(pool: Any, base: str, path: str, **kw: Any) -> HttpResponse:
        assert kw["cookie"] == "sid=verified"
        if path == "/api/clusters":
            return _http([{"name": "one", "status": "online"}, {"name": "two", "status": "online"}])
        parsed = urlsplit(path)
        cluster = parsed.path.split("/")[3]
        page = int(parse_qs(parsed.query)["page"][0])
        calls.append((cluster, page))
        assert page <= 3, "mutable pagination must finish at the first short page"
        if cluster == "two":
            return _http([{field: "shared"}])
        if page == 1:
            names = ["shared", *[f"item-{i:04}" for i in range(page_size - 1)]]
        elif page == 2:
            names = [f"item-{i:04}" for i in range(page_size // 2, page_size + page_size // 2)]
            names.reverse()  # page membership/order changes while the inventory is read
        else:
            if late_fault:
                return _http({"error": "denied"}, 403)
            names = ["shared", "tail"]
        return _http([{field: name} for name in names])

    monkeypatch.setattr(ui, "_get", get)
    option = "show_topics" if surface == "topics" else "show_consumer_groups"
    result = ui.collect_ui(
        SimpleNamespace(),
        {"status": "valid_credentials"},
        SimpleNamespace(ui_base="http://qa", ui_http=object(), ui_cookie="sid=verified"),
        {option: True},
    )
    key = "ui_topics" if surface == "topics" else "ui_consumer_groups"
    rows = result[key]
    expected_one = {"shared", *[f"item-{i:04}" for i in range(page_size + page_size // 2)]}
    if not late_fault:
        expected_one.add("tail")
    assert {row["name"] for row in rows if row["cluster"] == "one"} == expected_one
    assert [row for row in rows if row["cluster"] == "two"] == [{"cluster": "two", "name": "shared"}]
    assert len(rows) == len({(row["cluster"], row["name"]) for row in rows})
    assert result[key + "_partial"] is late_fault
    assert calls == [("one", 1), ("one", 2), ("one", 3), ("two", 1)]


@pytest.mark.parametrize("surface", ["catalog", "tags"])
@pytest.mark.parametrize("fault", ["none", "denied", "transport", "invalid"])
def test_registry_reordered_overlapping_pages_keep_union_and_route_credentials_to_original_origin(
    monkeypatch: pytest.MonkeyPatch, surface: str, fault: str
) -> None:
    calls: list[str] = []
    field = "repositories" if surface == "catalog" else "tags"

    def request(host: str, port: int, method: str, path: str, timeout: float, **kw: Any) -> Any:
        assert (host, port, method, kw["headers"]) == ("qa", 5000, "GET", {"Authorization": "Bearer scoped"})
        assert not urlsplit(path).netloc
        calls.append(path)
        assert len(calls) <= 3
        if len(calls) == 3 and fault != "none":
            return {
                "denied": (403, b"{}", {}, None),
                "transport": (0, b"", {}, "reset"),
                "invalid": (200, b"broken", {}, None),
            }[fault]
        rows = [["z", "a"], ["z", "m", "a"], ["m", "tail"]][len(calls) - 1]
        headers = {"link": f'<https://foreign.invalid/next?page={len(calls) + 1}&opaque=a%2Bb>; rel="next"'}
        return 200, json.dumps({field: rows}).encode(), headers if len(calls) < 3 else {}, None

    monkeypatch.setattr(registry, "_http_request", request)
    rows, error = (
        registry._fetch_registry_catalog("qa", 5000, 1, headers={"Authorization": "Bearer scoped"})
        if surface == "catalog"
        else registry._fetch_repository_tags("qa", 5000, "repo", 1, headers={"Authorization": "Bearer scoped"})
    )
    expected = {"a", "m", "tail", "z"} if fault == "none" else {"a", "m", "z"}
    assert rows is not None and set(rows) == expected and len(rows) == len(expected)
    assert error is None if fault == "none" else error and error.startswith("partial:")
    assert calls[1:] == ["/next?page=2&opaque=a%2Bb", "/next?page=3&opaque=a%2Bb"]


def _s3_page(keys: list[str], token: str | None = None) -> MinioResponse:
    items = "".join(f"<Contents><Key>{escape(key)}</Key><Size>1</Size></Contents>" for key in keys)
    more = f"<NextContinuationToken>{escape(token)}</NextContinuationToken>" if token else ""
    return MinioResponse(200, {}, f"<ListBucketResult>{items}{more}</ListBucketResult>".encode())


def test_minio_generator_close_does_not_prefetch_or_spend_next_bucket_budget() -> None:
    calls: list[tuple[str, str | None]] = []

    def listing(bucket: str, **kw: Any) -> MinioResponse:
        calls.append((bucket, kw["continuation_token"]))
        assert len(calls) == 1, "closing a consumer must not fetch the next continuation page"
        return _s3_page(["one", "two"], "next")

    iterator = minio_enum.iter_objects_multi(SimpleNamespace(list_objects_v2=listing), ["first", "later"], limit=5)
    assert next(iterator).key == "one"
    iterator.close()
    assert calls == [("first", None)]


def test_minio_long_token_cycle_is_bounded_and_does_not_poison_next_bucket() -> None:
    calls: list[tuple[str, str | None]] = []
    errors: list[str] = []

    def listing(bucket: str, **kw: Any) -> MinioResponse:
        token = kw["continuation_token"]
        calls.append((bucket, token))
        assert len(calls) <= 4, "a nonconsecutive token cycle must terminate"
        if bucket == "next":
            return _s3_page(["retained"])
        if token is None:
            return _s3_page(["first"], "a+b/=")
        if token == "a+b/=":
            return _s3_page(["second"], "second token")
        return _s3_page(["unverified-cycle-page"], "a+b/=")

    rows = list(
        minio_enum.iter_objects_multi(
            SimpleNamespace(list_objects_v2=listing),
            ["loop", "next"],
            page_size=2,
            on_error=errors.append,
        )
    )
    assert [(row.bucket, row.key) for row in rows] == [("loop", "first"), ("loop", "second"), ("next", "retained")]
    assert errors == ["ListObjects loop: repeated continuation token"]
    assert calls == [("loop", None), ("loop", "a+b/="), ("loop", "second token"), ("next", None)]


@pytest.mark.parametrize("vendor", ["elasticsearch", "opensearch"])
@pytest.mark.parametrize("stop", ["finished", "transport", "budget"])
@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_elastic_rotated_pit_is_used_for_next_page_and_closed_even_after_budget_or_transport_failure(
    vendor: str, stop: str, cleanup_fails: bool
) -> None:
    calls: list[DiscoverRequest] = []
    searches: list[dict[str, Any]] = []

    def request(item: DiscoverRequest) -> DiscoverResponse:
        calls.append(item)
        if item.method == "DELETE":
            if cleanup_fails:
                raise OSError("cleanup reset")
            return DiscoverResponse(200, b'{"succeeded":true}')
        body = json.loads(item.body or b"{}")
        searches.append(body)
        assert len(searches) <= 2
        if len(searches) == 2:
            assert body["pit"]["id"] == "pit-rotated"
            assert body["search_after"] == [101]
            if stop == "transport":
                raise TimeoutError("second page timeout")
            return DiscoverResponse(200, b'{"pit_id":"pit-final","hits":{"hits":[]}}')
        assert body["pit"]["id"] == "pit-original" and "search_after" not in body
        hits = [{"_id": "one", "_index": "logs", "sort": [101], "_source": {"password": "RetainedCampaignPassword"}}]
        if stop == "budget":
            # A second distinct hit proves the one-document limit is exhausted.
            hits.append({"_id": "two", "_index": "logs", "sort": [102], "_source": {"password": "MustNotBeScanned"}})
        return DiscoverResponse(200, json.dumps({"pit_id": "pit-rotated", "hits": {"hits": hits}}).encode())

    engine = DiscoverEngine(
        request, vendor=vendor, options=DiscoverOptions(max_documents=1 if stop == "budget" else 10)
    )
    completed = engine._paginate_pit(
        "logs", {"query": {"match_all": {}}}, candidate=False, pit_id="pit-original", payload_complete=True
    )
    assert completed is (stop != "transport")
    assert [finding.value for finding in engine.accumulator.findings()] == ["RetainedCampaignPassword"]
    assert engine.coverage.documents_scanned == 1
    assert len(searches) == (1 if stop == "budget" else 2)
    cleanup = calls[-1]
    expected_id = "pit-final" if stop == "finished" else "pit-rotated"
    assert cleanup.method == "DELETE"
    assert cleanup.path == ("/_pit" if vendor == "elasticsearch" else "/_search/point_in_time")
    assert json.loads(cleanup.body or b"{}") == (
        {"id": expected_id} if vendor == "elasticsearch" else {"pit_id": [expected_id]}
    )


def test_kafka_full_export_deduplicates_overlapping_cursor_pages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _assert_kafka_cursor_overlap_contract(monkeypatch, tmp_path, full_export=True)


def test_kafka_bounded_dump_deduplicates_overlapping_cursor_pages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _assert_kafka_cursor_overlap_contract(monkeypatch, tmp_path, full_export=False)


def _assert_kafka_cursor_overlap_contract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, full_export: bool
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ui, "_get", lambda *a, **kw: _http([{"name": "cluster", "status": "online"}]))
    cursors: list[str | None] = []

    def read(*a: Any, **kw: Any) -> Any:
        cursors.append(kw["cursor"])
        assert len(cursors) <= 2
        positions = [0, 1] if kw["cursor"] is None else [1, 2]
        messages = [{"partition": 0, "offset": position, "value": f"message-{position}"} for position in positions]
        return messages, True, None, "next" if kw["cursor"] is None else None, True

    monkeypatch.setattr(ui, "_read_ui_messages", read)
    result = ui.collect_ui(
        SimpleNamespace(args=SimpleNamespace()),
        {"status": "valid_credentials"},
        SimpleNamespace(ui_base="http://qa", ui_http=object(), ui_cookie="", ui_vendor="kafbat"),
        {"query_topic": "topic", "dump": True, "ui_dump_all": full_export},
    )
    if full_export:
        assert result["ui_export"]["partial"] is False
        path = tmp_path / result["ui_export"]["path"]
        messages = [json.loads(line)["value"] for line in path.read_text().splitlines()]
    else:
        assert result["ui_dump_partial"] is False
        messages = result["ui_dump_records"][0]["messages"]
    assert [(row["partition"], row["offset"]) for row in messages] == [(0, 0), (0, 1), (0, 2)]
    assert cursors == [None, "next"]
