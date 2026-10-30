"""Discovery byte limit is a per-portion bound, not target-wide quota."""

from __future__ import annotations

from types import SimpleNamespace

from redposture_core.data_discovery import _scan_portioned_value, inspect_record
from redposture_core.modules.token_api import ReadBudget
from redposture_core.storage_discovery import DiscoveryCollector


def test_record_scans_later_source_after_first_portion() -> None:
    result = inspect_record(
        "redis",
        {
            "status": "open_no_auth",
            "key_value_entries": [
                {"key": "first", "value": "harmless " * 30},
                {"key": "second", "value": "API_TOKEN=glpat-abcdefghijklmnopqrst"},
            ],
        },
        max_bytes=64,
    )
    assert result["status"] == "complete"
    assert any(finding["type"] == "gitlab_token" for finding in result["findings"])


def test_record_detects_token_split_by_portion_boundary() -> None:
    result = inspect_record(
        "redis",
        {
            "status": "open_no_auth",
            "key_value_entries": [{"key": "log", "value": "safe " * 15 + "glpat-abcdefghijklmnopqrst" + "\n"}],
        },
        max_bytes=64,
    )
    assert result["status"] == "complete"
    assert any(finding["type"] == "gitlab_token" for finding in result["findings"])


def test_timestamped_log_is_not_mistaken_for_truncated_json_array() -> None:
    log = "[2026-09-23T00:00:01+00:00] INFO - api_key=sk_live_RedpostureTaskLogD4w6kP8"
    matches, _size, covered = _scan_portioned_value(log, "$", 65_536)
    assert covered is True
    assert ("stripe_key", "sk_live_RedpostureTaskLogD4w6kP8") in [(match.detector, match.value) for match in matches]


def test_record_keeps_later_finding_after_unscannable_continuous_field() -> None:
    result = inspect_record(
        "redis",
        {
            "status": "open_no_auth",
            "key_value_entries": [{"key": "log", "value": "x" * 200 + "\nAPI_TOKEN=glpat-abcdefghijklmnopqrst\n"}],
        },
        max_bytes=64,
    )
    assert result["status"] == "complete"
    assert any(finding["type"] == "gitlab_token" for finding in result["findings"])


def test_large_neutral_nonuniform_field_does_not_mark_full_read_partial() -> None:
    args = SimpleNamespace(discover_time=30)
    ctx = SimpleNamespace(args=args, host="qa", port=2181)
    collector = DiscoveryCollector("zookeeper", ctx, {"status": "open_no_auth"})
    assert collector.add("znode./rpqa/node0001", {"node0001": '{"note":"ordinary-' + "x" * 500_000 + '"}'})
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert result["findings"] == []


def test_large_secret_named_field_preserves_complete_value() -> None:
    from redposture_core.discovery_values import DiskBackedText

    result = inspect_record("jupyter", {"notebook_contents": {"password": "harmless " * 20}}, max_bytes=64)
    assert result["status"] == "complete"
    assert len(result["findings"]) == 1
    value = result["findings"][0]["value"]
    assert isinstance(value, DiskBackedText)
    assert "".join(value.iter_text_chunks()) == "harmless " * 20


def test_large_json_text_keeps_nested_secret_context_and_completes() -> None:
    result = inspect_record(
        "jupyter",
        {"notebook_contents": {"metadata": '{"secret":"alpha value","padding":"' + "a " * 60 + '"}'}},
        max_bytes=64,
    )
    assert result["status"] == "complete"
    assert not result["partial_reasons"]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["type"] == "generic_secret" and finding["value"] == "alpha value"
    assert finding["object_path"].endswith(".metadata.secret")


def test_storage_collector_continues_after_cumulative_portion_limit() -> None:
    args = SimpleNamespace(discover_max_bytes=64, discover_time=30)
    ctx = SimpleNamespace(args=args, host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    assert collector.add("first", "safe " * 20)
    assert collector.add("second", "API_TOKEN=glpat-abcdefghijklmnopqrst")
    result = collector.result()
    assert result["status"] == "complete"
    assert result["bytes_read"] > 64
    assert any(finding["type"] == "gitlab_token" for finding in result["findings"])


def test_token_api_budget_continues_after_cumulative_portion_limit() -> None:
    from redposture_core.clients.http_api import HttpResponse

    budget = ReadBudget(SimpleNamespace(discover_max_bytes=64, discover_time=30))
    assert budget.consume(HttpResponse(200, b"a" * 40, {}))
    assert budget.consume(HttpResponse(200, b"b" * 40, {}))
    assert budget.allowed()
    assert not budget.partial


def test_token_api_budget_has_no_implicit_ten_thousand_request_stop() -> None:
    budget = ReadBudget(SimpleNamespace(discover_max_bytes=64, discover_time=30))
    budget.calls = 10_000
    assert budget.allowed()


def test_redis_portion_is_a_read_size_not_a_value_limit() -> None:
    import time

    from redposture_core.modules.redis.discovery import RESPStreamReader

    class Socket:
        body = b"$9\r\nlongvalue\r\n$6\r\nsecond\r\n"

        def recv(self, size):
            assert size <= 8
            chunk, self.body = self.body[:size], self.body[size:]
            return chunk

        def gettimeout(self):
            return 1

        def settimeout(self, seconds):
            assert seconds > 0

    reader = RESPStreamReader(Socket(), deadline=time.monotonic() + 30, portion=8)
    kind, raw = reader.read()
    assert kind == "bulk"
    with raw:
        text = raw.text()
        assert "".join(text.iter_text_chunks()) == "longvalue"
        text.close()
    assert reader.read() == ("bulk", b"second")


def test_etcd_reads_next_page_after_first_portion(monkeypatch) -> None:
    import base64
    import json
    import time

    from redposture_core.modules.etcd import actions

    pages = [
        {"kvs": [{"key": base64.b64encode(b"first").decode(), "value": base64.b64encode(b"a").decode()}], "more": True},
        {"kvs": [{"key": base64.b64encode(b"second").decode(), "value": base64.b64encode(b"b").decode()}]},
    ]
    encoded = [json.dumps(page) for page in pages]
    cap = max(len(body.encode()) for body in encoded) + 1
    assert sum(len(body.encode()) for body in encoded) > cap
    calls = []

    def request(_host, _port, _method, _path, _timeout, **kwargs):
        calls.append(kwargs["response_size_cap"])
        return 200, encoded[len(calls) - 1]

    monkeypatch.setattr(actions, "_http_json_request", request)
    budget = actions._EtcdDiscoveryBudget(deadline=time.monotonic() + 30, remaining_bytes=cap)
    values, error = actions._stream_dump_v3_all("qa", 2379, 2, batch=1, delay_ms=0, discovery_budget=budget)
    assert error is None
    assert [item["key"] for item in values] == ["first", "second"]
    assert calls == [cap, cap]


def test_kubeapi_reads_multiple_independent_response_portions(monkeypatch) -> None:
    import time

    from redposture_core.modules.kubeapi import actions

    caps = []

    def api_get(_host, _port, _path, _timeout, **kwargs):
        caps.append(kwargs.get("response_size_cap"))
        return 200, {"items": []}, {actions._KUBE_BODY_BYTES_HEADER: "6"}, None

    monkeypatch.setattr(actions, "_api_get_json", api_get)
    budget = actions.KubeDiscoveryReadBudget(remaining=8, deadline=time.monotonic() + 30)
    kwargs = dict(
        retries=0, use_https=False, insecure=False, ca_file=None, discovery_budget=budget, response_size_cap=8
    )
    for _ in range(2):
        assert actions._api_request_json_with_retries("qa", 6443, "GET", "/api/v1/pods", 2, **kwargs)[0] == 200
    assert caps == [8, 8]
    assert budget.reason() is None


def test_kafka_ui_keeps_response_cap_for_later_requests() -> None:
    import time

    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.kafka.ui import _get, _UiDiscoveryBudget

    class Pool:
        def __init__(self) -> None:
            self.caps = []

        def request(self, _method, _url, **kwargs):
            self.caps.append(kwargs["response_size_cap"])
            return HttpResponse(200, b"a" * 30, {})

    pool = Pool()
    budget = _UiDiscoveryBudget(remaining=40, deadline=time.monotonic() + 30)
    assert _get(pool, "http://qa", "/first", budget=budget).status == 200
    assert _get(pool, "http://qa", "/second", budget=budget).status == 200
    assert pool.caps == [40, 40]
    assert budget.reason is None


def test_elastic_document_budget_accepts_later_portion() -> None:
    from redposture_core.modules.elastic.discover import DiscoverOptions, DiscoveryBudget

    budget = DiscoveryBudget(DiscoverOptions(max_source_bytes=10))
    assert budget.consume_document(6)
    assert budget.consume_document(6)
    assert budget.source_bytes == 12
    assert budget.reasons == []


def test_kafka_broker_reads_second_complete_frame(monkeypatch) -> None:
    from redposture_core.clients import kafka

    chunks = [b"\x00\x00\x00\x06", b"ABCDEF", b"\x00\x00\x00\x06", b"GHIJKL"]
    monkeypatch.setattr(kafka, "_recv_exact", lambda _sock, _length: chunks.pop(0))
    budget = kafka.KafkaDiscoveryReadBudget(remaining=10)
    assert kafka._recv_kafka_frame(object(), budget=budget) == b"ABCDEF"
    assert kafka._recv_kafka_frame(object(), budget=budget) == b"GHIJKL"
    assert not chunks
