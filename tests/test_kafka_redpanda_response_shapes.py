"""Redpanda v2.7.2 API envelope, independently checked against its Go DTOs."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import http_surfaces


class Pool:
    def __init__(self, topics: Any, startup: Any = None, *, status: int = 200):
        self.topics = topics
        self.startup = {"isHttpOk": True, "isKafkaOk": True} if startup is None else startup
        self.status = status

    def request(self, method, url, **kwargs):
        assert method == "GET"
        path = urlsplit(url).path
        value, status = {
            "/": ("<title>Redpanda Console</title>", 200),
            "/admin/startup": (self.startup, 200),
            "/api/topics": (self.topics, self.status),
        }.get(path, ({"message": "not found"}, 404))
        return HttpResponse(status, (value if isinstance(value, str) else json.dumps(value)).encode(), {})


def detect(pool):
    return http_surfaces.detect(pool, "http://qa.invalid:8080", SimpleNamespace(host="qa.invalid", port=8080))


def test_official_topics_envelope_retains_all_topic_names():
    names = [f"billing.invoice.{i:03}-данные" for i in range(201)]
    result = detect(Pool({"topics": [{"topicName": name, "partitionCount": 3} for name in names]}))
    assert result is not None and result["ui_vendor"] == "redpanda_console"
    assert result["anonymous_read"] is True
    assert result["http_inventory"] == names
    output = http_surfaces.collect(result, {"show_topics": True})
    assert [item["name"] for item in output["ui_topics"]] == names
    assert not output.get("ui_topics_partial", False)


@pytest.mark.parametrize("topics", [{"topics": []}, []])
def test_empty_verified_catalogue_is_readable(topics):
    result = detect(Pool(topics))
    assert result is not None and result["anonymous_read"] is True and result["http_inventory"] == []


@pytest.mark.parametrize("startup", [{}, {"version": "1"}, {"isHttpOk": True}, {"isHttpOk": 1, "isKafkaOk": True}])
def test_generic_startup_json_is_not_independent_product_proof(startup):
    assert detect(Pool({"topics": []}, startup)) is None


@pytest.mark.parametrize("topics", [{}, {"message": "forbidden"}, {"topics": "not an array"}, {"topics": [1]}])
def test_arbitrary_topic_object_does_not_prove_anonymous_read(topics):
    result = detect(Pool(topics))
    assert result is not None and result["anonymous_read"] is None
    assert result["http_inventory_partial"] is True


def test_corrupt_item_preserves_completed_names_and_marks_partial():
    result = detect(Pool({"topics": [{"topicName": "first"}, None, {"topicName": "last"}]}))
    assert result is not None and result["http_inventory"] == ["first", "last"]
    assert result["http_inventory_partial"] is True
    assert http_surfaces.collect(result, {"show_topics": True})["ui_topics_partial"] is True


def test_legacy_array_is_retained_without_requiring_new_envelope():
    result = detect(Pool([{"name": "legacy-topic"}]))
    assert result is not None and result["anonymous_read"] is True
    assert result["http_inventory"] == ["legacy-topic"]


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_failed_read_never_becomes_readable_empty_catalogue(status):
    result = detect(Pool({"topics": []}, status=status))
    assert result is not None and result["anonymous_read"] is None
    assert result["http_inventory_partial"] is True


def test_disconnected_broker_does_not_hide_the_console():
    result = detect(Pool({"message": "broker unavailable"}, {"isHttpOk": True, "isKafkaOk": False}, status=500))
    assert result is not None and result["ui_vendor"] == "redpanda_console"
    assert result["anonymous_read"] is None and result["http_inventory_partial"] is True


@pytest.mark.parametrize("count", [0, 3])
def test_catalogue_counts_and_partial_marker_follow_airflow_palette(count, capsys):
    from redposture_core.console import Console
    from redposture_core.modules.kafka import render

    record = detect(Pool({"topics": [{"topicName": f"invoice-{i}"} for i in range(count)]}))
    record = http_surfaces.collect(record, {"show_topics": True})
    lines = render._format_ui_detail_records(record, "txt")
    heading = next(line for line in lines if "Topics Enumeration" in line)
    assert render._render_colored_kafka_line(Console(no_color=False), heading)
    colored = capsys.readouterr().out
    assert "\x1b[1;97mTopics Enumeration" in colored
    color = "1;38;5;196" if count else "1;92"
    assert f"\x1b[{color}mtopics:{count}\x1b[0m" in colored
    assert render._render_colored_kafka_line(Console(no_color=True), heading)
    assert "\x1b" not in capsys.readouterr().out

    partial = http_surfaces.collect(detect(Pool({"message": "unavailable"})), {"show_topics": True})
    line = next(line for line in render._format_ui_detail_records(partial, "txt") if "coverage:partial" in line)
    assert render._render_colored_kafka_line(Console(no_color=False), line)
    assert "\x1b[1;38;5;208mcoverage:partial" in capsys.readouterr().out
    assert "\x1b" not in json.dumps(partial)


@pytest.mark.parametrize("surface", ["redpanda_console", "ksqldb"])
def test_requested_http_metadata_survives_unknown_auth_runtime_gate(surface, monkeypatch):
    from redposture_core.cli_args import parse_args
    from redposture_core.modules.kafka import stage, ui
    from redposture_core.stage_runtime import AuditCommandRunner

    if surface == "redpanda_console":
        record = detect(Pool({"topics": [{"topicName": "retained"}, None]}))
    else:
        record = {
            "is_kafka": True,
            "is_kafka_ui": True,
            "kafka_interface": "http_surface",
            "ui_vendor": "ksqldb",
            "status": "unknown_auth",
            "auth_required": None,
            "http_inventory": [],
            "credential_verification_status": "unavailable",
        }

    def detected(ctx, _state):
        return {**record, "host": ctx.host, "port": ctx.port}

    monkeypatch.setattr(ui, "detect_ui", detected)
    monkeypatch.setattr(stage, "probe_execution", lambda ctx, value, state, execute: value)
    args = parse_args(["kafka", "-t", "http://qa.invalid:19000", "--show-topics", "--no-color"])
    lines = []
    result = AuditCommandRunner(args=args, spec=stage.build_kafka_spec(args), emit_line=lines.append).run_plan(
        stage.build_kafka_plan(args)
    )
    assert len(result.records) == 1
    row = result.records[0]
    assert row["auth_required"] is None and row["status"] == "unknown_auth"
    if surface == "redpanda_console":
        assert row["ui_topics"] == [{"name": "retained"}] and row["ui_topics_partial"] is True
        assert any("coverage:partial" in line for line in lines)
    else:
        assert row["ui_unsupported_actions"] == "topic enumeration is not supported by this HTTP surface"
        assert any("topic enumeration is not supported" in line for line in lines)
