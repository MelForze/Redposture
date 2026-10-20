"""DAG-source inventory and explicit read-only source dumps for both APIs."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.console import Console
from redposture_core.modules.airflow import actions, discover, policy, render
from redposture_core.scheduler import NestedSchedulerCancelled


def response(data, status=200, **kwargs):
    return AirflowResponse(
        http_status=status, body=json.dumps(data).encode(), headers={"Content-Type": "application/json"}, **kwargs
    )


class Client:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, path, **kwargs):
        self.calls.append((path, kwargs))
        return self.responses.get(path, response({}, 404))


def test_cli_source_inventory_and_selector_parse_and_order(capsys):
    args = parse_args(
        ["airflow", "-t", "localhost", "--show-dagsources", "--dagsource", "token", "--dagsource", "other", "--dump"]
    )
    assert args.show_dagsources is True
    assert args.dagsource == ["token", "other"]
    with pytest.raises(SystemExit):
        parse_args(["airflow", "-h"])
    help_text = capsys.readouterr().out.split("Discovery:", 1)[1]
    assert (
        help_text.index("--show-dags")
        < help_text.index("--show-dagsources")
        < help_text.index("--dagsource")
        < help_text.index("--show-keys")
    )


def test_selector_requires_source_inventory_or_dump_and_is_nonempty(capsys):
    assert policy.validate_args(SimpleNamespace(dagsource=["token"]), Console()) == 2
    assert policy.validate_args(SimpleNamespace(dagsource=[""], dump=True), Console()) == 2
    assert policy.validate_args(SimpleNamespace(dagsource=["token"], show_dagsources=True), Console()) is None


def test_inventory_deduplicates_tokens_across_dags_without_reading_source():
    client = Client(
        {
            "/api/v1/dags?limit=100&offset=0": response(
                {
                    "dags": [
                        {"dag_id": "a", "file_token": "shared", "fileloc": "/dags/shared.py"},
                        {"dag_id": "b", "file_token": "shared", "fileloc": "/dags/shared.py"},
                    ],
                    "total_entries": 2,
                }
            )
        }
    )
    report = discover.list_dag_sources(client, "v1")
    assert report["status"] == "complete"
    assert report["sources"] == [
        {"source_id": "shared", "file_token": "shared", "fileloc": "/dags/shared.py", "dag_ids": ["a", "b"]}
    ]
    assert [p for p, _ in client.calls] == ["/api/v1/dags?limit=100&offset=0"]


def test_inventory_pages_all_dags_and_falls_back_to_details():
    client = Client(
        {
            "/api/v1/dags?limit=100&offset=0": response(
                {"dags": [{"dag_id": str(i), "file_token": "same"} for i in range(100)], "total_entries": 101}
            ),
            "/api/v1/dags?limit=100&offset=100": response({"dags": [{"dag_id": "last"}], "total_entries": 101}),
            "/api/v1/dags/last/details": response({"file_token": "last-token", "fileloc": "/dags/last.py"}),
        }
    )
    report = discover.list_dag_sources(client, "v1")
    assert report["status"] == "complete"
    assert len(report["sources"]) == 2
    assert len(report["sources"][0]["dag_ids"]) == 100
    assert report["sources"][1]["source_id"] == "last-token"


def test_v2_inventory_uses_dag_id_even_for_same_path():
    client = Client(
        {
            "/api/v2/dags?limit=100&offset=0": response(
                {
                    "dags": [{"dag_id": "a", "fileloc": "same.py"}, {"dag_id": "b", "fileloc": "same.py"}],
                    "total_entries": 2,
                }
            )
        }
    )
    report = discover.list_dag_sources(client, "v2")
    assert [r["source_id"] for r in report["sources"]] == ["a", "b"]
    assert all(r["file_token"] is None for r in report["sources"])


def test_selected_inventory_filters_known_sources_and_marks_missing():
    client = Client(
        {
            "/api/v1/dags?limit=100&offset=0": response(
                {"dags": [{"dag_id": "a", "file_token": "a"}, {"dag_id": "b", "file_token": "b"}], "total_entries": 2}
            )
        }
    )
    report = discover.list_dag_sources(client, "v1", source_ids=["b", "missing"])
    assert [r["source_id"] for r in report["sources"]] == ["b"]
    assert report["status"] == "partial"
    assert "source_not_listed:missing" in report["partial_reasons"]


@pytest.mark.parametrize("generation", ["v1", "v2"])
def test_explicit_source_dump_needs_no_dag_listing(generation):
    client = Client({f"/api/{generation}/dagSources/token%2F%2B": response({"content": 'print("full source")\n'})})
    report = discover.dump_airflow(client, generation, sources=["token/+", "token/+"])
    assert report["status"] == "complete"
    assert report["records"] == [{"kind": "dag_source", "id": "token/+", "source": 'print("full source")\n'}]
    assert [p for p, _ in client.calls] == [f"/api/{generation}/dagSources/token%2F%2B"]


def test_dump_all_sources_reuses_inventory_and_never_reads_other_collections():
    inventory = {
        "status": "complete",
        "sources": [{"source_id": "a", "file_token": "a", "fileloc": "a.py", "dag_ids": ["a", "b"]}],
        "partial_reasons": [],
    }
    client = Client({"/api/v1/dagSources/a": response({"content": "code"})})
    report = discover.dump_airflow(client, "v1", all_sources=True, source_inventory=inventory)
    assert report["status"] == "complete"
    assert report["records"][0]["source"] == "code"
    assert [p for p, _ in client.calls] == ["/api/v1/dagSources/a"]


@pytest.mark.parametrize(
    "failure",
    [
        response({}, 403),
        response({}, 200, truncated=True),
        response({"wrong": "shape"}),
        AirflowResponse(http_status=0, body=b"", headers={}, transport_error="timeout"),
    ],
)
def test_failed_source_reads_are_partial_not_empty_success(failure):
    client = Client({"/api/v1/dagSources/a": failure, "/api/v1/dagSources/b": response({"content": "readable"})})
    report = discover.dump_airflow(client, "v1", sources=["a", "b"])
    assert report["status"] == "partial"
    assert [r["id"] for r in report["records"]] == ["b"]
    assert report["partial_reasons"]


def test_source_inventory_cancellation_and_denied_listing():
    with pytest.raises(NestedSchedulerCancelled):
        discover.list_dag_sources(Client({}), "v1", cancelled=lambda: True)
    report = discover.list_dag_sources(Client({}), "v1")
    assert report["status"] == "partial" and report["sources"] == []


def test_source_dump_budget_is_explicit_and_plain_text_is_supported():
    client = Client(
        {
            "/api/v1/dagSources/a": AirflowResponse(
                http_status=200, body=b"code\n", headers={"Content-Type": "text/plain"}
            )
        }
    )
    report = discover.dump_airflow(client, "v1", sources=["a"])
    assert report["records"][0]["source"] == "code\n"
    limited = discover.dump_airflow(client, "v1", sources=["a"], max_bytes=1)
    assert limited["status"] == "partial"


def test_inventory_renderer_places_source_dump_below_source_row():
    record = {
        "host": "localhost",
        "port": 8080,
        "show_dags_requested": True,
        "dag_ids": ["a"],
        "show_dagsources_requested": True,
        "dag_sources": [{"source_id": "token", "file_token": "token", "fileloc": "/dags/a.py", "dag_ids": ["a"]}],
        "dump_requested": True,
        "dump_report": {"status": "complete", "records": [{"kind": "dag_source", "id": "token", "source": "print(1)"}]},
    }
    lines = render._format_grouped_inventory_records(record, "txt")
    assert (
        next(i for i, line in enumerate(lines) if "DAG Id=" in line)
        < next(i for i, line in enumerate(lines) if "DAG Source Id=" in line)
        < next(i for i, line in enumerate(lines) if "dag_source Id=" in line)
    )
    assert sum("dag_source Id=" in line for line in lines) == 1
    assert "\x1b" not in "\n".join(lines)
    assert render._format_grouped_inventory_records(record, "json") == []


def test_actions_list_sources_and_dump_reuse_one_inventory(monkeypatch):
    client = Client(
        {
            "/api/v1/dags?limit=100&offset=0": response(
                {"dags": [{"dag_id": "a", "file_token": "token"}], "total_entries": 1}
            ),
            "/api/v1/dagSources/token": response({"content": "code"}),
        }
    )
    monkeypatch.setattr(actions, "_client_for", lambda *a, **kw: client)
    ctx = SimpleNamespace(
        args=SimpleNamespace(show_dagsources=True, dump=True), credential=SimpleNamespace(username=None, password=None)
    )
    record = actions.discover_record(
        ctx, {"detection_status": "confirmed", "api_generation": "v1", "auth_required": False}
    )
    assert record["dag_sources"][0]["source_id"] == "token"
    assert record["dump_report"]["records"][0]["source"] == "code"
    assert len(client.calls) == 2


@pytest.mark.parametrize("count,color", [(0, "\x1b[1;92m"), (1, "\x1b[1;38;5;196m")])
def test_source_counts_and_values_use_airflow_colors_and_no_color(monkeypatch, capsys, count, color):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    record = {
        "host": "localhost",
        "port": 8080,
        "show_dagsources_requested": True,
        "dag_sources": [{"source_id": "token", "dag_ids": ["a"], "fileloc": "a.py"}] * count,
    }
    lines = render._format_grouped_inventory_records(record, "txt")
    for line in lines:
        assert render._render_colored_airflow_line(Console(no_color=False), line)
    colored = capsys.readouterr().out
    assert f"{color}sources:{count}" in colored
    assert "\x1b[1;97mAirflow DAG Sources (" in colored
    if count:
        assert "\x1b[1;38;5;208mDAG Source Id=" in colored
    for line in lines:
        render._render_colored_airflow_line(Console(no_color=True), line)
    assert "\x1b" not in capsys.readouterr().out
    assert "\x1b" not in json.dumps(record)


def test_source_inventory_and_dump_stream_before_discovery_without_repeats(monkeypatch):
    client = Client(
        {
            "/api/v1/dags?limit=100&offset=0": response(
                {"dags": [{"dag_id": "a", "file_token": "token"}], "total_entries": 1}
            ),
            "/api/v1/dagSources/token": response({"content": "code"}),
        }
    )
    monkeypatch.setattr(actions, "_client_for", lambda *a, **kw: client)
    events = []

    def search(*args, **kwargs):
        assert any("DAG Source Id=" in line for line in events)
        assert any("dag_source Id=" in line for line in events)
        assert events[-1].endswith("[*] Discover Secrets")
        return {"status": "complete", "findings": []}

    monkeypatch.setattr(actions, "discover_task_logs", search)
    ctx = SimpleNamespace(
        args=SimpleNamespace(show_dagsources=True, dump=True, discover=True),
        credential=SimpleNamespace(username=None, password=None),
        host="localhost",
        port=8080,
        live_emit=lambda lines: events.extend(lines),
    )
    record = actions.discover_record(
        ctx,
        {
            "host": "localhost",
            "port": 8080,
            "detection_status": "confirmed",
            "api_generation": "v1",
            "auth_required": False,
        },
    )
    assert render._format_grouped_inventory_records(record, "txt") == []
    assert sum("DAG Source Id=" in line for line in events) == 1
    assert sum("dag_source Id=" in line for line in events) == 1


def test_explicit_token_source_can_be_read_even_when_global_dag_list_is_closed(monkeypatch):
    client = Client({"/api/v1/dagSources/token": response({"content": "code"})})
    monkeypatch.setattr(actions, "_client_for", lambda *a, **kw: client)
    ctx = SimpleNamespace(
        args=SimpleNamespace(dagsource=["token"], dump=True), credential=SimpleNamespace(username=None, password=None)
    )
    record = actions.discover_record(
        ctx, {"detection_status": "confirmed", "api_generation": "v1", "auth_required": True}
    )
    assert record["dump_report"]["status"] == "complete"
    assert record["auth_required"] is True
    assert record.get("provided_credentials_ok") is not True
    assert [p for p, _ in client.calls] == ["/api/v1/dagSources/token"]


def test_missing_token_is_partial_and_details_404_falls_back_to_basic_dag():
    client = Client(
        {
            "/api/v1/dags?limit=100&offset=0": response(
                {"dags": [{"dag_id": "a"}, {"dag_id": "missing"}], "total_entries": 2}
            ),
            "/api/v1/dags/a": response({"file_token": "token", "fileloc": "a.py"}),
        }
    )
    report = discover.list_dag_sources(client, "v1")
    assert report["sources"][0]["source_id"] == "token"
    assert report["status"] == "partial"
    assert "dag_source:missing:missing_file_token" in report["partial_reasons"]


def test_source_dump_item_limit_and_cancellation():
    client = Client({"/api/v1/dagSources/a": response({"content": "a"})})
    result = discover.dump_airflow(client, "v1", sources=["a", "b"], max_items=1)
    assert result["count"] == 1
    assert "item_limit" in result["partial_reasons"]
    with pytest.raises(NestedSchedulerCancelled):
        discover.dump_airflow(client, "v1", sources=["a"], cancelled=lambda: True)


@pytest.mark.parametrize(
    "generation,extra,error",
    [
        ("v1", {"credential_proof_surface": "web"}, "api_credentials_unverified"),
        ("v2", {"provided_credentials_ok": True}, "bearer_token_unavailable"),
    ],
)
def test_source_inventory_unverified_api_access_reports_unavailability(generation, extra, error):
    ctx = SimpleNamespace(
        args=SimpleNamespace(show_dagsources=True, dump=True), credential=SimpleNamespace(username="a", password="b")
    )
    record = actions.discover_record(
        ctx, {"detection_status": "confirmed", "api_generation": generation, "auth_required": True, **extra}
    )
    assert record["dag_sources_error"] == error
    assert record["dump_report"]["status"] == "unavailable"
