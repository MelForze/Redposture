"""YARN product proof, bounded read-only inventory and allocation-only probes."""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse

INFO = {
    "clusterInfo": {
        "state": "STARTED",
        "haState": "ACTIVE",
        "resourceManagerVersion": "3.3.6",
        "hadoopVersion": "3.3.6",
    }
}
APP = {"id": "application_1234_0001", "name": "report", "state": "RUNNING", "startedTime": 1234}
NODE = {"id": "worker:8041", "state": "RUNNING", "nodeHostName": "worker"}


class Pool:
    def __init__(self, replies: dict[str, Any]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, url: str, **_kwargs: Any) -> HttpResponse:
        parsed = urlsplit(url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        self.calls.append((method, path))
        reply = self.replies.get(path, (404, {}))
        if isinstance(reply, HttpResponse):
            return reply
        status, data = reply
        return HttpResponse(status, json.dumps(data).encode(), {"Content-Type": "application/json"})


def context(replies: dict[str, Any] | None = None, **args: Any) -> Any:
    data = {"/ws/v1/cluster/info": (200, INFO), "/ws/v1/cluster/apps?limit=1": (200, {"apps": None})}
    data.update(replies or {})
    return SimpleNamespace(
        host="localhost",
        port=8088,
        args=SimpleNamespace(**args),
        credential=None,
        lifecycle_state=SimpleNamespace(http=Pool(data)),
    )


def actions() -> Any:
    return importlib.import_module("redposture_core.modules.yarn.actions")


def test_cluster_schema_confirms_yarn_without_mutating_requests() -> None:
    ctx = context()
    record = actions().detect_record(ctx)
    assert record["is_yarn"] is True
    assert record["detection_status"] == "confirmed"
    assert record["version"] == "3.3.6"
    assert record["anonymous_apps_access"] is True
    assert record["submit_access"] == "unverified"
    assert not record["rce_potential"]
    assert all(method == "GET" for method, _ in ctx.lifecycle_state.http.calls)


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {},
        {"clusterInfo": {}},
        {"clusterInfo": {"state": "STARTED", "haState": "ACTIVE"}},
        {"clusterInfo": {**INFO["clusterInfo"], "state": "not-yarn"}},
        {"clusterInfo": {**INFO["clusterInfo"], "haState": True}},
        {"clusterInfo": {**INFO["clusterInfo"], "resourceManagerVersion": []}},
        {"clusterInfo": {**INFO["clusterInfo"], "hadoopVersion": "<html>"}},
    ],
)
def test_foreign_and_malformed_json_cannot_confirm(data: Any) -> None:
    record = actions().detect_record(
        context({"/ws/v1/cluster/info": (200, data), "/cluster": (200, "<title>ResourceManager</title>")})
    )
    assert record["is_yarn"] is False
    assert record["detection_status"] != "confirmed"


@pytest.mark.parametrize(
    "response,state",
    [
        (HttpResponse(0, b"", {}, error="connection refused"), "transport_failure"),
        (HttpResponse(200, json.dumps(INFO).encode(), {}, truncated=True), "not_service"),
        (HttpResponse(503, json.dumps(INFO).encode(), {}), "not_service"),
    ],
)
def test_transport_status_and_truncation_never_confirm(response: HttpResponse, state: str) -> None:
    ctx = context({"/ws/v1/cluster/info": response, "/cluster": HttpResponse(0, b"", {}, error="refused")})
    result = actions().detect_record(ctx)
    assert result["is_yarn"] is False
    assert result["detection_status"] == state


@pytest.mark.parametrize(
    "status,state,auth",
    [(403, "denied", True), (429, "rate_limited", None), (500, "unknown", None), (200, "unknown", None)],
)
def test_apps_denial_or_ambiguity_does_not_invent_auth_configuration(
    status: int, state: str, auth: bool | None
) -> None:
    record = actions().detect_record(context({"/ws/v1/cluster/apps?limit=1": (status, {})}))
    assert record["is_yarn"] is True
    assert record["anonymous_apps_access"] is False
    assert record["apps_access"] == state
    assert record["auth_required"] is auth
    assert record.get("security_enabled") is not False


def test_inventory_preserves_resource_models_without_side_effects() -> None:
    ctx = context(
        {
            "/ws/v1/cluster/apps?limit=5000": (200, {"apps": {"app": [APP]}}),
            "/ws/v1/cluster/nodes": (200, {"nodes": {"node": [NODE]}}),
            "/ws/v1/cluster/metrics": (
                200,
                {"clusterMetrics": {"totalMB": 8192, "allocatedMB": 1024, "totalNodes": 1}},
            ),
        },
        show_apps=True,
        show_nodes=True,
        show_metrics=True,
    )
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record["apps"] == [APP]
    assert record["nodes"] == [NODE]
    assert record["metrics"]["totalNodes"] == 1
    assert record["inventory_status"] == "complete"
    assert all(method == "GET" for method, _ in ctx.lifecycle_state.http.calls)


@pytest.mark.parametrize(
    "data,expected,partial",
    [
        ({"apps": None}, [], False),
        ({"apps": {"app": []}}, [], False),
        ({"apps": {"app": [APP, APP]}}, [APP], True),
        ({"apps": {}}, [], False),
        ({"apps": {"app": [{"id": "../bad"}]}}, None, True),
        ({"apps": {"app": "wrong"}}, None, True),
    ],
)
def test_collection_shapes_and_duplicates_are_never_silently_complete(data: Any, expected: Any, partial: bool) -> None:
    ctx = context({"/ws/v1/cluster/apps?limit=5000": (200, data)}, show_apps=True)
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record.get("apps") == expected
    assert record["apps_partial"] is partial


def test_full_snapshot_is_bounded_and_reports_unknown_coverage() -> None:
    rows = [{**APP, "id": f"application_1234_{n:04}"} for n in range(5001)]
    ctx = context({"/ws/v1/cluster/apps?limit=5000": (200, {"apps": {"app": rows}})}, show_apps=True)
    result = actions().data_record(ctx, actions().detect_record(ctx))
    assert len(result["apps"]) == 5000
    assert result["apps_partial"] is True
    assert result["inventory_status"] == "partial"
    assert len(ctx.lifecycle_state.http.calls) == 3


def test_discovery_reuses_same_origin_valid_application_snapshot() -> None:
    spec = {**APP, "diagnostics": "password=qa-secret", "trackingUrl": "http://foreign/private"}
    ctx = context(
        {
            "/ws/v1/cluster/apps?limit=5000": (200, {"apps": {"app": [spec, spec]}}),
        },
        discover=True,
    )
    result = actions().data_record(ctx, actions().detect_record(ctx))
    assert result["app_specs"] == [{"app": APP["id"], "spec": spec}]
    assert result["inventory_requested"] == []
    assert all(
        method == "GET" and path.startswith("/ws/v1/cluster/") for method, path in ctx.lifecycle_state.http.calls
    )
    assert ctx.lifecycle_state.http.calls.count(("GET", "/ws/v1/cluster/apps/application_1234_0001")) == 0


def test_budget_exhaustion_keeps_collection_unknown_and_partial() -> None:
    ctx = context(
        {"/ws/v1/cluster/apps?limit=5000": (200, {"apps": {"app": [APP]}})}, show_apps=True, discover_max_bytes=1
    )
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record["apps_access"] == "unknown"
    assert record["apps_partial"] is True
    assert "apps" not in record


@pytest.mark.parametrize(
    "status,data,expected",
    [
        (
            200,
            {"application-id": "application_1234_0002", "maximum-resource-capability": {"memory": 8192, "vCores": 8}},
            "allowed",
        ),
        (200, {"application-id": "application_1234_0002"}, "unverified"),
        (200, {"application-id": "evil", "maximum-resource-capability": {"memory": 8192, "vCores": 8}}, "unverified"),
        (
            200,
            {"application-id": "application_1234_0002", "maximum-resource-capability": {"memory": True, "vCores": 8}},
            "unverified",
        ),
        (403, {}, "denied"),
        (401, {}, "denied"),
        (429, {}, "rate_limited"),
        (500, {}, "unverified"),
    ],
)
def test_explicit_probe_only_proves_allocation_endpoint(status: int, data: Any, expected: str) -> None:
    ctx = context({"/ws/v1/cluster/apps/new-application": (status, data)}, probe_submit=True)
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record["allocation_access"] == expected
    assert record["submit_access"] == "unverified"
    assert record["rce_potential"] is (expected == "allowed")
    assert record["submit_probe"]["executed"] is False
    assert [(method, path) for method, path in ctx.lifecycle_state.http.calls if method != "GET"] == [
        ("POST", "/ws/v1/cluster/apps/new-application")
    ]


def test_unconfirmed_target_never_receives_probe_or_inventory() -> None:
    ctx = context({"/ws/v1/cluster/info": (200, {})}, probe_submit=True, show_apps=True)
    prior = actions().detect_record(ctx)
    count = len(ctx.lifecycle_state.http.calls)
    result = actions().data_record(ctx, prior)
    assert len(ctx.lifecycle_state.http.calls) == count
    assert result.get("rce_potential") is not True


class RecordingConsole:
    def __init__(self) -> None:
        self.paints: list[tuple[str, str]] = []

    def _paint(self, text: str, color: str, _stream: Any) -> str:
        self.paints.append((text, color))
        return text

    def plain(self, _text: str) -> None:
        pass


@pytest.mark.parametrize(
    "field,value,want",
    [
        ("apps_access", "allowed", "true_red"),
        ("apps_access", "denied", "bright_green"),
        ("apps_access", "unknown", "orange"),
        ("apps_access", "rate_limited", "orange"),
    ],
)
def test_inventory_access_colors_follow_airflow(field: str, value: str, want: str) -> None:
    render = importlib.import_module("redposture_core.modules.yarn.render")
    record = {"host": "host", "port": 8088, "inventory_requested": ["apps"], field: value}
    console = RecordingConsole()
    for line in render._format_inventory_records(record, "txt"):
        assert render._render_colored_yarn_line(console, line)
    assert any(f"access:{value}" in text and color == want for text, color in console.paints)
    assert any("Applications Enumeration" in text and color == "white" for text, color in console.paints)


@pytest.mark.parametrize("rows,want", [([], "bright_green"), ([APP], "true_red")])
def test_inventory_counts_and_values_have_distinct_colors(rows: list[Any], want: str) -> None:
    render = importlib.import_module("redposture_core.modules.yarn.render")
    record = {"host": "host", "port": 8088, "inventory_requested": ["apps"], "apps_access": "allowed", "apps": rows}
    console = RecordingConsole()
    for line in render._format_inventory_records(record, "txt"):
        render._render_colored_yarn_line(console, line)
    assert any(f"apps:{len(rows)}" in text and color == want for text, color in console.paints)
    if rows:
        assert any(APP["id"] in text and color == "orange" for text, color in console.paints)


def test_render_probe_is_explicit_about_allocation_vs_submit() -> None:
    render = importlib.import_module("redposture_core.modules.yarn.render")
    record = {
        "host": "host",
        "port": 8088,
        "rce_potential": True,
        "allocation_access": "allowed",
        "submit_probe": {"access": "allowed"},
    }
    text = "\n".join(render._format_inventory_records(record, "txt"))
    assert "RCE:potential" in text
    assert "allocation" in text.lower()
    assert "submission unverified" in text.lower()
    assert "\x1b" not in text
    assert render._format_inventory_records(record, "json") == []
    assert render._format_record(record, "txt") == ""


def test_detection_values_and_auth_colors() -> None:
    render = importlib.import_module("redposture_core.modules.yarn.render")
    record = {
        "host": "host",
        "port": 8088,
        "is_yarn": True,
        "version": "3.3.6",
        "cluster_state": "STARTED",
        "ha_state": "ACTIVE",
        "auth_required": False,
    }
    console = RecordingConsole()
    render._render_colored_yarn_line(console, render._format_detect_record(record, "txt"))
    assert any("auth required:False" in text and color == "true_red" for text, color in console.paints)
    assert any("version:3.3.6" in text and color == "white" for text, color in console.paints)
    assert render._format_detect_record(record, "json") == ""


def test_policy_rejects_unpaired_tls_and_invalid_budgets() -> None:
    policy = importlib.import_module("redposture_core.modules.yarn.policy")
    errors: list[str] = []
    for args in ({"tls_cert": "client.pem"}, {"tls_key": "key.pem"}, {"discover_time": 0}, {"discover_max_bytes": -1}):
        assert policy.validate_args(SimpleNamespace(**args), SimpleNamespace(error=errors.append)) == 2
    assert policy.validate_args(SimpleNamespace(), SimpleNamespace(error=errors.append)) is None


def test_real_hadoop_empty_wrappers_are_accessible_without_inventing_auth() -> None:
    ctx = context(
        {
            "/ws/v1/cluster/apps?limit=1": (200, {"apps": {}}),
            "/ws/v1/cluster/apps?limit=5000": (200, {"apps": {}}),
            "/ws/v1/cluster/nodes": (200, {"nodes": {}}),
        },
        show_apps=True,
        show_nodes=True,
    )
    detected = actions().detect_record(ctx)
    assert detected["anonymous_apps_access"] is True
    assert detected["auth_required"] is False
    result = actions().data_record(ctx, detected)
    assert result["apps"] == []
    assert result["nodes"] == []
    assert result["apps_partial"] is False
    assert result["nodes_partial"] is False
    assert result["inventory_status"] == "complete"


@pytest.mark.parametrize("identifier", ["application_1234_" + "1" * 4096, "application_1_1\n"])
def test_discovery_rejects_unbounded_or_control_character_ids(identifier: str) -> None:
    ctx = context({"/ws/v1/cluster/apps?limit=5000": (200, {"apps": {"app": [{"id": identifier}]}})}, discover=True)
    result = actions().data_record(ctx, actions().detect_record(ctx))
    assert result["apps_access"] == "unknown"
    assert result["app_specs"] == []
    assert len(ctx.lifecycle_state.http.calls) == 3


@pytest.mark.parametrize("value", [0, 3])
def test_metric_resource_counts_are_observed_values_not_verdicts(value: int) -> None:
    render = importlib.import_module("redposture_core.modules.yarn.render")
    record = {
        "host": "host",
        "port": 8088,
        "inventory_requested": ["metrics"],
        "metrics_access": "allowed",
        "metrics": {"appsRunning": value, "totalNodes": value, "allocatedMB": 1024},
    }
    console = RecordingConsole()
    for line in render._format_inventory_records(record, "txt"):
        render._render_colored_yarn_line(console, line)
    assert any(f'"appsRunning"={value}' in text and painted == "orange" for text, painted in console.paints)
    assert any(f'"totalNodes"={value}' in text and painted == "orange" for text, painted in console.paints)
    assert any('"allocatedMB"=1024' in text and painted == "orange" for text, painted in console.paints)
