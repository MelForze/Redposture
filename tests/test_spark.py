"""Spark product proof, bounded metadata reads and non-executing submit probe."""

from __future__ import annotations

import copy
import importlib
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse

WORKER = {
    "id": "worker-qa",
    "host": "worker.internal",
    "port": 7078,
    "webuiaddress": "http://worker.internal:8081",
    "cores": 2,
    "coresused": 0,
    "memory": 1024,
    "memoryused": 0,
    "state": "ALIVE",
}
APP = {"id": "app-qa", "name": "etl", "user": "alice", "cores": 1, "state": "RUNNING", "memoryperexecutor": 1024}
MASTER = {
    "url": "spark://master.internal:7077",
    "workers": [WORKER],
    "activeapps": [APP],
    "completedapps": [],
    "cores": 2,
    "coresused": 1,
    "memory": 1024,
    "memoryused": 0,
    "status": "ALIVE",
}
STATUS = {
    "action": "SubmissionStatusResponse",
    "serverSparkVersion": "3.5.1",
    "submissionId": "redposture-probe",
    "success": False,
}
HTML = HttpResponse(
    200,
    b'<html><title>Spark Master at spark://master.internal:7077</title><span class="version">3.5.1</span></html>',
    {},
)


class Pool:
    def __init__(self, routes: dict[str, Any]):
        self.routes = routes
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        path = urlsplit(url).path
        self.calls.append((method, path, kwargs))
        reply = self.routes.get(method + " " + path, self.routes.get(path, (404, {})))
        if isinstance(reply, HttpResponse):
            return reply
        return HttpResponse(reply[0], json.dumps(reply[1]).encode(), {})


def context(routes=None, port=8080, **args):
    return SimpleNamespace(
        host="127.0.0.1",
        port=port,
        args=SimpleNamespace(**args),
        credential=None,
        lifecycle_state=SimpleNamespace(http=Pool(routes or {})),
    )


def actions():
    try:
        return importlib.import_module("redposture_core.modules.spark.actions")
    except ModuleNotFoundError:
        pytest.fail("Spark audit actions have not been implemented")


def test_master_json_confirms_spark_without_claiming_rest_submission():
    ctx = context({"/json/": (200, MASTER), "/": HTML})
    record = actions().detect_record(ctx)
    assert record["is_spark"] is True
    assert record["detection_status"] == "confirmed"
    assert record["surface"] == "master_ui"
    assert record["version"] == "3.5.1"
    assert record["anonymous_access"] is True
    assert record["submit_access"] == "unverified"
    assert record["rce_potential"] is False
    assert all(call[0] == "GET" for call in ctx.lifecycle_state.http.calls)


def test_rest_status_is_strong_read_only_product_proof():
    ctx = context({"/v1/submissions/status/redposture-probe": (200, STATUS)}, port=6066)
    record = actions().detect_record(ctx)
    assert record["surface"] == "submission_rest"
    assert record["version"] == "3.5.1"
    assert record["submit_access"] == "unverified"
    assert record["submit_parser_reachable"] is None
    assert record["rce_potential"] is True
    assert all(call[0] == "GET" for call in ctx.lifecycle_state.http.calls)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        "Spark",
        {"version": "3.5.1"},
        {"workers": [], "activeapps": [], "cores": 0},
        {**MASTER, "url": "http://master:8080"},
        {**MASTER, "cores": True},
        {**MASTER, "workers": [{}]},
        {**MASTER, "activeapps": [{"id": "app"}]},
        {**MASTER, "workers": "workers"},
    ],
)
def test_generic_or_malformed_json_never_confirms_master(payload):
    record = actions().detect_record(context({"/json/": (200, payload), "/": HTML}))
    assert record["is_spark"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"action": "ErrorResponse"},
        {"serverSparkVersion": "unknown"},
        {"submissionId": "unrelated"},
        {"success": "false"},
        {"serverSparkVersion": None},
    ],
)
def test_incomplete_or_foreign_submission_response_is_rejected(change):
    record = actions().detect_record(context({"/v1/submissions/status/redposture-probe": (200, {**STATUS, **change})}))
    assert record["is_spark"] is False


@pytest.mark.parametrize(
    "response",
    [
        HttpResponse(200, b'{"url":', {}),
        HttpResponse(200, json.dumps(MASTER).encode(), {}, truncated=True),
        HttpResponse(200, json.dumps(MASTER).encode(), {}, error="incomplete"),
        HttpResponse(403, json.dumps(MASTER).encode(), {}),
    ],
)
def test_untrusted_or_incomplete_http_body_is_not_product_proof(response):
    assert actions().detect_record(context({"/json/": response}))["is_spark"] is False


def test_native_master_port_is_not_queried_as_http():
    ctx = context({"/json/": (200, MASTER)}, port=7077)
    result = actions().detect_record(ctx)
    assert result["is_spark"] is False
    assert result["detection_status"] == "unsupported_protocol"
    assert ctx.lifecycle_state.http.calls == []


def test_master_inventory_and_discovery_reuse_only_validated_metadata():
    ctx = context({"/json/": (200, MASTER)}, show_workers=True, show_apps=True, discover=True)
    detected = actions().detect_record(ctx)
    record = actions().data_record(ctx, detected)
    assert record["workers"] == [WORKER]
    assert record["apps"] == [APP]
    assert record["workers_access"] == record["apps_access"] == "allowed"
    assert record["inventory_status"] == "complete"
    assert record["spark_metadata"] == {"workers": [WORKER], "apps": [APP]}
    assert len([call for call in ctx.lifecycle_state.http.calls if call[1] == "/json/"]) == 2
    assert all(call[0] == "GET" for call in ctx.lifecycle_state.http.calls)


def test_discovery_only_does_not_expose_implicit_inventory():
    ctx = context({"/json/": (200, MASTER)}, discover=True)
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record["inventory_requested"] == []
    assert record["spark_metadata"]["apps"] == [APP]
    assert "apps" not in record and "workers" not in record


@pytest.mark.parametrize(
    "response,state",
    [((403, {}), "denied"), ((429, {}), "rate_limited"), ((200, {**MASTER, "activeapps": [{}]}), "unknown")],
)
def test_inventory_failure_never_becomes_successful_empty_collection(response, state):
    ctx = context({"/json/": (200, MASTER)}, show_workers=True, show_apps=True, discover=True)
    detected = actions().detect_record(ctx)
    ctx.lifecycle_state.http.routes["/json/"] = response
    record = actions().data_record(ctx, detected)
    assert record["apps_access"] == state
    assert record["inventory_status"] == "unavailable"
    assert record["content_discovery_partial"] is True
    assert "apps" not in record


def test_inventory_item_cap_marks_partial_without_following_discovered_worker_urls():
    master = copy.deepcopy(MASTER)
    master["workers"] = [{**WORKER, "id": f"worker-{i}"} for i in range(5001)]
    ctx = context({"/json/": (200, master)}, show_workers=True, discover=True)
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert len(record["workers"]) == 5000
    assert record["workers_partial"] is True
    assert record["content_discovery_partial"] is True
    assert record["inventory_status"] == "partial"
    assert all(call[1] in {"/json/", "/"} for call in ctx.lifecycle_state.http.calls)


def test_discovery_byte_budget_does_not_label_unread_metadata_complete():
    ctx = context({"/json/": (200, MASTER)}, discover=True, discover_max_bytes=1)
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record["content_discovery_partial"] is True
    assert "spark_metadata" not in record


def test_rest_only_inventory_is_unavailable_without_guessing_ui_port():
    ctx = context({"/v1/submissions/status/redposture-probe": (200, STATUS)}, show_workers=True, show_apps=True)
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record["workers_access"] == record["apps_access"] == "unavailable"
    assert record["inventory_status"] == "unavailable"
    assert all(call[0] == "GET" for call in ctx.lifecycle_state.http.calls)


def test_explicit_probe_posts_only_action_and_reports_parser_not_submit_permission():
    malformed = {
        "action": "ErrorResponse",
        "serverSparkVersion": "3.5.1",
        "message": "Malformed request: Validation of message CreateSubmissionRequest failed! 'clientSparkVersion' is missing",
    }
    ctx = context(
        {"/v1/submissions/status/redposture-probe": (200, STATUS), "POST /v1/submissions/create": (400, malformed)},
        probe_submit=True,
    )
    record = actions().data_record(ctx, actions().detect_record(ctx))
    posts = [call for call in ctx.lifecycle_state.http.calls if call[0] == "POST"]
    assert len(posts) == 1
    assert json.loads(posts[0][2]["body"]) == {"action": "CreateSubmissionRequest"}
    assert posts[0][2]["retries"] == 0
    assert posts[0][2]["allow_cross_origin_redirects"] is False
    assert record["submit_parser_reachable"] is True
    assert record["submit_access"] == "unverified"
    assert record["submit_probe"]["execution"] is False
    assert record["rce_potential"] is True


@pytest.mark.parametrize(
    "response,reachable,access",
    [
        ((403, {}), False, "denied"),
        ((400, {"message": "bad request"}), None, "unverified"),
        ((200, {"action": "CreateSubmissionResponse", "success": True}), None, "unverified"),
        ((429, {}), None, "rate_limited"),
    ],
)
def test_probe_distinguishes_access_denial_from_unknown_parser_response(response, reachable, access):
    ctx = context(
        {"/v1/submissions/status/redposture-probe": (200, STATUS), "POST /v1/submissions/create": response},
        probe_submit=True,
    )
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record["submit_parser_reachable"] is reachable
    assert record["submit_access"] == access


def test_probe_does_not_send_create_to_master_ui():
    ctx = context({"/json/": (200, MASTER)}, probe_submit=True)
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record["submit_probe"]["access"] == "unavailable"
    assert all(call[0] == "GET" for call in ctx.lifecycle_state.http.calls)


def test_real_spark_validation_error_omits_nested_missing_field_cause():
    # RestServlet.formatException emits the outer exception and stack frames,
    # not the nested required-field exception's message.
    malformed = {
        "action": "ErrorResponse",
        "serverSparkVersion": "3.5.1",
        "message": "Malformed request: org.apache.spark.deploy.rest.SubmitRestProtocolException: Validation of message CreateSubmissionRequest failed!\n\tat org.apache.spark.deploy.rest.SubmitRestProtocolMessage.validate(SubmitRestProtocolMessage.scala:70)",
    }
    ctx = context(
        {"/v1/submissions/status/redposture-probe": (200, STATUS), "POST /v1/submissions/create": (400, malformed)},
        probe_submit=True,
    )
    record = actions().data_record(ctx, actions().detect_record(ctx))
    assert record["submit_parser_reachable"] is True
    assert record["submit_access"] == "unverified"
