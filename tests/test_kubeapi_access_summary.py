"""Resource access must be visible without requesting inventory."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.console import Console
from redposture_core.modules.kubeapi import actions


def options(**overrides):
    return {
        "namespace_filters": [],
        "show_namespaces": False,
        "show_pods": False,
        "show_secrets": False,
        "exec_pod": None,
        "exec_command": None,
        **overrides,
    }


@pytest.fixture
def context():
    state = actions.KubeApiLifecycleState()
    ctx = SimpleNamespace(
        host="localhost",
        port=6443,
        target=SimpleNamespace(scheme="https"),
        args=SimpleNamespace(timeout=1, retries=0),
        credential=SimpleNamespace(token=None, username=None, password=None),
        lifecycle_state=state,
    )
    try:
        yield ctx
    finally:
        state.close()


@pytest.mark.parametrize(
    "namespace_status,pod_status,auth_required",
    [(403, 403, True), (401, 401, True), (200, 403, False), (403, 200, False), (200, 200, False)],
)
def test_detection_probes_both_resources_without_inventory_flags(
    monkeypatch, context, namespace_status, pod_status, auth_required
):
    calls = []

    def request(ctx, state, path, **kwargs):
        calls.append(path)
        if path == "/version":
            return 200, {"major": "1", "minor": "31", "gitVersion": "v1.31.4"}, {}, None
        assert path == "/api/v1/pods?limit=1"
        return (
            pod_status,
            {"kind": "PodList", "apiVersion": "v1", "items": [], "metadata": {"continue": "next-page"}},
            {},
            None,
        )

    monkeypatch.setattr(actions, "_lifecycle_get_json_with_retries", request)
    monkeypatch.setattr(
        actions,
        "_probe_namespace_access",
        lambda *a, **kw: (namespace_status == 200, namespace_status, "denied" if namespace_status != 200 else None),
    )
    record = actions.detect_kubeapi(context, options())
    assert record["auth_required"] is auth_required
    assert record["can_list_namespaces"] is (namespace_status == 200)
    assert record["can_list_pods"] is (pod_status == 200)
    assert calls == ["/version", "/api/v1/pods?limit=1"]
    line = actions._format_detect_record(record, "txt")
    assert (
        f"(auth required:{auth_required}) (namespaces access:{namespace_status == 200}) (pods access:{pod_status == 200}) (version:v1.31.4)"
        in line
    )
    assert "anonymous access:" not in line


@pytest.mark.parametrize(
    "payload,error",
    [
        ({"kind": "Status", "items": []}, None),
        ({"kind": "PodList", "items": "invalid"}, None),
        (None, "response exceeds byte limit"),
        (None, "connection timeout"),
    ],
)
def test_bad_pod_probe_response_cannot_claim_access_or_definitive_denial(monkeypatch, context, payload, error):
    monkeypatch.setattr(
        actions,
        "_lifecycle_get_json_with_retries",
        lambda ctx, state, path, **kw: (
            (200, {"major": "1", "minor": "31", "gitVersion": "v1.31.4"}, {}, None)
            if path == "/version"
            else (200, payload, {}, error)
        ),
    )
    monkeypatch.setattr(actions, "_probe_namespace_access", lambda *a, **kw: (False, 403, "Forbidden"))
    record = actions.detect_kubeapi(context, options())
    assert record["can_list_pods"] is None
    assert "pods access:unknown" in actions._format_detect_record(record, "txt")


def test_pod_probe_checks_selected_namespaces_without_pagination(monkeypatch, context):
    calls = []

    def request(ctx, state, path, **kw):
        calls.append(path)
        if path == "/version":
            return 200, {"major": "1", "minor": "31", "gitVersion": "v1.31.4"}, {}, None
        if "/blocked/" in path:
            return 403, {"kind": "Status", "code": 403}, {}, None
        return 200, {"kind": "PodList", "items": [], "metadata": {"continue": "next"}}, {}, None

    monkeypatch.setattr(actions, "_lifecycle_get_json_with_retries", request)
    monkeypatch.setattr(actions, "_probe_namespace_access", lambda *a, **kw: (False, 403, "Forbidden"))
    record = actions.detect_kubeapi(context, options(namespace_filters=["blocked", "allowed"]))
    assert record["can_list_pods"] is True and record["auth_required"] is False
    assert calls == ["/version", "/api/v1/namespaces/blocked/pods?limit=1", "/api/v1/namespaces/allowed/pods?limit=1"]


def test_collection_does_not_erase_passive_access_flags(monkeypatch, context):
    context.lifecycle_state.access_namespaces = []
    record = actions.collect_kubeapi_data(
        context, {"status": "open_no_auth", "can_list_namespaces": True, "can_list_pods": True}, options()
    )
    assert record["can_list_pods"] is True


@pytest.mark.parametrize(
    "access,color", [(True, "\x1b[1;38;5;196m"), (False, "\x1b[1;92m"), (None, "\x1b[1;38;5;208m")]
)
def test_summary_access_colors_and_no_color(capsys, access, color):
    record = {
        "host": "localhost",
        "port": 6443,
        "status": "detected",
        "auth_required": True,
        "can_list_namespaces": access,
        "can_list_pods": access,
        "version": "v1.31.4",
    }
    line = actions._format_detect_record(record, "txt")
    actions._render_colored_kubeapi_line(Console(no_color=False), line)
    colored = capsys.readouterr().out
    value = "unknown" if access is None else str(access)
    assert color + f"namespaces access:{value}" in colored
    assert color + f"pods access:{value}" in colored
    actions._render_colored_kubeapi_line(Console(no_color=True), line)
    assert "\x1b" not in capsys.readouterr().out
    assert "\x1b" not in actions._format_detect_record(record, "json")
    assert json.loads(actions._format_detect_record(record, "json"))["can_list_pods"] is access
