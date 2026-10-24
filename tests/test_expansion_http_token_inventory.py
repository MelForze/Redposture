"""Bounded token-service traversal contracts beyond happy-path snapshots."""

from __future__ import annotations

import json
from types import SimpleNamespace as NS
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.jupyter import actions as jupyter
from redposture_core.modules.nomad import actions as nomad
from redposture_core.modules.vault import actions as vault


def reply(value: Any, status: int = 200, **kwargs: Any) -> HttpResponse:
    return HttpResponse(status, json.dumps(value).encode(), kwargs.pop("headers", {}), **kwargs)


def context(**args: Any) -> Any:
    return NS(args=NS(**args), credential=NS(token="verified-token"))


@pytest.mark.parametrize("failure", ["denied", "rate", "malformed", "truncated", "transport"])
def test_nomad_keeps_valid_page_when_followup_fails(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    calls = []
    faults = {
        "denied": reply({}, 403),
        "rate": reply({}, 429),
        "malformed": reply([{"ID": 17}]),
        "truncated": reply([{"ID": "untrusted"}], truncated=True),
        "transport": reply({}, 0, error="connection reset"),
    }

    def get(ctx: Any, base: str, path: str, token: str | None = None) -> HttpResponse:
        calls.append((path, token))
        return reply([{"ID": "job-a"}], headers={"X-Nomad-NextToken": "a/b +"}) if len(calls) == 1 else faults[failure]

    monkeypatch.setattr(nomad, "_get", get)
    result = nomad.data_record(context(show_jobs=True), {"api_endpoint": "http://qa", "token_valid": True})
    assert result["jobs"] == [{"ID": "job-a"}]
    assert result["jobs_access"] == "allowed"
    assert result["jobs_partial"] is True and result["jobs_error"]
    assert result["inventory_status"] == "partial" and result["job_discovery_partial"] is True
    assert parse_qs(urlsplit(calls[1][0]).query) == {"namespace": ["default"], "next_token": ["a/b +"]}
    assert [token for _, token in calls] == ["verified-token"] * 2


def test_nomad_repeated_continuation_stops_without_third_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def get(*args: Any) -> HttpResponse:
        calls.append(args[2])
        return reply([{"ID": f"job-{len(calls)}"}], headers={"x-nomad-nexttoken": "repeat"})

    monkeypatch.setattr(nomad, "_get", get)
    result = nomad.data_record(context(show_jobs=True), {"api_endpoint": "http://qa"})
    assert result["jobs"] == [{"ID": "job-1"}, {"ID": "job-2"}]
    assert len(calls) == 2 and result["jobs_error"] == "pagination repeated a token"
    assert result["inventory_status"] == "partial"


@pytest.mark.parametrize(
    "bad_row", [{"ID": "../secret"}, {"ID": "valid", "Namespace": "*"}, {"ID": "valid", "Namespace": "../other"}]
)
def test_nomad_discovery_never_follows_unsafe_inventory_names(
    monkeypatch: pytest.MonkeyPatch, bad_row: dict[str, Any]
) -> None:
    calls = []

    def get(*args: Any) -> HttpResponse:
        calls.append(args[2])
        return (
            reply([bad_row, {"ID": "safe job", "Namespace": "team a"}])
            if len(calls) == 1
            else reply({"ID": "safe job", "TaskGroups": []})
        )

    monkeypatch.setattr(nomad, "_get", get)
    result = nomad.data_record(context(discover=True), {"api_endpoint": "http://qa"})
    assert calls == ["/v1/jobs?namespace=default", "/v1/job/safe%20job?namespace=team+a"]
    assert result["job_specs"] == [
        {"namespace": "team a", "job": "safe job", "spec": {"ID": "safe job", "TaskGroups": []}}
    ]
    assert result["job_discovery_partial"] is True and result["inventory_status"] == "partial"


def test_nomad_item_cap_keeps_prefix_and_does_not_fetch_more(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{"ID": str(i)} for i in range(5001)]
    calls = []
    monkeypatch.setattr(nomad, "_get", lambda *args: calls.append(args[2]) or reply(rows))
    result = nomad.data_record(context(show_nodes=True), {"api_endpoint": "http://qa"})
    assert result["nodes"] == rows[:5000] and result["nodes_error"] == "item limit"
    assert result["inventory_status"] == "partial" and calls == ["/v1/nodes"]


@pytest.mark.parametrize("section,key", [("jobs", "ID"), ("nodes", "ID"), ("members", "Name")])
def test_nomad_empty_snapshot_is_complete(monkeypatch: pytest.MonkeyPatch, section: str, key: str) -> None:
    monkeypatch.setattr(nomad, "_get", lambda *args: reply({"Members": []} if section == "members" else []))
    result = nomad.data_record(context(**{"show_" + section: True}), {"api_endpoint": "http://qa"})
    assert result[section] == [] and result[section + "_partial"] is False
    assert result[section + "_access"] == "allowed" and result["inventory_status"] == "complete"


def entry(path: str, kind: str = "file", **extra: Any) -> dict[str, Any]:
    return {"name": path.rsplit("/", 1)[-1], "path": path, "type": kind, **extra}


def test_jupyter_recursive_discovery_rejects_escape_and_retains_notebook(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    notebook = {"cells": [{"source": "PASSWORD = 'qa'"}]}
    routes = {
        "/api/contents/home?content=1": entry(
            "home",
            "directory",
            content=[
                entry("elsewhere"),
                entry("home/../escape"),
                entry("home/sub", "directory"),
                entry("home/report.ipynb", "notebook"),
            ],
        ),
        "/api/contents/home/sub?content=1": reply({}, 403),
        "/api/contents/home/report.ipynb?content=1": entry("home/report.ipynb", "notebook", content=notebook),
    }

    def get(ctx: Any, base: str, path: str, token: str | None) -> HttpResponse:
        calls.append((path, token))
        value = routes[path]
        return value if isinstance(value, HttpResponse) else reply(value)

    monkeypatch.setattr(jupyter, "_get", get)
    result = jupyter.data_record(
        context(path="home", discover=True), {"api_endpoint": "http://qa", "token_valid": True}
    )
    assert [row["path"] for row in result["contents"]] == ["home/sub", "home/report.ipynb"]
    assert result["notebook_contents"] == [{"path": "home/report.ipynb", "notebook": notebook}]
    assert result["contents_partial"] is True and result["content_discovery_partial"] is True
    assert result["inventory_status"] == "partial" and result["contents_error"]
    assert [path for path, _ in calls] == list(routes)
    assert all(token == "verified-token" for _, token in calls)


@pytest.mark.parametrize("content", [None, {}, "invalid"])
def test_jupyter_invalid_directory_children_report_partial(monkeypatch: pytest.MonkeyPatch, content: Any) -> None:
    monkeypatch.setattr(jupyter, "_get", lambda *args: reply(entry("", "directory", content=content)))
    result = jupyter.data_record(context(show_contents=True), {"api_endpoint": "http://qa"})
    assert result["contents"] == [] and result["contents_partial"] is True
    assert result["inventory_status"] == "partial"


@pytest.mark.parametrize(
    "resource,value",
    [("sessions", [{"id": "a", "kernel": None}]), ("kernels", [{"name": "python3"}]), ("terminals", [{"name": 3}])],
)
def test_jupyter_invalid_inventory_is_unknown_not_empty_success(
    monkeypatch: pytest.MonkeyPatch, resource: str, value: Any
) -> None:
    monkeypatch.setattr(jupyter, "_get", lambda *args: reply(value))
    result = jupyter.data_record(context(**{"show_" + resource: True}), {"api_endpoint": "http://qa"})
    assert result[resource + "_access"] == "unknown" and resource not in result
    assert result["inventory_status"] == "unavailable"


@pytest.mark.parametrize("version", ["1", "2"])
def test_vault_list_fallback_nested_duplicates_and_unsafe_keys(monkeypatch: pytest.MonkeyPatch, version: str) -> None:
    calls = []
    prefix = "/v1/secret/" + ("metadata/" if version == "2" else "")
    read_prefix = "/v1/secret/" + ("data/" if version == "2" else "")

    def request(client: Any, base: str, path: str, *, token: str | None = None, method: str = "GET") -> HttpResponse:
        calls.append((method, path, token))
        if path == "/v1/sys/mounts":
            return reply(
                {"data": {"secret/": {"type": "kv", "options": {"version": version}}, "ignore/": {"type": "database"}}}
            )
        if path == prefix and method == "LIST":
            return reply({}, 405)
        if path == prefix + "?list=true":
            return reply({"data": {"keys": ["one", "one", "sub/", "../escape", "/outside", 17, ""]}})
        if path == prefix + "sub/":
            return reply({"data": {"keys": ["two"]}})
        assert path in {read_prefix + "one", read_prefix + "sub/two"}
        secret = {"password": path}
        return reply({"data": {"data": secret} if version == "2" else secret})

    monkeypatch.setattr(vault, "_client", lambda ctx: object())
    monkeypatch.setattr(vault, "_request", request)
    result = vault.data_record(context(discover=True), {"api_endpoint": "http://qa", "token_valid": True})
    assert [item["key"] for item in result["kv_dump_items"]] == ["secret/one", "secret/sub/two"]
    assert result["kv_secrets_read"] == 2 and result["kv_discovery_partial"] is True
    assert result["inventory_status"] == "partial"
    assert len(calls) == 6 and all(token == "verified-token" for _, _, token in calls)
    assert calls[2][:2] == ("GET", prefix + "?list=true")


@pytest.mark.parametrize("fault", ["denied", "missing", "truncated", "bytes"])
def test_vault_kv_read_failure_preserves_already_read_secret(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    def request(client: Any, base: str, path: str, **kwargs: Any) -> HttpResponse:
        if path == "/v1/sys/mounts":
            return reply({"data": {"secret/": {"type": "kv"}}})
        if path == "/v1/secret/":
            return reply({"data": {"keys": ["good", "bad"]}})
        if path.endswith("good"):
            return reply({"data": {"password": "retained"}})
        return {
            "denied": reply({}, 403),
            "missing": reply({}),
            "truncated": reply({"data": "no"}, truncated=True),
            "bytes": reply({"data": "x" * 2000}),
        }[fault]

    monkeypatch.setattr(vault, "_client", lambda ctx: object())
    monkeypatch.setattr(vault, "_request", request)
    result = vault.data_record(context(discover=True, discover_max_bytes=1000), {"api_endpoint": "http://qa"})
    assert result["kv_dump_items"] == [{"key": "secret/good", "value": {"password": "retained"}}]
    assert result["kv_discovery_partial"] is True and result["kv_discovery_reasons"]
    assert result["inventory_status"] == "partial"


def test_vault_selected_missing_mount_is_explicit_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "_client", lambda ctx: object())
    monkeypatch.setattr(vault, "_request", lambda *args, **kwargs: reply({"data": {"transit/": {"type": "transit"}}}))
    result = vault.data_record(context(discover=True, mount="missing/"), {"api_endpoint": "http://qa"})
    assert result["kv_dump_items"] == [] and result["kv_discovery_reasons"] == ["selected KV mount unavailable"]
    assert result["inventory_status"] == "partial"
