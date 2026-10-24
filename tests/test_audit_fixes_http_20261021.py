"""Independent reproductions for the 2026-10-21 HTTP and artifact audit."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS
from typing import Any

import pytest

from redposture_core import web_panel_export as we
from redposture_core import web_panels as wp
from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules import token_render
from redposture_core.modules.airflow import actions as airflow
from redposture_core.modules.gitlab import actions as gitlab
from redposture_core.modules.jenkins import actions as jenkins
from redposture_core.modules.jupyter import actions as jupyter
from redposture_core.modules.minio import discover as minio
from redposture_core.modules.minio.enumerate import ObjectInfo
from redposture_core.modules.qdrant import actions as qdrant
from redposture_core.modules.registry import actions as registry
from redposture_core.modules.yarn import actions as yarn


def reply(value, status=200):
    return HttpResponse(status, json.dumps(value).encode(), {})


@pytest.mark.parametrize("failure", ["config", "log", "env", "builds", "long_config", "long_log", "job_limit"])
def test_http21_01_jenkins_retains_success_and_reports_partial(monkeypatch, failure):
    count = 21 if failure == "job_limit" else 1
    jobs = [{"name": f"job{i:02}", "lastBuild": {"number": 1}} for i in range(count)]

    def get(_client, _base, path, _basic=None):
        if path.startswith("/api/json"):
            return reply({"jobs": jobs})
        if "tree=builds" in path:
            return reply({"builds": [{"number": 1}]}, 503 if failure == "builds" else 200)
        kind = "config" if path.endswith("config.xml") else "log" if path.endswith("consoleText") else "env"
        if failure == kind:
            return reply({}, 503)
        if kind == "env":
            return reply({"envMap": {"PASSWORD": "proof"}})
        return HttpResponse(200, b"x" * (70022 if failure == "long_" + kind else 10), {})

    monkeypatch.setattr(jenkins, "_client", lambda ctx: object())
    monkeypatch.setattr(jenkins, "_get", get)
    result = jenkins.data_record(
        NS(args=NS(show_jobs=100, show_builds=2, discover=True)), {"api_endpoint": "http://qa"}
    )
    assert result.get("job_discovery_partial") is True
    assert result.get("discovery_errors")
    assert result["jobs"]
    from redposture_core.modules.jenkins import render

    assert "partial" in "\n".join(render._format_inventory_records(result, "txt"))


def test_http21_02_qdrant_metadata_failure_is_explicit_and_scroll_still_attempted(monkeypatch):
    monkeypatch.setattr(
        qdrant,
        "_qdrant_get_collection_info",
        lambda h, p, t, n, **kw: (503, {}, None) if n == "bad" else (200, {}, None),
    )
    monkeypatch.setattr(qdrant, "_qdrant_scroll_payloads", lambda h, p, t, n, **kw: ([{"id": n}], False))
    monkeypatch.setattr(qdrant, "_qdrant_edit_probe_empty_patch", lambda *a, **kw: {})
    monkeypatch.setattr(qdrant, "_qdrant_logger_endpoint_probe", lambda *a, **kw: {})
    state = qdrant.QdrantLifecycleState()
    ctx = NS(lifecycle_state=state, args=NS(discover=True), host="qa", port=6333, credential=NS(token=None))
    result = qdrant.collect_qdrant_data(
        ctx,
        {"collections": ["good", "bad"]},
        dict(dump_requested=True, dump_limit=None, collection_name=None, ssrf_urls=[]),
    )
    assert result.get("payload_discovery_partial") is True
    assert result.get("payload_discovery_errors")
    assert [x["collection"] for x in result["payload_discovery_items"]] == ["good", "bad"]


@pytest.mark.parametrize("resource", ["contents", "kernels", "sessions", "terminals"])
def test_http21_03_jupyter_truncation_visible_in_txt(monkeypatch, resource):
    value: Any
    if resource == "contents":
        value = {
            "name": "",
            "path": "",
            "type": "directory",
            "content": [{"name": str(i), "path": str(i), "type": "file"} for i in range(5001)],
        }
    else:
        value = [{"id": str(i), "name": str(i), "kernel": {}} for i in range(5001)]
    monkeypatch.setattr(jupyter, "_get", lambda *a, **kw: reply(value))
    result = jupyter.data_record(
        NS(args=NS(**{"show_" + resource: True}), credential=NS()), {"api_endpoint": "http://qa"}
    )
    assert result["inventory_status"] == "partial"
    lines = token_render.inventory("jupyter", result, "txt")
    assert any("coverage (status:partial)" in line for line in lines)
    assert "\x1b" not in "\n".join(lines) and "\\u001b" not in json.dumps(result)


def test_http21_e01_yarn_discovery_uses_full_list_snapshot(monkeypatch):
    rows = [{"id": f"application_1_{i}", "name": f"app{i}", "diagnostics": "full text"} for i in range(100)]
    paths = []

    def get(ctx, base, path):
        paths.append(path)
        return reply(
            {"apps": {"app": rows}} if "?" in path else {"app": next(r for r in rows if path.endswith(r["id"]))}
        )

    monkeypatch.setattr(yarn, "_get", get)
    result = yarn.data_record(NS(args=NS(discover=True)), {"api_endpoint": "http://qa", "is_yarn": True})
    assert [x["spec"] for x in result["app_specs"]] == rows
    assert paths == ["/ws/v1/cluster/apps?limit=5000"]


def test_http21_e02_airflow_negative_corroboration_reused():
    paths = []

    class Client:
        base_url = "http://qa"

        def get(self, path, **kw):
            paths.append(path)
            return AirflowResponse(
                http_status=200 if path == "/api/v2/version" else 404,
                headers={},
                body=b'{"version":"3.0.2"}' if path == "/api/v2/version" else b"{}",
            )

    assert airflow.detect_airflow(Client()).status == "not_airflow"
    assert len(paths) == len(set(paths)) == 6


def test_a21_01_minio_deadline_applies_to_skipped_media(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(minio.time, "monotonic", lambda: now[0])
    consumed = []

    def objects():
        for i in range(10):
            consumed.append(i)
            now[0] += 0.1
            yield ObjectInfo(bucket="qa", key=f"{i}.jpg", size=1)

    result = minio.discover_secrets(NS(), objects(), budget=minio.Budget(time_budget=0.01, _started=0))
    assert result.coverage_complete is False and "timeout" in result.partial_reasons
    assert consumed == [0]


@pytest.mark.parametrize("full", [False, True])
def test_a21_02_portainer_null_volumes_are_legal_empty(monkeypatch, full):
    def get(*args, **kw):
        path = args[2]
        return reply([{"Id": 1}] if "/api/endpoints?" in path else {"Volumes": None, "Warnings": None})

    if full:
        monkeypatch.setattr(we, "_get", get)
        rows = list(we._portainer(None, "http://qa", {}, {"volumes"}))
        assert [row for row in rows if row[1] == "volumes"] == []
    else:
        monkeypatch.setattr(wp, "HttpSessionPool", lambda **kw: NS(close=lambda: None))
        monkeypatch.setattr(wp, "_get", get)
        result = wp.enumerate_panel(
            NS(args=NS(volumes=True)), {"ui_product": "portainer", "ui": {"endpoint": "http://qa"}}
        )["ui"]["inventory"]["volumes"]
        assert result["count"] == 0 and result["partial"] is False


@pytest.mark.parametrize("kind", ["catalog", "tags", "nexus"])
@pytest.mark.parametrize("later", [False, True])
@pytest.mark.parametrize(
    "bad",
    [{}, {"repositories": "oops", "tags": "oops", "items": "oops"}, {"repositories": [4], "tags": [4], "items": [4]}],
)
def test_a21_03_registry_malformed_collection_is_error(monkeypatch, kind, later, bad):
    calls = [0]

    def request(*a, **kw):
        calls[0] += 1
        first = later and calls[0] == 1
        value = (
            {
                "catalog": {"repositories": ["one"]},
                "tags": {"tags": ["one"]},
                "nexus": {"items": [{"name": "one"}], "continuationToken": "next"},
            }[kind]
            if first
            else bad
        )
        return 200, json.dumps(value).encode(), {"link": '</next>; rel="next"'} if first else {}, None

    monkeypatch.setattr(registry, "_http_request", request)
    fn = {
        "catalog": registry._fetch_registry_catalog,
        "tags": registry._fetch_repository_tags,
        "nexus": registry._fetch_nexus_components,
    }[kind]
    rows, error = fn("qa", 80, *(() if kind == "catalog" else ("repo",)), 1, headers={})
    assert error and ("partial:" in error if later else True)
    assert (len(rows) == 1) if later else rows is None


def test_a21_03_registry_null_tags_remain_legal(monkeypatch):
    monkeypatch.setattr(registry, "_http_request", lambda *a, **kw: (200, b'{"name":"repo","tags":null}', {}, None))
    assert registry._fetch_repository_tags("qa", 80, "repo", 1, headers={}) == ([], None)


def test_a21_04_gitlab_mounts_have_distinct_clone_destinations(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(gitlab.shutil, "which", lambda x: "/usr/bin/git")

    def run(cmd, **kw):
        calls.append(cmd)
        Path(cmd[-1], ".git").mkdir(parents=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(gitlab.subprocess, "run", run)
    results = [
        gitlab._clone_project(
            {"id": 1, "path_with_namespace": "g/p", "http_url_to_repo": f"http://qa:8080/{mount}/g/p.git"},
            "qa",
            8080,
            use_https=False,
            token=None,
            clone_dir=str(tmp_path),
        )
        for mount in ["first", "second"]
    ]
    assert [r["status"] for r in results] == ["cloned", "cloned"]
    assert results[0]["dest"] != results[1]["dest"] and len(calls) == 2


def test_a21_04_gitlab_existing_repo_requires_matching_origin(tmp_path, monkeypatch):
    project = {"id": 1, "path_with_namespace": "g/p", "http_url_to_repo": "http://qa:8080/first/g/p.git"}
    monkeypatch.setattr(gitlab.shutil, "which", lambda x: "/usr/bin/git")

    def clone(cmd, **kw):
        Path(cmd[-1], ".git").mkdir(parents=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(gitlab.subprocess, "run", clone)
    result = gitlab._clone_project(project, "qa", 8080, use_https=False, token=None, clone_dir=str(tmp_path))
    monkeypatch.setattr(
        gitlab.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "http://different/wrong.git\n", ""),
    )
    repeated = gitlab._clone_project(project, "qa", 8080, use_https=False, token=None, clone_dir=str(tmp_path))
    assert repeated["status"] == "failed" and "source" in repeated["error"]
    assert Path(result["dest"], ".git").is_dir()


def test_a21_01_expired_minio_budget_does_not_start_listing():
    consumed = []

    def objects():
        consumed.append(True)
        yield ObjectInfo(bucket="qa", key="image.jpg", size=1)

    result = minio.discover_secrets(NS(), objects(), budget=minio.Budget(time_budget=0))
    assert consumed == [] and "timeout" in result.partial_reasons


@pytest.mark.parametrize("module", ["jenkins", "jupyter"])
def test_partial_coverage_airflow_colors_and_plain_saved_output(module, tmp_path, monkeypatch, capsys):
    from redposture_core.console import Console
    from redposture_core.modules.jenkins import render as jr

    record = {
        "host": "qa",
        "port": 8080,
        "job_discovery_partial": True,
        "discovery_errors": ["text limit reached"],
        "inventory_requested": ["contents"],
        "contents_access": "allowed",
        "contents": [{"name": "first"}],
        "contents_partial": True,
        "contents_error": "item limit reached",
    }
    lines = (
        jr._format_inventory_records(record, "txt")
        if module == "jenkins"
        else token_render.inventory(module, record, "txt")
    )
    coverage = next(line for line in lines if "coverage (status:partial)" in line)

    class Recording:
        def __init__(self):
            self.paints = []

        def _paint(self, text, color, stream):
            self.paints.append((text, color))
            return text

        def plain(self, text):
            pass

    console = Recording()
    colorize = (
        jr._render_colored_jenkins_line
        if module == "jenkins"
        else lambda console, line: token_render.colorize(console, line, module)
    )
    assert colorize(console, coverage)
    assert ("status:partial", "orange") in console.paints
    assert any("coverage" in text and color == "white" for text, color in console.paints)
    assert any("reason=" in text and color == "orange" for text, color in console.paints)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert colorize(Console(no_color=True), coverage)
    assert "\x1b" not in capsys.readouterr().out
    txt, js = tmp_path / "saved.txt", tmp_path / "saved.json"
    txt.write_text("\n".join(lines))
    js.write_text(json.dumps(record))
    assert "\x1b" not in txt.read_text() and "\\u001b" not in js.read_text()


def test_http21_03_session_cap_does_not_mark_complete_contents_partial(monkeypatch):
    def get(ctx, base, path, token):
        return reply(
            [{"id": str(i), "kernel": {}} for i in range(5001)]
            if path == "/api/sessions"
            else {"name": "", "path": "", "type": "directory", "content": []}
        )

    monkeypatch.setattr(jupyter, "_get", get)
    result = jupyter.data_record(
        NS(args=NS(show_sessions=True, show_contents=True), credential=NS()), {"api_endpoint": "http://qa"}
    )
    assert result["sessions_partial"] is True
    assert result["contents_partial"] is False
