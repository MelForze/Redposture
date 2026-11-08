"""Source access reports distinguish config/log/env reads from artifact metadata."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.jenkins import actions


def run(monkeypatch, *, denied=None, env_status=200, malformed=False):
    class Pool:
        def request(self, method, url, **kwargs):
            value: dict[str, Any]
            assert method == "GET"
            path = url.removeprefix("http://qa")
            if path.startswith("/api/json?tree=jobs"):
                if denied == "catalog":
                    return HttpResponse(403, b"{}", {})
                value = {"jobs": [{"name": "qa", "firstBuild": {"number": 1}, "lastBuild": {"number": 1}}]}
            elif "tree=artifacts" in path:
                value = {"artifacts": []}
            elif path.endswith("/injectedEnvVars/api/json"):
                if env_status != 200:
                    return HttpResponse(env_status, b'{"password":"not-a-source!42"}', {})
                if malformed:
                    return HttpResponse(200, b'{"envMap":false}', {})
                value = {"envMap": {"DB_PASSWORD": "inactive-env!42"}}
            else:
                raise AssertionError(path)
            return HttpResponse(200, json.dumps(value).encode(), {})

        def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
            assert method == "GET"
            kind = "config" if url.endswith("config.xml") else "log" if url.endswith("consoleText") else None
            assert kind
            status = 403 if denied == kind else 200
            on_response(status, {})
            body = ('password="' + ("error-body!42" if status == 403 else "inactive-" + kind + "!42") + '"\n').encode()
            on_chunk(body)
            return HttpResponse(status, b"", {})

    monkeypatch.setattr(actions, "_client", lambda ctx: actions.ScopedHttpClient(Pool(), 1024 * 1024))
    ctx = SimpleNamespace(
        host="qa",
        port=8080,
        args=SimpleNamespace(discover=True, discover_time=30, timeout=1, show_jobs=True),
        credential=None,
    )
    return actions.data_record(ctx, {"status": "open_no_auth", "api_endpoint": "http://qa"})["content_discovery"]


def test_config_logs_env_and_catalog_are_explicit_independent_sources(monkeypatch):
    result = run(monkeypatch)
    assert result["status"] == "complete"
    rows = {r["id"]: r for r in result["sources"]}
    assert set(rows) == {
        "jenkins.job_catalog",
        "jenkins.job_configs",
        "jenkins.build_logs",
        "jenkins.build_envs",
        "jenkins.artifact_contents",
    }
    assert all(rows[k]["read"] == 1 and rows[k]["complete"] for k in rows if k != "jenkins.artifact_contents")
    assert rows["jenkins.artifact_contents"]["read"] == 0 and rows["jenkins.artifact_contents"]["complete"]
    assert {f["value"] for f in result["findings"]} == {"inactive-config!42", "inactive-log!42", "inactive-env!42"}


@pytest.mark.parametrize("denied,kind", [("catalog", "job_catalog"), ("config", "job_configs"), ("log", "build_logs")])
def test_denied_source_never_becomes_read_or_complete(monkeypatch, denied, kind):
    result = run(monkeypatch, denied=denied)
    row = next(r for r in result["sources"] if r["id"] == "jenkins." + kind)
    assert row["denied"] == 1 and row["read"] == 0 and not row["complete"]
    assert all(f["value"] != "error-body!42" for f in result["findings"])
    assert result["status"] in {"partial", "unavailable"}


@pytest.mark.parametrize("status", [403, 404])
def test_env_plugin_denial_and_missing_endpoint_are_distinct(monkeypatch, status):
    result = run(monkeypatch, env_status=status)
    row = next(r for r in result["sources"] if r["id"] == "jenkins.build_envs")
    assert row["denied"] == int(status == 403) and row["unsupported"] == (status == 404)
    assert row["read"] == 0 and not row["complete"]
    assert all(f["value"] != "not-a-source!42" for f in result["findings"])


def test_invalid_env_map_is_not_reported_read(monkeypatch):
    result = run(monkeypatch, malformed=True)
    row = next(r for r in result["sources"] if r["id"] == "jenkins.build_envs")
    assert row["read"] == 0 and not row["complete"] and not row["denied"]
