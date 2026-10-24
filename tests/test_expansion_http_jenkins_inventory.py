"""Jenkins artifact selection refuses escaping paths and malformed build data."""

from __future__ import annotations

import json
from types import SimpleNamespace as NS
from typing import Any

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.jenkins import actions as jenkins


def reply(value: Any, status: int = 200) -> HttpResponse:
    return HttpResponse(status, json.dumps(value).encode(), {})


def test_jenkins_artifact_walk_rejects_unsafe_and_invalid_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = []
    heads = []
    artifacts = [
        {"fileName": "escape", "relativePath": "../escape"},
        {"fileName": "empty", "relativePath": "a//b"},
        {"fileName": "slash", "relativePath": "a\\b"},
        {"fileName": "control", "relativePath": "a\nb"},
        {"fileName": "", "relativePath": "a"},
        {"fileName": "missing"},
        {"fileName": "report name.txt", "relativePath": "out/report name.txt"},
        {"fileName": "capped.txt", "relativePath": "out/capped.txt"},
    ]

    class Client:
        def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            heads.append((method, url, kwargs))
            return HttpResponse(200, b"", {"content-length": "42"})

    def get(client: Any, base: str, path: str, basic: str | None) -> HttpResponse:
        paths.append(path)
        if path.startswith("/api/json"):
            return reply({"jobs": [{"name": "folder/job"}]})
        return reply(
            {
                "builds": [
                    {"number": True, "artifacts": artifacts},
                    {"number": "bad", "artifacts": artifacts},
                    {"number": 7, "result": "SUCCESS", "artifacts": artifacts},
                ]
            }
        )

    monkeypatch.setattr(jenkins, "_client", lambda ctx: Client())
    monkeypatch.setattr(jenkins, "_get", get)
    ctx = NS(args=NS(show_artifacts=1), credential=NS(username="user", password="pass"))
    result = jenkins.data_record(ctx, {"api_endpoint": "https://qa/mount", "provided_credentials_ok": True})
    assert result["builds"] == [{"job": "folder/job", "number": 7, "result": "SUCCESS"}]
    assert result["artifacts"] == [
        {"job": "folder/job", "build": 7, "name": "report name.txt", "path": "out/report name.txt", "size_bytes": 42}
    ]
    assert len(paths) == 2 and paths[1].startswith("/job/folder%2Fjob/api/json")
    assert heads == [
        (
            "HEAD",
            "https://qa/mount/job/folder%2Fjob/7/artifact/out/report%20name.txt",
            {"headers": {"Authorization": "Basic dXNlcjpwYXNz"}},
        )
    ]


def test_jenkins_invalid_environment_map_is_partial_without_losing_config(monkeypatch: pytest.MonkeyPatch) -> None:
    def get(client: Any, base: str, path: str, basic: str | None) -> HttpResponse:
        if path.startswith("/api/json"):
            return reply({"jobs": [{"name": "job", "lastBuild": {"number": 7}}]})
        return reply({"envMap": []}) if "injectedEnvVars" in path else HttpResponse(200, b"retained", {})

    monkeypatch.setattr(jenkins, "_client", lambda ctx: object())
    monkeypatch.setattr(jenkins, "_get", get)
    result = jenkins.data_record(NS(args=NS(show_jobs=True, discover=True)), {"api_endpoint": "http://qa"})
    assert result["job_configs"] == [{"job": "job", "config": "retained"}]
    assert result["build_envs"] == [] and result["build_logs"] == [{"job": "job", "build": 7, "log": "retained"}]
    assert result["job_discovery_partial"] is True
    assert result["discovery_errors"] == ["job/7: invalid environment map"]
