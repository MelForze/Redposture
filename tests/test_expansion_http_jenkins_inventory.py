"""Jenkins artifact selection refuses escaping paths and malformed build data."""

from __future__ import annotations

import json
import re
from types import SimpleNamespace as NS
from typing import Any

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.scoped_http import ScopedHttpClient
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.jenkins import actions as jenkins
from redposture_core.storage_discovery import DiscoveryCollector


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
            if "api/json?tree=artifacts[" in url:
                return reply({"artifacts": []})
            heads.append((method, url, kwargs))
            return HttpResponse(200, b"", {"content-length": "42"})

    def get(client: Any, base: str, path: str, basic: str | None) -> HttpResponse:
        if "api/json?tree=artifacts[" in path:
            return reply({"artifacts": []})
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
        if "api/json?tree=artifacts[" in path:
            return reply({"artifacts": []})
        if path.startswith("/api/json"):
            return reply({"jobs": [{"name": "job", "firstBuild": {"number": 7}, "lastBuild": {"number": 7}}]})
        return reply({"envMap": []}) if "injectedEnvVars" in path else HttpResponse(200, b"retained", {})

    monkeypatch.setattr(jenkins, "_client", lambda ctx: object())
    monkeypatch.setattr(jenkins, "_get", get)
    result = jenkins.data_record(NS(args=NS(show_jobs=True, discover=True)), {"api_endpoint": "http://qa"})
    assert result["job_configs"] == [{"job": "job", "config": "retained"}]
    assert result["build_envs"] == [] and result["build_logs"] == [{"job": "job", "build": 7, "log": "retained"}]
    assert result["job_discovery_partial"] is True
    assert result["discovery_errors"] == ["job/7: invalid environment map"]


def test_jenkins_discover_reads_past_twenty_jobs_and_emits_before_next_get(monkeypatch: pytest.MonkeyPatch) -> None:
    emitted: list[str] = []
    fetched: list[str] = []
    jobs = [{"name": f"job-{number:02d}"} for number in range(21)]

    def get(_client: Any, _base: str, path: str, _basic: str | None = None) -> HttpResponse:
        if "api/json?tree=artifacts[" in path:
            return reply({"artifacts": []})
        if path.startswith("/api/json"):
            return reply({"jobs": jobs})
        if len(fetched) == 1:
            assert emitted, "first finding must be emitted before fetching the second job"
        fetched.append(path)
        return HttpResponse(200, b"api_token=glpat-abcdefghijklmnopqrst" if len(fetched) == 1 else b"ordinary", {})

    monkeypatch.setattr(jenkins, "_client", lambda _ctx: object())
    monkeypatch.setattr(jenkins, "_get", get)
    ctx = NS(
        args=NS(show_jobs=True, discover=True, discover_time=5, discover_max_bytes=4096),
        credential=NS(username=None, password=None),
        host="qa",
        port=8080,
        live_emit=lambda lines: emitted.extend(lines),
    )
    result = jenkins.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    assert len(fetched) == 21
    assert result["content_discovery"]["status"] == "complete"
    assert result["content_discovery"]["findings"]


def test_jenkins_discover_retries_oversized_jobs_list_with_real_tree_ranges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs = [{"name": f"job-{index:02d}"} for index in range(12)]
    requested: list[str] = []

    def get(_client: Any, _base: str, path: str, _basic: str | None = None) -> HttpResponse:
        if "api/json?tree=artifacts[" in path:
            return reply({"artifacts": []})
        requested.append(path)
        if path.startswith("/api/json?tree="):
            match = re.search(r"\{(\d+),(\d+)\}$", path)
            if match is None or int(match.group(2)) - int(match.group(1)) > 3:
                return HttpResponse(200, b'{"jobs":[', {}, truncated=True)
            start, end = (int(part) for part in match.groups())
            return reply({"_class": "hudson.model.Hudson", "jobs": jobs[start:end]})
        if path.endswith("/config.xml") and "job-11" in path:
            return HttpResponse(200, b"API_TOKEN=glpat-abcdefghijklmnopqrstuv", {})
        return HttpResponse(200, b"ordinary", {})

    monkeypatch.setattr(jenkins, "_client", lambda _ctx: object())
    monkeypatch.setattr(jenkins, "_get", get)
    ctx = NS(
        args=NS(show_jobs=True, discover=True, discover_time=5, discover_max_bytes=1024),
        credential=NS(username=None, password=None),
        host="qa",
        port=8080,
    )
    result = jenkins.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    discovery = result["content_discovery"]
    assert discovery["status"] == "complete", discovery["partial_reasons"]
    assert len(result["jobs"]) == 12
    assert any(item["value"] == "glpat-abcdefghijklmnopqrstuv" for item in discovery["findings"])
    assert sum(path.endswith("/config.xml") for path in requested) == 12
    assert any("{9,12}" in path for path in requested)


@pytest.mark.parametrize("failure", ["repeated_page", "oversized_single_job"])
def test_jenkins_oversized_job_fallback_does_not_claim_complete_on_bad_pages(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    seen: list[str] = []

    def get(_client: Any, _base: str, path: str, _basic: str | None = None) -> HttpResponse:
        if "api/json?tree=artifacts[" in path:
            return reply({"artifacts": []})
        seen.append(path)
        if "{" not in path or failure == "oversized_single_job":
            return HttpResponse(200, b'{"jobs":[', {}, truncated=True)
        return reply({"_class": "hudson.model.Hudson", "jobs": [{"name": f"job-{index}"} for index in range(100)]})

    monkeypatch.setattr(jenkins, "_get", get)
    ctx = NS(args=NS(discover_time=5, discover_max_bytes=1024), host="qa", port=8080)
    collector = DiscoveryCollector("jenkins", ctx, {"status": "open_no_auth"})
    jobs, _response = jenkins._discovery_jobs(object(), "http://qa", "/api/json?tree=jobs[name]", None, collector)
    if failure == "repeated_page":
        assert jobs is not None and len(jobs) == 100
    else:
        assert jobs is None
    reason = "repeated_job_page" if failure == "repeated_page" else "oversized_single_job"
    assert reason in str(collector.result()["partial_reasons"])
    assert len(seen) < 12


def test_jenkins_discover_denied_jobs_are_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jenkins, "_client", lambda _ctx: object())
    monkeypatch.setattr(jenkins, "_get", lambda *_a: reply({"error": "glpat-should-not-scan"}, 403))
    ctx = NS(args=NS(show_jobs=True, discover=True), credential=NS(username=None, password=None))
    result = jenkins.data_record(ctx, {"api_endpoint": "http://qa", "status": "auth_required"})
    assert result["content_discovery"]["status"] == "unavailable"
    assert result["content_discovery"]["findings"] == []


def test_jenkins_discover_caps_http_body_before_loading() -> None:
    caps: list[int] = []

    class FakePool:
        def request(self, _method: str, _url: str, **kwargs: Any) -> HttpResponse:
            caps.append(int(kwargs["response_size_cap"]))
            return HttpResponse(200, b"<config>glpat-abcdefghijklmnopqrst", {}, truncated=True)

    ctx = NS(args=NS(discover_time=5, discover_max_bytes=32), host="qa", port=8080)
    collector = DiscoveryCollector("jenkins", ctx, {"status": "open_no_auth"})
    response = jenkins._get_discovery(
        ScopedHttpClient(FakePool(), 1024 * 1024), "http://qa", "/job/app/config.xml", None, collector
    )
    assert response is None
    assert caps == [32]
    assert collector.result()["bytes_read"] == 32
    assert collector.result()["status"] == "partial"


def test_jenkins_discover_streams_large_log_past_one_portion(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = (b"ordinary " * 25) + b"\nAPI_TOKEN=glpat-abcdefghijklmnopqrst\n"
    streamed: list[str] = []

    class FakePool:
        def request(self, _method: str, url: str, **kwargs: Any) -> HttpResponse:
            if "api/json?tree=artifacts[" in url:
                return reply({"artifacts": []})
            if "/api/json?tree=" in url and "/job/" not in url:
                return reply({"jobs": [{"name": "app", "firstBuild": {"number": 1}, "lastBuild": {"number": 1}}]})
            if url.endswith("/injectedEnvVars/api/json"):
                return HttpResponse(404, b"", {})
            return HttpResponse(200, payload[: kwargs["response_size_cap"]], {}, truncated=True)

        def request_stream(self, _method: str, url: str, *, on_chunk, chunk_size: int, **_kwargs: Any) -> HttpResponse:
            streamed.append(url)
            _kwargs["on_response"](200, {"Content-Type": "text/plain"})
            body = payload if url.endswith("/consoleText") else b"<project/>"
            for start in range(0, len(body), chunk_size):
                on_chunk(body[start : start + chunk_size])
            return HttpResponse(200, b"", {})

    monkeypatch.setattr(jenkins, "_client", lambda _ctx: ScopedHttpClient(FakePool(), 1024 * 1024))
    ctx = NS(
        args=NS(show_jobs=True, discover=True, discover_time=5, discover_max_bytes=128),
        credential=NS(username=None, password=None),
        host="qa",
        port=8080,
    )
    result = jenkins.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    discovery = result["content_discovery"]
    assert discovery["status"] == "complete", discovery["partial_reasons"]
    assert any("consoleText" in url for url in streamed)
    assert sum(item["type"] == "gitlab_token" for item in discovery["findings"]) == 1
    assert sum(item["value"] == "glpat-abcdefghijklmnopqrst" for item in discovery["findings"]) == 1


@pytest.mark.parametrize("token", ["glpat-" + "Ab9_" * 350_000, "glpat-abcdefghijklmnopqrstuv"])
def test_jenkins_discover_streams_oversized_injected_environment(monkeypatch: pytest.MonkeyPatch, token: str) -> None:
    env_body = json.dumps({"envMap": {"API_TOKEN": token}}).encode()
    streamed: list[str] = []

    class FakePool:
        def request(self, _method: str, url: str, **kwargs: Any) -> HttpResponse:
            if "api/json?tree=artifacts[" in url:
                return reply({"artifacts": []})
            if "/api/json?tree=" in url and "/job/" not in url:
                return reply({"jobs": [{"name": "app", "firstBuild": {"number": 1}, "lastBuild": {"number": 1}}]})
            if url.endswith("/injectedEnvVars/api/json"):
                return HttpResponse(200, env_body[: kwargs["response_size_cap"]], {}, truncated=True)
            return HttpResponse(200, b"<project/>" if url.endswith("/config.xml") else b"ordinary log", {})

        def request_stream(
            self, _method: str, url: str, *, on_chunk, on_response=None, chunk_size: int, **_kwargs: Any
        ) -> HttpResponse:
            streamed.append(url)
            if on_response is not None:
                on_response(200, {"Content-Type": "application/json" if url.endswith("/api/json") else "text/plain"})
            body = (
                env_body
                if url.endswith("/api/json")
                else b"<project/>"
                if url.endswith("/config.xml")
                else b"ordinary log"
            )
            for position in range(0, len(body), chunk_size):
                on_chunk(body[position : position + chunk_size])
            return HttpResponse(200, b"", {})

    monkeypatch.setattr(jenkins, "_client", lambda _ctx: ScopedHttpClient(FakePool(), 1024 * 1024))
    ctx = NS(
        args=NS(show_jobs=True, discover=True, discover_time=10, discover_max_bytes=300_000_000),
        credential=NS(username=None, password=None),
        host="qa",
        port=8080,
    )
    result = jenkins.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    discovery = result["content_discovery"]
    assert discovery["status"] == "complete", discovery["partial_reasons"]
    assert any(url.endswith("/injectedEnvVars/api/json") for url in streamed)
    assert len(discovery["findings"]) == 1
    assert any(
        "".join(value.iter_text_chunks()) == token if isinstance(value, DiskBackedText) else value == token
        for value in (item["value"] for item in discovery["findings"])
    )


def test_jenkins_discover_optional_env_plugin_absent_is_not_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    def get(_client: Any, _base: str, path: str, _basic: str | None = None) -> HttpResponse:
        if "api/json?tree=artifacts[" in path:
            return reply({"artifacts": []})
        if path.startswith("/api/json"):
            return reply({"jobs": [{"name": "job", "firstBuild": {"number": 1}, "lastBuild": {"number": 1}}]})
        if path.endswith("/config.xml"):
            return HttpResponse(200, b"<project><description>glpat-abcdefghijklmnopqrst</description></project>", {})
        if path.endswith("/consoleText"):
            return HttpResponse(200, b"ordinary build log", {})
        return HttpResponse(404, b"not installed", {})

    monkeypatch.setattr(jenkins, "_client", lambda _ctx: object())
    monkeypatch.setattr(jenkins, "_get", get)
    ctx = NS(args=NS(show_jobs=True, discover=True), credential=NS(username=None, password=None))
    result = jenkins.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "complete"
    assert result["content_discovery"]["findings"]


def test_jenkins_discover_walks_folder_and_older_build_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    fetched: list[str] = []

    def get(_client: Any, _base: str, path: str, _basic: str | None = None) -> HttpResponse:
        if "api/json?tree=artifacts[" in path:
            return reply({"artifacts": []})
        fetched.append(path)
        if path.startswith("/api/json"):
            return reply({"jobs": [{"name": "team", "_class": "com.cloudbees.hudson.plugins.folder.Folder"}]})
        if path.startswith("/job/team/api/json"):
            return reply(
                {
                    "jobs": [
                        {
                            "name": "app",
                            "_class": "hudson.model.FreeStyleProject",
                            "firstBuild": {"number": 1},
                            "lastBuild": {"number": 2},
                        }
                    ]
                }
            )
        if path.endswith("/config.xml"):
            return HttpResponse(200, b"<project/>", {})
        if path.endswith("/1/consoleText"):
            return HttpResponse(200, b"glpat-abcdefghijklmnopqrst", {})
        if path.endswith("/2/consoleText"):
            return HttpResponse(200, b"ordinary log", {})
        return HttpResponse(404, b"not installed", {})

    monkeypatch.setattr(jenkins, "_client", lambda _ctx: object())
    monkeypatch.setattr(jenkins, "_get", get)
    ctx = NS(args=NS(show_jobs=True, discover=True), credential=NS(username=None, password=None))
    result = jenkins.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["object_path"] == "$.job.team/app.build.1.log" for item in result["content_discovery"]["findings"])
    assert "/job/team/job/app/2/consoleText" in fetched
