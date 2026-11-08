"""Artifact catalogs, paths and content obey the read-only discovery budget."""

from __future__ import annotations

import io
import json
import re
import zipfile
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_sources import SourceManifest
from redposture_core.modules.jenkins import actions
from redposture_core.modules.jenkins.actions import _artifact_url
from redposture_core.modules.jenkins.discover import scan_build_artifacts
from redposture_core.storage_discovery import DiscoveryCollector


def collector():
    return DiscoveryCollector(
        "jenkins",
        SimpleNamespace(host="qa", port=8080, args=SimpleNamespace(discover_time=30)),
        {"status": "auth_valid"},
    )


def response(items, **kw):
    return HttpResponse(200, json.dumps({"artifacts": items}).encode(), {}, **kw)


def scan(c, m, get, read, *, limit=None):
    scan_build_artifacts(
        c,
        build_path="/job/team/job/build/17",
        source="job.team/build.build.17",
        get_page=get,
        artifact_path=lambda rel: _artifact_url("", "/job/team/job/build", 17, rel),
        read_content=read,
        manifest=m,
        limit=limit,
    )


def test_catalog_pages_all_artifacts_without_duplicates_or_head_requests():
    c, m, reads, calls = collector(), SourceManifest(), [], []
    emitted = []
    c.ctx.live_emit = emitted.extend
    items = [{"relativePath": f"configs/app-{i}.json"} for i in range(250)]

    def get(path):
        calls.append(path)
        start, end = map(int, re.search(r"\{(\d+),(\d+)\}$", path).groups())
        if start:
            assert emitted, "completed content must be available before the next catalog page"
        return response(items[start:end])

    def read(path, source, media):
        reads.append(path)
        assert source.endswith("/artifact/" + media)
        assert c.add(source, {"password": "inactive-artifact!42"}, charge=False)
        return True, 200

    scan(c, m, get, read)
    r = c.result()
    assert r["status"] == "complete"
    assert len(calls) == 3 and len(reads) == len(set(reads)) == 250
    assert len(r["findings"]) == 1 and r["findings"][0]["occurrence_count"] == 250
    assert m.result()[0]["read"] == 250 and m.result()[0]["complete"]


def test_cancelled_artifact_walk_keeps_closed_findings_and_repeat_is_independent():
    from redposture_core.scheduler import NestedSchedulerCancelled

    def attempt(cancel):
        c, m, reads, emitted = collector(), SourceManifest(), [], []
        c.ctx.live_emit = emitted.extend
        c.ctx.cancelled = lambda: cancel and bool(reads)

        def read(path, source, media):
            c.add(source, {"password": "inactive-" + media + "!42"}, charge=False)
            reads.append(path)
            return True, 200

        if cancel:
            with pytest.raises(NestedSchedulerCancelled):
                scan(c, m, lambda p: response([{"relativePath": "first"}, {"relativePath": "second"}]), read)
        else:
            scan(c, m, lambda p: response([{"relativePath": "first"}, {"relativePath": "second"}]), read)
        return c.result(), m.result()[0], reads, emitted

    interrupted, row, reads, emitted = attempt(True)
    assert interrupted["status"] == "partial" and not row["complete"]
    assert len(reads) == len(emitted) == row["read"] == 1
    assert [f["value"] for f in interrupted["findings"]] == ["inactive-first!42"]
    for _ in range(2):
        complete, row, reads, emitted = attempt(False)
        assert complete["status"] == "complete" and row["complete"]
        assert row["read"] == len(reads) == len(emitted) == 2
        assert {f["value"] for f in complete["findings"]} == {"inactive-first!42", "inactive-second!42"}


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_catalog_access_failure_never_means_empty_complete(status):
    c, m = collector(), SourceManifest()
    scan(c, m, lambda p: HttpResponse(status, b"{}", {}), lambda *a: pytest.fail("no content request"))
    assert c.result()["status"] != "complete"
    assert not m.result()[0]["complete"] and m.result()[0]["read"] == 0
    assert bool(m.result()[0]["denied"]) == (status in {401, 403})


def test_repeated_page_stops_and_retains_completed_content():
    c, m, seen = collector(), SourceManifest(), []
    items = [{"relativePath": f"configs/app-{i}.json"} for i in range(100)]

    def read(path, source, media):
        seen.append(path)
        c.add(source, {"password": "inactive-completed!42"}, charge=False)
        return True, 200

    scan(c, m, lambda p: response(items), read)
    assert len(seen) == 100
    assert c.result()["status"] == "partial"
    assert any("repeated_artifact_page" in r for r in c.result()["partial_reasons"])
    assert c.result()["findings"][0]["occurrence_count"] == 100
    assert not m.result()[0]["complete"]


@pytest.mark.parametrize("bad", ["../secret", "/absolute", "http://evil.invalid/data", "a\\b", "a//b", "a\0b"])
def test_artifact_path_cannot_escape_the_selected_build(bad):
    c, m = collector(), SourceManifest()
    scan(c, m, lambda p: response([{"relativePath": bad}]), lambda *a: pytest.fail("invalid path fetched"))
    assert c.result()["status"] == "partial"
    assert not m.result()[0]["complete"]


def test_truncated_page_retries_same_offset_and_shrinks_without_losing_entries():
    c, m, calls, read_paths = collector(), SourceManifest(), [], []

    def get(path):
        calls.append(path)
        if len(calls) == 1:
            return response([], truncated=True)
        return response([{"relativePath": "settings.json"}])

    def read(path, source, media):
        read_paths.append(path)
        c.add(source, {"password": "inactive-content!42"}, charge=False)
        return True, 200

    scan(c, m, get, read)
    assert calls[0].endswith("{0,100}") and calls[1].endswith("{0,50}")
    assert len(read_paths) == 1 and m.result()[0]["complete"]


def test_failure_and_denial_during_content_keep_completed_values_and_continue():
    c, m, reads = collector(), SourceManifest(), []

    def read(path, source, media):
        reads.append(media)
        if media == "broken":
            raise OSError("read failed")
        if media == "denied":
            c.partial(source, "access_denied")
            return False, 403
        c.add(source, {"password": "inactive-preserved!42"}, charge=False)
        return True, 200

    scan(c, m, lambda p: response([{"relativePath": x} for x in ["first", "broken", "denied", "last"]]), read)
    assert reads == ["first", "broken", "denied", "last"]
    assert c.result()["status"] == "partial" and len(c.result()["findings"]) == 1
    assert m.result()[0]["read"] == 2 and m.result()[0]["denied"] == 1 and not m.result()[0]["complete"]


def test_explicit_limit_and_unreadable_format_are_partial_even_if_wire_read_succeeds():
    for limit in (None, 1):
        c, m = collector(), SourceManifest()

        def read(path, source, media, *, limit=limit, c=c):
            if limit is None:
                c.partial(source, "unsupported_content")
            return True, 200

        scan(c, m, lambda p: response([{"relativePath": "a"}, {"relativePath": "b"}]), read, limit=limit)
        assert c.result()["status"] == "partial" and not m.result()[0]["complete"]


@pytest.mark.parametrize("denied", [False, True])
def test_module_reads_artifact_json_and_archive_using_authenticated_stream_without_build_execution(monkeypatch, denied):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("config/.env", 'password="inactive-archived!42"\n')
    files = {"settings.json": b'{"password":"inactive-config!42"}', "bundle.zip": archive.getvalue()}
    requests, emitted = [], []

    class Pool:
        def request(self, method, url, **kwargs):
            assert method == "GET"
            assert kwargs["headers"]["Authorization"] == "Basic dXNlcjpwYXNz"
            path = url.removeprefix("http://qa")
            requests.append(path)
            if path.startswith("/api/json?tree=jobs"):
                data: dict[str, Any] = {
                    "jobs": [{"name": "demo", "firstBuild": {"number": 1}, "lastBuild": {"number": 1}}]
                }
            elif "/api/json?tree=artifacts" in path:
                data = {"artifacts": [{"relativePath": key} for key in files]}
            elif path.endswith("/injectedEnvVars/api/json"):
                data = {"envMap": {}}
            else:
                pytest.fail("unexpected metadata request " + path)
            return HttpResponse(200, json.dumps(data).encode(), {})

        def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
            assert method == "GET"
            assert kwargs["headers"]["Authorization"] == "Basic dXNlcjpwYXNz"
            assert kwargs["allow_cross_origin_redirects"] is False
            path = url.removeprefix("http://qa")
            requests.append(path)
            if path.endswith("config.xml"):
                raw = b"<project/>"
            elif path.endswith("consoleText"):
                raw = b"Finished: SUCCESS\n"
            else:
                name = path.rsplit("/", 1)[-1]
                if name == "bundle.zip":
                    assert any("inactive-config!42" in line for line in emitted)
                raw = files[name]
                if name == "bundle.zip" and denied:
                    on_response(403, {})
                    on_chunk(b'password="not-an-artifact-error-echo!42"\n')
                    return HttpResponse(403, b"", {})
            on_response(200, {})
            for start in range(0, len(raw), 7):
                on_chunk(raw[start : start + 7])
            return HttpResponse(200, b"", {})

    monkeypatch.setattr(actions, "_client", lambda ctx: actions.ScopedHttpClient(Pool(), 1024 * 1024))
    ctx = SimpleNamespace(
        host="qa",
        port=8080,
        args=SimpleNamespace(discover=True, discover_time=30, show_jobs=True, timeout=1),
        live_emit=emitted.extend,
        credential=SimpleNamespace(username="user", password="pass"),
    )
    result = actions.data_record(
        ctx, {"api_endpoint": "http://qa", "status": "auth_valid", "provided_credentials_ok": True}
    )["content_discovery"]
    assert result["status"] == ("partial" if denied else "complete"), result["partial_reasons"]
    expected = {"inactive-config!42"} if denied else {"inactive-config!42", "inactive-archived!42"}
    assert {row["value"] for row in result["findings"]} == expected
    assert result["sources"][0]["read"] == (1 if denied else 2)
    assert result["sources"][0]["denied"] == int(denied)
    assert result["sources"][0]["complete"] is not denied
    assert all("\x1b" not in line for line in emitted)
    assert len([p for p in requests if "/artifact/" in p]) == 2
