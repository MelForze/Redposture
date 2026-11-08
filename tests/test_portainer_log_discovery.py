"""Docker logs are finite read streams, not attach/exec or merged channels."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.portainer.discover import DockerLogFrames, scan_container_logs
from redposture_core.scheduler import NestedSchedulerCancelled
from redposture_core.storage_discovery import DiscoveryCollector


def frame(channel, body):
    return bytes([channel, 0, 0, 0]) + len(body).to_bytes(4, "big") + body


@pytest.mark.parametrize("portion", [1, 3, 7, 8, 17, 65536])
def test_log_frames_preserve_exact_channels_and_never_buffer_a_payload(portion):
    values = []
    body = frame(1, b"stdout-a") + frame(2, b"stderr-b") + frame(1, b"stdout-c") + frame(2, b"")
    decoder = DockerLogFrames(lambda name, data: values.append((name, data)), False)
    for i in range(0, len(body), portion):
        decoder.feed(body[i : i + portion])
        assert len(decoder.header) <= 8
    decoder.finish()
    assert b"".join(v for k, v in values if k == "stdout") == b"stdout-astdout-c"
    assert b"".join(v for k, v in values if k == "stderr") == b"stderr-b"


@pytest.mark.parametrize("size", [10_000_000, 100_000_000])
def test_large_frame_has_constant_decoder_state(size):
    n = 0

    def emit(_name, data):
        nonlocal n
        n += len(data)

    decoder = DockerLogFrames(emit, False)
    decoder.feed(b"\x01\0\0\0" + size.to_bytes(4, "big"))
    portion = b"x" * 65536
    for start in range(0, size, len(portion)):
        decoder.feed(portion[: min(len(portion), size - start)])
        assert not decoder.header
    decoder.finish()
    assert n == size and decoder.remaining == 0


def run(body, *, tty=False, status=200, error=None, portion=7, cancel=False):
    emitted = []
    cancelled = [False]
    c = DiscoveryCollector(
        "portainer",
        SimpleNamespace(
            host="qa",
            port=9000,
            args=SimpleNamespace(discover_time=30),
            live_emit=emitted.extend,
            cancelled=lambda: cancelled[0],
        ),
        {"status": "auth_valid"},
    )

    class Pool:
        def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
            assert method == "GET" and "follow=0" in url and "tail=all" in url
            assert kwargs["allow_cross_origin_redirects"] is False
            assert kwargs["preserve_authorization_on_cross_origin"] is False
            assert kwargs["headers"]["Authorization"] == "Bearer local-token"
            on_response(status, {})
            for i in range(0, len(body), portion):
                on_chunk(body[i : i + portion])
                if cancel and emitted:
                    cancelled[0] = True
            if status == 200 and b"\n" in body:
                assert emitted or b"\0" in body or error, "closed plain lines must be published before return"
            return HttpResponse(status, b"", {}, error=error, truncated=bool(error))

    try:
        outcome = scan_container_logs(
            c,
            Pool(),
            "http://qa/logs?follow=0&tail=all",
            "container/c/logs",
            tty=tty,
            headers={"Authorization": "Bearer local-token"},
            timeout=1,
        )
    except NestedSchedulerCancelled:
        assert cancel
        outcome = (False, 200)
    return c.result(), emitted, outcome


@pytest.mark.parametrize("portion", [1, 7, 65536])
@pytest.mark.parametrize("tty", [False, True])
def test_complete_log_secret_survives_chunk_and_frame_boundaries(tty, portion):
    raw = 'password="inactive-log-λ!42"\n'.encode()
    body = raw if tty else frame(1, raw[:13]) + frame(1, raw[13:])
    report, emitted, (ok, status) = run(body, tty=tty, portion=portion)
    assert report["status"] == "complete" and ok and status == 200
    assert [(r["type"], r["value"]) for r in report["findings"]] == [("password", "inactive-log-λ!42")]
    assert len(emitted) == 1 and "\x1b" not in emitted[0]


def test_interleaved_streams_do_not_create_a_secret_from_different_channels():
    body = frame(1, b'password="inactive-') + frame(2, b'stderr-is-not-the-suffix"\n') + frame(1, b'stdout!42"\n')
    report, _, _ = run(body)
    assert [r["value"] for r in report["findings"]] == ["inactive-stdout!42"]
    assert report["findings"][0]["object_path"].startswith("$.container/c/logs/stdout")


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_error_body_is_never_parsed_as_logs(status):
    r, emitted, (ok, _) = run(b'password="error-echo-not-source!42"\n', status=status)
    assert not ok and not emitted and not r["findings"]
    assert r["status"] == ("unavailable" if status in {401, 403} else "partial")


@pytest.mark.parametrize("fault", ["short-header", "short-payload", "bad-reserved", "transport"])
def test_incomplete_log_response_keeps_closed_values_and_not_truncated_candidates(fault):
    body = frame(1, b'password="inactive-completed!42"\n')
    error = None
    if fault == "short-header":
        body += b"\x01\0"
    elif fault == "short-payload":
        body += b'\x01\0\0\0\0\0\0\xffpassword="unfinished'
    elif fault == "bad-reserved":
        body += b"\x01bad\0\0\0\x10password=invalid"
    else:
        body += frame(1, b'password="unfinished')
        error = "read timeout"
    r, _, (ok, _) = run(body, error=error)
    assert not ok and r["status"] == "partial"
    assert [row["value"] for row in r["findings"]] == ["inactive-completed!42"]


def test_unknown_tty_is_explicitly_partial_even_when_frame_can_be_read():
    r, _, (ok, _) = run(frame(1, b'password="inactive-readable!42"\n'), tty=None)
    assert not ok and r["status"] == "partial"
    assert r["findings"][0]["value"] == "inactive-readable!42"
    assert any("tty_setting_unavailable" in reason for reason in r["partial_reasons"])


def test_large_value_is_full_and_only_published_after_end():
    value = "inactive-" + "Ab0λ " * 20000
    r, _, (ok, _) = run(frame(1, ('password="' + value + '"\n').encode()), portion=1024)
    assert ok and r["status"] == "complete"
    got = r["findings"][0]["value"]
    assert isinstance(got, DiskBackedText)
    assert got.digest == hashlib.sha256(value.encode()).hexdigest()


def test_cancel_stops_read_and_keeps_completed_live_value():
    r, emitted, (ok, _) = run(
        frame(1, b'password="inactive-before-cancel!42"\n') + frame(1, b"ordinary later data"), cancel=True
    )
    assert not ok and r["status"] == "partial"
    assert len(emitted) == 1 and [row["value"] for row in r["findings"]] == ["inactive-before-cancel!42"]
    assert any("cancelled" in reason for reason in r["partial_reasons"])


@pytest.mark.parametrize("log_status", [200, 403])
def test_portainer_adapter_reads_logs_only_for_selected_environment_and_reports_source_acl(monkeypatch, log_status):
    from redposture_core import web_panels
    from redposture_core.clients import http_session
    from redposture_core.storage_discovery import discover_portainer_sources

    calls = []

    class Pool:
        def __init__(self, **kwargs):
            pass

        def close(self):
            pass

        def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
            assert method == "GET"
            assert kwargs["headers"]["Authorization"] == "Bearer local-token"
            assert url.startswith("http://qa:9000/api/endpoints/2/docker/containers/abc/logs?")
            assert "follow=0" in url and "tail=all" in url
            calls.append(url)
            on_response(log_status, {})
            body = (
                frame(1, b'password="inactive-portainer-log!42"\n')
                if log_status == 200
                else b'password="not-a-source-error-body!42"\n'
            )
            for i in range(0, len(body), 3):
                on_chunk(body[i : i + 3])
            return HttpResponse(log_status, b"", {})

    def get(_pool, _base, path, **kwargs):
        calls.append(path)
        assert kwargs["headers"]["Authorization"] == "Bearer local-token"
        if path == "/api/stacks":
            body: Any = []
        elif path == "/api/endpoints/2/docker/containers/abc/json":
            body = {"Config": {"Tty": False, "Env": []}}
        elif path == "/api/endpoints/2/docker/configs":
            return HttpResponse(503, b"{}", {})
        elif path == "/api/endpoints/2/docker/info":
            body = {"Swarm": {"LocalNodeState": "inactive"}}
        else:
            pytest.fail("outside requested environment or unexpected API: " + path)
        return HttpResponse(200, json.dumps(body).encode(), {})

    monkeypatch.setattr(http_session, "HttpSessionPool", Pool)
    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(host="qa", port=9000, args=SimpleNamespace(discover_time=30, timeout=1, endpoint="2"))
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000", "session_token": "local-token"}}
    c = DiscoveryCollector("portainer", ctx, record)
    discover_portainer_sources(
        ctx,
        record,
        {
            "environments": {"records": [{"Id": 2, "Name": "selected"}]},
            "containers": {"records": [{"environment": 2, "Id": "abc"}]},
        },
        c,
    )
    r = c.result()
    assert r["status"] == ("complete" if log_status == 200 else "partial"), r["partial_reasons"]
    assert [row["value"] for row in r["findings"]] == (["inactive-portainer-log!42"] if log_status == 200 else [])
    source = next(row for row in r["sources"] if row["id"] == "portainer.container_logs")
    assert source["requested"] == 1 and source["complete"] == (log_status == 200)
    assert source["denied"] == int(log_status == 403)
    assert all("/endpoints/3/" not in path for path in calls)
