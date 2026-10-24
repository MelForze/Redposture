"""Native Elastic detection retains root, late and denied fingerprints."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpApiClient, HttpResponse, join_http_target_path, pin_http_redirect_path
from redposture_core.clients.tls_cache import shared_client_ssl_context
from redposture_core.modules.elastic import actions, stage
from redposture_core.modules.elastic.http_session import ElasticHttpSession
from redposture_core.targeting import ScanTargetSpec


def _ctx():
    return SimpleNamespace(
        host="127.0.0.1",
        port=9200,
        target=ScanTargetSpec(host="127.0.0.1", scheme="http", explicit_port=9200, path="/mounted"),
        args=SimpleNamespace(timeout=1, retries=0, debug=False),
        credential=SimpleNamespace(username=None, password=None, token=None, source="anonymous"),
        lifecycle_state=actions.ElasticLifecycleState(),
        debug_emit=None,
    )


class Native:
    timeout = 1
    retries = 0
    max_bytes = 262144
    ssl_context = shared_client_ssl_context(insecure=True)

    def __init__(self, respond):
        self.respond = respond

    async def close(self):
        pass

    async def get(self, url, *, headers=None):
        await asyncio.sleep(0)
        return self.respond(url, headers)


@pytest.mark.parametrize(
    "case",
    [
        "root",
        "denied",
        "opensearch",
        "nodes",
        "auth_endpoint",
        "authinfo",
        "soft_late",
        "negative",
        "gateway",
        "malformed",
        "offline",
        "tls_fallback",
        "redirect",
        "redirect_late",
    ],
)
def test_full_native_record_and_request_parity(monkeypatch, case):
    calls = []
    monkeypatch.setattr(actions, "utc_now_iso", lambda: "fixed")
    monkeypatch.setattr(actions, "_DETECT_SLOW_PROBE_THRESHOLD", float("inf"))

    def respond(url, headers):
        calls.append((url, dict(headers or {})))
        path = urlsplit(url).path.removeprefix("/mounted").removeprefix("/moved") or "/"
        if case == "offline" or case == "tls_fallback" and url.startswith("http:"):
            error = (
                "[SSL: WRONG_VERSION_NUMBER] wrong version number" if case == "tls_fallback" else "connection refused"
            )
            return HttpResponse(0, b"", {}, error=error, request_url=url, final_url=url)
        data: dict[str, Any]
        code, data, h = 200, {}, {"Content-Type": "application/json"}
        if case == "auth_endpoint" and path == "/":
            code = 404
        if case in {"root", "redirect", "tls_fallback"}:
            data = {
                "name": "qa",
                "cluster_name": "qa",
                "version": {"number": "8.17.3", "build_flavor": "default"},
                "tagline": "You Know, for Search",
            }
            h["X-Elastic-Product"] = "Elasticsearch"
        elif case == "denied":
            code, data = (
                401,
                {
                    "error": {"type": "security_exception", "reason": "missing authentication credentials"},
                    "status": 401,
                },
            )
        elif case == "opensearch":
            code, data = 401, {"message": "Unauthorized"}
            h["WWW-Authenticate"] = 'Basic realm="OpenSearch Security"'
        elif case in {"nodes", "redirect_late"} and path == "/_nodes":
            data = {"nodes": {"qa": {"version": "8.17.3"}}}
        elif case == "auth_endpoint" and path == "/_security/_authenticate":
            code, data = 401, {"error": {"type": "security_exception", "reason": "missing authentication credentials"}}
        elif case == "authinfo" and path == "/_plugins/_security/authinfo":
            data = {"user_name": "anonymous"}
        elif case == "soft_late" and path == "/_cluster/health":
            data = {"cluster_name": "qa", "status": "yellow"}
        body = json.dumps(data).encode()
        if case == "soft_late" and path == "/_cat/health":
            body, h = b"cluster status node.total node.data\nqa yellow 1 1", {"Content-Type": "text/plain"}
        elif case == "gateway":
            body, h = b"<html>gateway login</html>", {"Content-Type": "text/html"}
        elif case == "malformed":
            body = b"{invalid"
        final = (
            url.replace("http://127.0.0.1:9200/mounted", "https://127.0.0.2:9243/moved")
            if case in {"redirect", "redirect_late"}
            else url
        )
        response = HttpResponse(
            code, body, h, request_url=url, final_url=final, redirect_history=(url,) if final != url else ()
        )
        pin_http_redirect_path(response, method="GET")
        return response

    def sync_request(session, scheme, method, path, headers=None, data=None):
        url = f"{scheme}://{session._authority(scheme)}{join_http_target_path(path)}"
        return respond(url, headers)

    monkeypatch.setattr(ElasticHttpSession, "request", sync_request)
    # Redirected origins use the established generic HTTP client path.
    monkeypatch.setattr(HttpApiClient, "request", lambda self, method, url, **kw: respond(url, kw.get("headers")))
    ctx = _ctx()
    spec = stage.build_elastic_spec(ctx.args)
    assert spec.detect is not None
    expected = spec.detect(ctx).to_dict()
    expected_calls = list(calls)
    calls.clear()
    original_state = ctx.lifecycle_state
    ctx = _ctx()
    monkeypatch.setattr(ElasticHttpSession, "request", lambda *_a, **_kw: pytest.fail("blocking Elastic session"))
    monkeypatch.setattr(HttpApiClient, "request", lambda *_a, **_kw: pytest.fail("blocking generic client"))
    assert spec.detect_async is not None
    got = asyncio.run(spec.detect_async(ctx, Native(respond))).to_dict()
    for record in (expected, got):
        record.pop("elapsed_ms", None)
        record.pop("stage_durations_ms", None)
        for item in record.get("stages", []):
            item.pop("duration_ms", None)
    assert got == expected
    assert calls == expected_calls
    assert got["is_elastic"] is (case not in {"negative", "gateway", "malformed", "offline"})
    assert ctx.lifecycle_state.session is None
    for key in ("origin_scheme", "origin_host", "origin_port"):
        assert getattr(ctx.lifecycle_state, key) == getattr(original_state, key)
    if case == "soft_late":
        assert [item["path"] for item in got["detect_probe_trace"]] == [
            "/",
            "/_nodes?filter_path=nodes.*.version",
            "/_security/_authenticate",
            "/_plugins/_security/authinfo",
            "/_cluster/health",
            "/_cat/health",
        ]
    if case in {"denied", "opensearch", "auth_endpoint"}:
        assert got["auth_required"] is True


def test_slow_confirmation_never_starts_nested_event_loop(monkeypatch):
    ctx = _ctx()
    monkeypatch.setattr(actions, "_DETECT_SLOW_PROBE_THRESHOLD", -1)
    monkeypatch.setattr(actions, "probe_direct_paths", lambda *_a: pytest.fail("nested asyncio.run"))
    monkeypatch.setattr(actions.urllib.request, "getproxies", lambda: pytest.fail("sync proxy inspection"))

    def respond(url, headers):
        body = b'{"nodes":{"qa":{"version":"8.17.3"}}}' if "_nodes?" in url else b"{}"
        return HttpResponse(200, body, {}, request_url=url, final_url=url)

    spec = stage.build_elastic_spec(ctx.args)
    assert spec.detect_async is not None
    record = asyncio.run(spec.detect_async(ctx, Native(respond))).to_dict()
    assert record["is_elastic"] is True
    assert record["server_version"] == "8.17.3"


def test_cancellation_closes_unclaimed_sync_session(monkeypatch):
    ctx = _ctx()
    sessions = []
    original = actions._make_lifecycle_session

    def make_session(context):
        session = original(context)
        sessions.append(session)
        return session

    monkeypatch.setattr(actions, "_make_lifecycle_session", make_session)
    monkeypatch.setattr(ElasticHttpSession, "request", lambda *_a, **_kw: pytest.fail("sync request"))

    async def run():
        entered = asyncio.Event()

        class Waiting(Native):
            async def get(self, url, *, headers=None):
                entered.set()
                await asyncio.Event().wait()

        spec = stage.build_elastic_spec(ctx.args)
        assert spec.detect_async is not None
        task = asyncio.create_task(spec.detect_async(ctx, Waiting(None)))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert ctx.lifecycle_state.session is None
    assert sessions[0].closed is True
    assert sessions[0]._owner_thread_id is None


def test_interleaved_targets_keep_their_origin_and_confirmation_records(monkeypatch):
    prior_bindings = dict(actions._THREAD_LOCAL_ELASTIC_SESSION.__dict__)
    monkeypatch.setattr(ElasticHttpSession, "request", lambda *_a, **_kw: pytest.fail("sync request"))
    monkeypatch.setattr(actions, "_DETECT_SLOW_PROBE_THRESHOLD", float("inf"))
    contexts = []

    async def run_one(index):
        ctx = _ctx()
        ctx.host = f"127.0.0.{index}"
        ctx.target = ScanTargetSpec(host=ctx.host, scheme="http", explicit_port=9200, path=f"/target{index}")
        contexts.append(ctx)

        def respond(url, headers):
            assert url.startswith(f"http://127.0.0.{index}:9200/target{index}/")
            data = {"nodes": {"qa": {"version": f"8.17.{index}"}}} if "_nodes?" in url else {}
            return HttpResponse(200, json.dumps(data).encode(), {}, request_url=url, final_url=url)

        spec = stage.build_elastic_spec(ctx.args)
        assert spec.detect_async is not None
        return (await spec.detect_async(ctx, Native(respond))).to_dict()

    async def run():
        return await asyncio.gather(*(run_one(index) for index in range(1, 9)))

    records = asyncio.run(run())
    assert [item["server_version"] for item in records] == [f"8.17.{index}" for index in range(1, 9)]
    assert [ctx.lifecycle_state.origin_host for ctx in contexts] == [f"127.0.0.{index}" for index in range(1, 9)]
    assert actions._THREAD_LOCAL_ELASTIC_SESSION.__dict__ == prior_bindings
    assert all(ctx.lifecycle_state.session is None for ctx in contexts)
