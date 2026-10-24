"""Native Kube detection shares the complete synchronous decision tree."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse, pin_http_redirect_path
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.clients.tls_cache import shared_client_ssl_context
from redposture_core.modules.kubeapi import actions, stage
from redposture_core.modules.kubeapi.http_session import KubeApiHttpSession
from redposture_core.targeting import ScanTargetSpec
from tests.test_stage_kubeapi import _kube_args


def _context(args, target=None):
    return SimpleNamespace(
        host="127.0.0.1",
        port=6443,
        args=args,
        target=target,
        credential=SimpleNamespace(username=None, password=None, token=None),
        lifecycle_state=actions.KubeApiLifecycleState(),
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
    ["open", "denied", "limited", "api_only", "typed_auth", "negative", "malformed", "offline", "upgrade", "redirect"],
)
def test_complete_records_requests_and_lifecycle_match(monkeypatch, case):
    calls = []
    args = _kube_args(https=False, defcreds=True, namespace=["blue", "green"])
    target = ScanTargetSpec(host="127.0.0.1", explicit_port=6443, scheme="http", path="/proxy/version")

    def respond(url, headers):
        calls.append((url, dict(headers or {})))
        path = urlsplit(url).path.removeprefix("/proxy").removeprefix("/mounted")
        if case == "offline" or case == "upgrade" and url.startswith("http:"):
            return HttpResponse(0, b"", {}, error="connection refused", request_url=url, final_url=url)
        data: dict[str, Any]
        code, data, response_headers = 200, {}, {}
        if path == "/version":
            data = {"major": "1", "minor": "31", "gitVersion": "v1.31.2"}
            if case == "api_only":
                code, data = 404, {}
        elif path == "/api":
            data = {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]}
        elif path.endswith("/namespaces"):
            data = {"kind": "NamespaceList", "apiVersion": "v1", "items": [], "metadata": {"continue": "next"}}
        elif path.endswith("/pods"):
            data = {"kind": "PodList", "apiVersion": "v1", "items": []}
        if case in {"negative", "malformed"}:
            data = {"version": "1.31.2"}
        if case in {"denied", "limited", "typed_auth"} and (path not in {"/version", "/api"} or case == "typed_auth"):
            code = 403 if case == "limited" else 401
            reason = "Forbidden" if code == 403 else "Unauthorized"
            data = {"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": reason, "code": code}
            response_headers = {"WWW-Authenticate": 'Basic realm="kubernetes"'}
        body = b"not-json" if case == "malformed" else json.dumps(data).encode()
        final = (
            url.replace("http://127.0.0.1:6443/proxy/", "https://127.0.0.2:7443/mounted/")
            if case == "redirect"
            else url
        )
        response = HttpResponse(
            code,
            body,
            response_headers,
            request_url=url,
            final_url=final,
            redirect_history=(url,) if final != url else (),
        )
        pin_http_redirect_path(response, method="GET")
        return response

    monkeypatch.setattr(actions, "utc_now_iso", lambda: "fixed")
    monkeypatch.setattr(actions, "_elapsed_ms", lambda _state: 17)
    monkeypatch.setattr(KubeApiHttpSession, "request", lambda self, method, url, **kw: respond(url, kw.get("headers")))
    spec = stage.build_kubeapi_spec(args)
    sync_ctx = _context(args, target)
    assert spec.detect is not None
    expected = spec.detect(sync_ctx).to_dict()
    expected_calls = list(calls)
    calls.clear()
    monkeypatch.setattr(
        KubeApiHttpSession, "request", lambda *_a, **_kw: pytest.fail("sync Kube request on event loop")
    )
    ctx = _context(args, target)
    assert spec.detect_async is not None
    got = asyncio.run(spec.detect_async(ctx, Native(respond))).to_dict()
    assert got == expected
    assert calls == expected_calls
    for key in (
        "use_https",
        "insecure",
        "tls_auto_insecure",
        "origin_resolved",
        "host",
        "port",
        "anonymous_namespaces",
        "anonymous_namespaces_error",
        "anonymous_namespace_status",
        "access_namespaces",
        "access_namespace_status",
        "anonymous_access",
        "anonymous_pod_probe",
        "access_pod_probe",
    ):
        assert getattr(ctx.lifecycle_state, key) == getattr(sync_ctx.lifecycle_state, key)
    assert got["is_kubeapi"] is (case not in {"negative", "malformed", "offline"})
    if case == "open":
        assert got["status"] == "open_no_auth"
        assert got["can_list_namespaces"] is True
        assert got["can_list_pods"] is True
        assert [urlsplit(url).path for url, _ in calls] == [
            "/proxy/version",
            "/proxy/api/v1/namespaces",
            "/proxy/api/v1/namespaces/blue/pods",
            "/proxy/api/v1/namespaces/green/pods",
            "/proxy/api/v1/namespaces",
        ]
    if case in {"denied", "typed_auth"}:
        assert got["auth_required"] is True
        assert got["credential_verification_status"] == "available"
    if ctx.lifecycle_state.http_session is not None:
        assert ctx.lifecycle_state.http_session._owner_thread_id is None
        assert ctx.lifecycle_state.http_session._connection is None
    sync_ctx.lifecycle_state.close()
    ctx.lifecycle_state.close()


def test_cancellation_keeps_sync_session_unclaimed(monkeypatch):
    args = _kube_args()
    spec = stage.build_kubeapi_spec(args)
    ctx = _context(args)
    monkeypatch.setattr(KubeApiHttpSession, "request", lambda *_a, **_kw: pytest.fail("sync request"))

    async def run():
        entered = asyncio.Event()

        class Waiting(Native):
            async def get(self, url, *, headers=None):
                entered.set()
                await asyncio.Event().wait()

        assert spec.detect_async is not None
        task = asyncio.create_task(spec.detect_async(ctx, Waiting(None)))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert ctx.lifecycle_state.http_session is not None
    assert ctx.lifecycle_state.http_session._owner_thread_id is None
    assert ctx.lifecycle_state.http_session._connection is None
    ctx.lifecycle_state.close()


def test_explicit_ca_verification_error_never_downgrades(monkeypatch):
    args = _kube_args(ca_file="/configured/cluster-ca.pem", retries=0)
    ctx = _context(args)
    calls = []

    # The trust file is outside this unit test; inspect the policy passed to
    # the transport descriptor while supplying an already prepared context.
    def target_context(pool):
        assert pool.insecure is False
        assert pool.ca_file == "/configured/cluster-ca.pem"
        return shared_client_ssl_context(insecure=True)

    monkeypatch.setattr(HttpSessionPool, "_target_context", target_context)
    monkeypatch.setattr(KubeApiHttpSession, "request", lambda *_a, **_kw: pytest.fail("sync request"))

    def respond(url, headers):
        calls.append(url)
        return HttpResponse(0, b"", {}, error="certificate verify failed", request_url=url, final_url=url)

    spec = stage.build_kubeapi_spec(args)
    assert spec.detect_async is not None
    result = asyncio.run(spec.detect_async(ctx, Native(respond))).to_dict()
    assert calls == ["https://127.0.0.1:6443/version", "https://127.0.0.1:6443/api"]
    assert result["is_kubeapi"] is False
    assert result["insecure_effective"] is False
    assert result["tls_auto_insecure"] is False
    assert ctx.lifecycle_state.http_session._owner_thread_id is None
    ctx.lifecycle_state.close()


def test_retry_sleep_yields_to_other_tasks(monkeypatch):
    args = _kube_args(retries=1)
    ctx = _context(args)
    events = []
    monkeypatch.setattr(actions, "_retry_delay", lambda _attempt: 0.001)
    monkeypatch.setattr(KubeApiHttpSession, "request", lambda *_a, **_kw: pytest.fail("sync request"))
    monkeypatch.setattr(actions.time, "sleep", lambda _delay: pytest.fail("blocking retry sleep"))

    def respond(url, headers):
        events.append("request")
        return HttpResponse(0, b"", {}, error="connection refused", request_url=url, final_url=url)

    async def run():
        async def sibling():
            await asyncio.sleep(0)
            events.append("sibling")

        spec = stage.build_kubeapi_spec(args)
        assert spec.detect_async is not None
        result, _ = await asyncio.gather(spec.detect_async(ctx, Native(respond)), sibling())
        return result.to_dict()

    result = asyncio.run(run())
    assert result["is_kubeapi"] is False
    assert events.count("request") == 6
    assert "request" in events[events.index("sibling") + 1 :]
    ctx.lifecycle_state.close()
