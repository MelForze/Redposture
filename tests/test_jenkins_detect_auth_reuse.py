"""Reuse a complete anonymous control without skipping any candidate identity."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.detection_steps import run_async_requests
from redposture_core.modules.jenkins import actions
from redposture_core.modules.jenkins.stage import build_jenkins_spec

ANONYMOUS = b'{"authenticated":false,"name":"anonymous","authorities":[]}'
IDENTITY = b'{"authenticated":true,"name":"admin","authorities":["authenticated"]}'
LOGIN = b"<h1>Jenkins</h1><form><input name='j_username'><input name='j_password'></form>"


def context():
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=8080,
        args=SimpleNamespace(timeout=1, retries=0, proxy=None),
        credential=SimpleNamespace(username="admin", password="pass", source="provided"),
    )
    factory = build_jenkins_spec(ctx.args).lifecycle_state_factory
    assert factory is not None
    ctx.lifecycle_state = factory(ctx)
    return ctx


def route(monkeypatch, *, initial=None, open_api=False):
    calls = []

    def get(_client, base, path, basic=None):
        calls.append((base, path, basic))
        if path == "/whoAmI/api/json":
            response = HttpResponse(200, IDENTITY if basic else ANONYMOUS, {})
            if basic is None and initial is not None and sum(x[1:] == (path, None) for x in calls) == 1:
                response = initial
        elif path == "/login":
            response = HttpResponse(200, LOGIN, {})
        elif path == "/":
            response = HttpResponse(200, b"", {"X-Jenkins": "2.541.3"})
        elif path.startswith("/api/json"):
            response = HttpResponse(
                200 if basic or open_api else 401,
                b'{"_class":"jenkins.model.Jenkins","jobs":[{"name":"deploy"}]}',
                {},
            )
        else:
            raise AssertionError(path)
        return replace(
            response,
            request_url=response.request_url or base + path,
            final_url=response.final_url or base + path,
        )

    monkeypatch.setattr(actions, "_get", get)
    return calls, get


@pytest.mark.parametrize("engine", ["sync", "async"])
@pytest.mark.parametrize("status", [200, 401, 403])
def test_detect_anonymous_identity_is_reused_but_every_pair_is_verified(monkeypatch, engine, status):
    ctx = context()
    calls, get = route(monkeypatch, initial=HttpResponse(status, ANONYMOUS if status == 200 else b"denied", {}))
    try:
        if engine == "sync":
            detected = actions.detect_record(ctx)
        else:

            async def send(base, path):
                return get(None, base, path)

            detected = asyncio.run(run_async_requests(actions.detect_requests(ctx), send))
        assert detected["is_jenkins"]
        for password in ("pass", "second-pass"):
            ctx.credential.password = password
            result = actions.auth_record(ctx, detected)
            assert result["provided_credentials_ok"] is True
            assert result["credential_jobs_count"] == 1
        assert sum(path == "/whoAmI/api/json" and basic is None for _, path, basic in calls) == 1
        candidates = [basic for _, path, basic in calls if path == "/whoAmI/api/json" and basic]
        assert candidates == [actions._basic("admin", "pass"), actions._basic("admin", "second-pass")]
    finally:
        ctx.lifecycle_state.close()


@pytest.mark.parametrize("new_base", ["http://127.0.0.1:8080/other", "https://127.0.0.1:8080", "http://localhost:8080"])
def test_detect_control_never_crosses_origin_scheme_or_prefix(monkeypatch, new_base):
    ctx = context()
    calls, _ = route(monkeypatch)
    try:
        detected = actions.detect_record(ctx)
        result = actions.auth_record(ctx, dict(detected, api_endpoint=new_base))
        assert result["provided_credentials_ok"] is True
        assert (new_base, "/whoAmI/api/json", None) in calls
    finally:
        ctx.lifecycle_state.close()


@pytest.mark.parametrize(
    "initial",
    [
        HttpResponse(200, ANONYMOUS, {}, truncated=True),
        HttpResponse(200, ANONYMOUS, {}, error="incomplete response"),
        HttpResponse(200, b"{}", {}),
        HttpResponse(200, ANONYMOUS + b" " * 16384, {}),
        HttpResponse(200, ANONYMOUS, {"Large": "a" * 8192}),
        HttpResponse(429, b"Too many requests", {}),
        HttpResponse(403, b"Account locked", {}),
        HttpResponse(200, ANONYMOUS, {}, final_url="https://idp.example.invalid/whoAmI/api/json"),
    ],
)
def test_incomplete_large_throttled_or_redirected_detect_control_is_refetched(monkeypatch, initial):
    ctx = context()
    calls, _ = route(monkeypatch, initial=initial)
    try:
        detected = actions.detect_record(ctx)
        assert actions.auth_record(ctx, detected)["provided_credentials_ok"] is True
        assert sum(path == "/whoAmI/api/json" and basic is None for _, path, basic in calls) == 2
    finally:
        ctx.lifecycle_state.close()


def test_open_api_fast_path_does_not_prefetch_an_unneeded_control(monkeypatch):
    ctx = context()
    calls, _ = route(monkeypatch, open_api=True)
    try:
        detected = actions.detect_record(ctx)
        assert len(calls) == 2
        assert actions.auth_record(ctx, detected)["provided_credentials_ok"] is True
        assert sum(path == "/whoAmI/api/json" and basic is None for _, path, basic in calls) == 1
    finally:
        ctx.lifecycle_state.close()


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("insecure", False),
        ("ca_file", "other-ca"),
        ("cert_file", "other-cert"),
        ("key_file", "other-key"),
        ("timeout", 2),
    ],
)
def test_changed_transport_policy_does_not_reuse_detect_proof(monkeypatch, attribute, value):
    ctx = context()
    calls, _ = route(monkeypatch)
    try:
        detected = actions.detect_record(ctx)
        setattr(ctx.lifecycle_state.http, attribute, value)
        assert actions.auth_record(ctx, detected)["provided_credentials_ok"] is True
        assert sum(path == "/whoAmI/api/json" and basic is None for _, path, basic in calls) == 2
    finally:
        ctx.lifecycle_state.close()


def test_close_discards_proof_and_prevents_late_publication(monkeypatch):
    ctx = context()
    route(monkeypatch)
    detected = actions.detect_record(ctx)
    state = ctx.lifecycle_state
    base = detected["api_endpoint"]
    proof = state.anonymous_control(base)
    assert proof is not None
    state.close()
    state.remember_anonymous(base, proof)
    assert state.anonymous_control(base) is None


@pytest.mark.parametrize("status,expected", [(401, False), (429, None), (503, None)])
def test_cached_anonymous_proof_cannot_accept_a_rejected_or_unavailable_candidate(monkeypatch, status, expected):
    ctx = context()
    calls, get = route(monkeypatch)
    try:
        detected = actions.detect_record(ctx)

        def candidate(_client, base, path, basic=None):
            if basic and path == "/whoAmI/api/json":
                return HttpResponse(status, b"unavailable", {})
            return get(_client, base, path, basic)

        monkeypatch.setattr(actions, "_get", candidate)
        result = actions.auth_record(ctx, detected)
        assert result["provided_credentials_ok"] is expected
        assert sum(path == "/whoAmI/api/json" and basic is None for _, path, basic in calls) == 1
    finally:
        ctx.lifecycle_state.close()
