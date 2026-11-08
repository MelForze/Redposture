"""Anonymous fallback proof must survive detect without replacing auth controls."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import http_target_context
from redposture_core.http_headers import custom_http_headers
from redposture_core.modules.grafana import actions
from tests.test_grafana_auth_ping import Peer


@pytest.fixture
def setup(monkeypatch):
    previous = vars(actions._THREAD_LOCAL_HTTP).copy()
    peer = Peer("basic")
    original = peer.request

    def request(method, url, **kwargs):
        response = original(method, url, **kwargs)
        return replace(response, request_url=url, final_url=url)

    monkeypatch.setattr(peer, "request", request)
    peer.insecure = True
    state = actions.GrafanaLifecycleState(http=peer, host="qa", port=3000, scheme="http", origin_resolved=True)
    actions._activate_grafana_transport(state)
    yield peer, state
    state.close()
    vars(actions._THREAD_LOCAL_HTTP).clear()
    vars(actions._THREAD_LOCAL_HTTP).update(previous)


def test_fallback_detection_control_is_not_repeated_and_negative_controls_stay(setup):
    peer, state = setup
    assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is True
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True
    calls = [(method, path, headers.get("authorization")) for method, path, headers in peer.calls]
    assert calls.count(("GET", "/api/login/ping", None)) == 1
    protected = [authorization for method, path, authorization in calls if path == "/api/login/ping" and authorization]
    assert actions._auth_header("alice", "correct") in protected
    assert len(protected) == 3  # candidate, nonexistent user, same user with invalid password
    assert state.auth_attempts == []  # no fabricated credential attempt by the detector


def test_changed_tls_policy_refetches_detect_control(setup):
    peer, _state = setup
    assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is True
    peer.insecure = False
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True
    assert sum(path == "/api/login/ping" and not headers.get("authorization") for _, path, headers in peer.calls) == 2


def test_changed_mount_refetches_detect_control(setup, monkeypatch):
    peer, state = setup
    original = peer.request

    def request(method, url, **kwargs):
        plain = url.replace("/first/", "/").replace("/second/", "/")
        return replace(original(method, plain, **kwargs), request_url=url, final_url=url)

    monkeypatch.setattr(peer, "request", request)
    with http_target_context(SimpleNamespace(scheme="http", path="/first")):
        assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is True
        assert "/api/login/ping" in state.anonymous_responses
    with http_target_context(SimpleNamespace(scheme="http", path="/second")):
        assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True
    assert sum(path == "/api/login/ping" and not headers.get("authorization") for _, path, headers in peer.calls) == 2


def test_changed_operator_headers_refetch_all_controls(setup):
    peer, _state = setup
    with custom_http_headers([("X-Tenant", "first")]):
        assert actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True) is True
        assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True
    with custom_http_headers([("X-Tenant", "second")]):
        assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True
    anonymous = [
        headers for _, path, headers in peer.calls if path == "/api/login/ping" and not headers.get("authorization")
    ]
    assert len(anonymous) == 2


@pytest.mark.parametrize("mode", ["any-basic", "username-only", "public"])
def test_prefetched_control_does_not_verify_a_non_specific_pair(setup, mode):
    peer, _state = setup
    peer.mode = mode
    actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True)
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is not True


def test_closed_lifecycle_cannot_publish_a_late_control(setup, monkeypatch):
    peer, state = setup
    original = peer.request

    def request(method, url, **kwargs):
        response = original(method, url, **kwargs)
        if url.endswith("/api/login/ping"):
            state.close()
        return response

    monkeypatch.setattr(peer, "request", request)
    actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True)
    assert state.control_closed and state.anonymous_responses == {}
    assert actions._grafana_control_state("qa", 3000, 1) is None


@pytest.mark.parametrize("bad", ["error", "truncated", "large", "redirect", "headers"])
def test_unusable_detect_proof_is_refetched(setup, monkeypatch, bad):
    peer, _state = setup
    original = peer.request
    modified = False

    def request(method, url, **kwargs):
        nonlocal modified
        response = original(method, url, **kwargs)
        if not modified and url.endswith("/api/login/ping") and not (kwargs.get("headers") or {}).get("Authorization"):
            modified = True
            if bad == "error":
                return replace(response, error="connection interrupted")
            if bad == "truncated":
                return replace(response, truncated=True)
            if bad == "large":
                return replace(response, body=response.body + b" " * 16384)
            if bad == "headers":
                return replace(response, headers={"Large": "a" * 8192})
            return replace(response, final_url="https://other.test/api/login/ping", redirect_history=(url,))
        return response

    monkeypatch.setattr(peer, "request", request)
    # Error is an unavailable inference, not a negative credential decision.
    actions._infer_grafana_auth_required("qa", 3000, 1, health_status=200, health_api_ok=True)
    assert actions._verify_credentials("qa", 3000, 1, "alice", "correct")[0] is True
    assert sum(path == "/api/login/ping" and not headers.get("authorization") for _, path, headers in peer.calls) >= 2
