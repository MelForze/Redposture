"""Reuse only the V2 response that actually verified this credential run."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.console import Console
from redposture_core.modules.registry import actions


def context(*, host="registry.local", token=None, source="provided", state=None):
    challenge = (
        'Bearer realm="https://registry.local/jwt/auth",service="container_registry"' if token else 'Basic realm="QA"'
    )
    state = state or actions.RegistryLifecycleState(
        anonymous_probe=(
            401,
            b'{"errors":[{"code":"UNAUTHORIZED"}]}',
            {"docker-distribution-api-version": "registry/2.0", "www-authenticate": challenge},
            None,
        )
    )
    return SimpleNamespace(
        host=host,
        port=5443,
        args=SimpleNamespace(timeout=1, retries=0),
        lifecycle_state=state,
        credential=SimpleNamespace(
            username=None if token else "reader", password=None if token else "correct", token=token, source=source
        ),
    )


def detected():
    return {"is_registry": True, "status": "auth_required", "auth_required": True}


@pytest.fixture(autouse=True)
def restore_transport():
    previous = getattr(actions._THREAD_LOCAL_HTTP, "state", None)
    yield
    actions._THREAD_LOCAL_HTTP.state = previous


@pytest.mark.parametrize("product,token", [("docker-registry", None), ("gitlab", "qa-token")])
def test_verified_base_response_is_the_same_object_saved_for_data_with_one_get(monkeypatch, product, token):
    ctx = context(token=token)
    replies = []

    def request(host, port, method, path, timeout, *, headers):
        assert (host, port, method, path, timeout) == (ctx.host, 5443, "GET", "/v2/", 1)
        assert headers == actions._auth_headers(ctx.credential.username, ctx.credential.password, token)
        reply = (
            200,
            f'{{"response":{len(replies)}}}'.encode(),
            {"docker-distribution-api-version": "registry/2.0"},
            None,
        )
        replies.append(reply)
        return reply

    monkeypatch.setattr(actions, "_http_request", request)
    result = actions.authenticate_registry(ctx, detected(), {"product": product})
    assert result["provided_credentials_ok"] is True and result["status"] == "valid_credentials"
    key = (ctx.credential.username, ctx.credential.password, token, "provided")
    assert ctx.lifecycle_state.credential_probes[key] is replies[0]
    assert len(replies) == 1


@pytest.mark.parametrize(
    "reply,expected",
    [
        (
            (401, b'{"errors":[{"code":"UNAUTHORIZED"}]}', {"docker-distribution-api-version": "registry/2.0"}, None),
            False,
        ),
        ((200, b"<title>proxy login</title>", {}, None), None),
        ((403, b"blocked", {}, None), None),
        ((503, b"unavailable", {}, None), None),
        ((0, b"", {}, "connection reset"), None),
        ((200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, "incomplete response"), None),
    ],
)
def test_rejected_or_unverified_response_is_not_cached_or_retried(monkeypatch, reply, expected):
    ctx = context()
    calls = []
    monkeypatch.setattr(actions, "_http_request", lambda *a, **k: calls.append((a, k)) or reply)
    result = actions.authenticate_registry(ctx, detected(), {"product": "docker-registry"})
    assert result["provided_credentials_ok"] is expected
    assert not ctx.lifecycle_state.credential_probes and len(calls) == 1


@pytest.mark.parametrize("anonymous", [(200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None), None])
def test_public_or_unconfirmed_registry_still_cannot_verify_a_pair(monkeypatch, anonymous):
    ctx = context(state=actions.RegistryLifecycleState(anonymous_probe=anonymous))
    monkeypatch.setattr(actions, "_http_request", lambda *a, **k: pytest.fail("unnecessary credential request"))
    result = actions.authenticate_registry(ctx, detected(), {"product": "docker-registry"})
    assert result["provided_credentials_ok"] is None and not ctx.lifecycle_state.credential_probes


def test_handoff_is_target_and_credential_local_not_a_global_response_cache(monkeypatch):
    calls = []

    def request(host, *args, **kwargs):
        calls.append((host, kwargs["headers"]["Authorization"]))
        return 200, host.encode(), {"docker-distribution-api-version": "registry/2.0"}, None

    monkeypatch.setattr(actions, "_http_request", request)
    for host in ("first.local", "second.local"):
        ctx = context(host=host)
        for password in ("first-pass", "second-pass"):
            ctx.credential.password = password
            actions.authenticate_registry(ctx, detected(), {"product": "docker-registry"})
            key = ("reader", password, None, "provided")
            assert ctx.lifecycle_state.credential_probes[key][1] == host.encode()
        assert len(ctx.lifecycle_state.credential_probes) == 2
    assert len(calls) == 4 and len(set(calls)) == 4


def test_data_receives_verified_response_without_repeating_the_identity_probe(monkeypatch):
    ctx = context()
    probe = (200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None)
    monkeypatch.setattr(actions, "_http_request", lambda *a, **k: probe)
    authenticated = actions.authenticate_registry(ctx, detected(), {"product": "docker-registry"})
    monkeypatch.setattr(actions, "_http_request", lambda *a, **k: pytest.fail("repeated identity GET"))
    seen = []

    def data(host, port, timeout, retries, **kwargs):
        seen.append(kwargs["initial_probe"])
        assert kwargs["username"] == "reader" and kwargs["password"] == "correct"
        return {"is_registry": True, "status": "open_no_auth", "error": None}

    monkeypatch.setattr(actions, "_audit_registry_host_core", data)
    options = {
        "docker": True,
        "show_images": False,
        "show_tags": False,
        "repository": None,
        "tag": None,
        "metadata": False,
        "harbor": False,
        "gitlab": False,
        "nexus": False,
        "assets": False,
        "inspect": False,
        "image": None,
        "download": False,
        "download_dir": "/unused",
        "console": Console(),
    }
    result = actions.collect_registry_data(ctx, authenticated, options)
    assert seen == [probe] and seen[0] is probe
    assert result["provided_credentials_ok"] is True


@pytest.mark.parametrize("product", ["harbor", "nexus"])
def test_vendor_identity_does_not_replace_the_separate_registry_access_check(monkeypatch, product):
    import json

    ctx = context()
    calls = []
    identity = "/api/v2.0/users/current" if product == "harbor" else "/service/rest/v1/security/users"

    def request(host, port, method, path, timeout, *, headers=None):
        calls.append(path)
        if path == identity:
            if not headers:
                return 401, b"", {}, None
            payload = {"username": "reader", "user_id": 7} if product == "harbor" else [{"userId": "reader"}]
            return 200, json.dumps(payload).encode(), {}, None
        assert path == "/v2/"
        return 200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None

    monkeypatch.setattr(actions, "_http_request", request)
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *a, **kw: ({"version": "3.72.0"}, None))
    result = actions.authenticate_registry(ctx, detected(), {"product": product})
    assert result["provided_credentials_ok"] is True
    assert calls.count("/v2/") == 1 and calls[0] == identity


def test_gitlab_basic_exchange_does_not_replace_registry_access_with_the_issuer_response(monkeypatch):
    import base64
    import json

    ctx = context()
    ctx.lifecycle_state.anonymous_probe = context(token="qa-token").lifecycle_state.anonymous_probe
    issued = "header." + base64.urlsafe_b64encode(b'{"sub":"reader"}').decode().rstrip("=") + ".signature"
    calls = []
    monkeypatch.setattr(
        actions, "_http_request_url", lambda *a, **kw: (200, json.dumps({"token": issued}).encode(), {}, None)
    )
    probe = (200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None)
    monkeypatch.setattr(actions, "_http_request", lambda *a, **kw: calls.append(a[3]) or probe)
    result = actions.authenticate_registry(ctx, detected(), {"product": "gitlab"})
    assert result["provided_credentials_ok"] is True and calls == ["/v2/"]
    assert ctx.lifecycle_state.credential_probes[("reader", "correct", None, "provided")] is probe


def test_reauth_same_identity_performs_a_new_check_instead_of_reading_a_stale_cache(monkeypatch):
    ctx = context()
    responses = iter(
        [
            (200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None),
            (401, b"", {"docker-distribution-api-version": "registry/2.0"}, None),
        ]
    )
    monkeypatch.setattr(actions, "_http_request", lambda *a, **kw: next(responses))
    assert (
        actions.authenticate_registry(ctx, detected(), {"product": "docker-registry"})["provided_credentials_ok"]
        is True
    )
    assert (
        actions.authenticate_registry(ctx, detected(), {"product": "docker-registry"})["provided_credentials_ok"]
        is False
    )
    assert ("reader", "correct", None, "provided") not in ctx.lifecycle_state.credential_probes


@pytest.mark.parametrize(
    "reply",
    [
        (401, b"", {"docker-distribution-api-version": "registry/2.0"}, None),
        (200, b"<html>proxy</html>", {}, None),
        (0, b"", {}, "timeout"),
    ],
)
def test_new_verdict_invalidates_only_its_previous_probe_and_vendor_metadata(monkeypatch, reply):
    ctx = context()
    key = ("reader", "correct", None, "provided")
    other = ("other", "password", None, "default")
    old = (200, b"old", {"docker-distribution-api-version": "registry/2.0"}, None)
    ctx.lifecycle_state.credential_probes.update({key: old, other: old})
    ctx.lifecycle_state.credential_nexus.update(
        {key: ({"version": "stale"}, None), other: ({"version": "other"}, None)}
    )
    monkeypatch.setattr(actions, "_http_request", lambda *a, **kw: reply)
    actions.authenticate_registry(ctx, detected(), {"product": "docker-registry"})
    assert key not in ctx.lifecycle_state.credential_probes
    assert key not in ctx.lifecycle_state.credential_nexus
    assert ctx.lifecycle_state.credential_probes[other] is old
    assert ctx.lifecycle_state.credential_nexus[other][0]["version"] == "other"
