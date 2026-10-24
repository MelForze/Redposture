from __future__ import annotations

import json
from types import SimpleNamespace as NS

import pytest

from redposture_core.modules.gitlab import actions as gitlab
from redposture_core.modules.grafana import actions as grafana


@pytest.mark.parametrize("enum_cve", [False, True])
def test_gitlab_verified_identity_fetches_missing_version_without_requiring_cve(monkeypatch, enum_cve):
    calls = []

    def request(host, port, path, timeout, **kwargs):
        calls.append(path)
        return (
            200,
            {"id": 1, "username": "qa", "state": "active"}
            if path == "/api/v4/user"
            else {"version": "17.3.1", "revision": "abc"},
            {},
            None,
        )

    monkeypatch.setattr(gitlab, "_api_get_json", request)
    ctx = NS(
        host="qa",
        port=80,
        args=NS(timeout=1, enum_cve=enum_cve),
        credential=NS(token="valid"),
        lifecycle_state=gitlab.GitLabLifecycleState(),
    )
    result = gitlab.authenticate_gitlab(ctx, {"status": "auth_required", "https": False}, {"project_filters": []})
    assert result["version"] == "17.3.1" and result["token_valid"] is True
    assert calls == ["/api/v4/user", "/api/v4/version"]


@pytest.mark.parametrize("ok", [True, False, None])
def test_grafana_only_verified_login_recovers_missing_private_health_version(monkeypatch, ok):
    calls = []
    monkeypatch.setattr(grafana, "_verify_credentials", lambda *a: (ok, None))

    def request(host, port, path, timeout, **kwargs):
        calls.append((path, kwargs["headers"]))
        return 200, json.dumps({"database": "ok", "version": "11.3.1", "commit": "abc"}), {}

    monkeypatch.setattr(grafana, "_http_request", request)
    ctx = NS(
        host="qa",
        port=80,
        args=NS(timeout=1),
        credential=NS(username="u", password="p", token=None, source="provided"),
        lifecycle_state=grafana.GrafanaLifecycleState(),
    )
    result = grafana.authenticate_grafana(ctx, {"auth_required": True}, {})
    if ok:
        assert result["server_version"] == "11.3.1" and result["provided_credentials_ok"] is True
        assert calls == [("/api/health", {"Authorization": grafana._auth_header("u", "p")})]
    else:
        assert not calls and result.get("server_version") is None


def test_grafana_optional_version_failure_does_not_erase_valid_login(monkeypatch):
    monkeypatch.setattr(grafana, "_verify_credentials", lambda *a: (True, None))

    def request(*a, **kw):
        raise TimeoutError("timeout")

    monkeypatch.setattr(grafana, "_http_request", request)
    ctx = NS(
        host="qa",
        port=80,
        args=NS(timeout=1),
        credential=NS(username="u", password="p", token=None, source="provided"),
        lifecycle_state=grafana.GrafanaLifecycleState(),
    )
    result = grafana.authenticate_grafana(ctx, {"auth_required": True}, {})
    assert result["provided_credentials_ok"] is True and result.get("server_version") is None
