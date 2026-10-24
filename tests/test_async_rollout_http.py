"""Parity of shared decision trees and actual lifecycle adapter registration."""

from __future__ import annotations

import asyncio
import importlib
import json
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.detection_steps import run_async_requests

MODULES = ("spark", "yarn", "jenkins", "keycloak")


def reply(module, url, positive):
    body = {}
    headers = {}
    status = 404
    if positive and module == "spark" and url.endswith("/json/"):
        body = {"url": "spark://master:7077", "workers": [], "activeapps": [], "cores": 2}
        status = 200
    if positive and module == "yarn" and url.endswith("/ws/v1/cluster/info"):
        body = {
            "clusterInfo": {
                "state": "STARTED",
                "haState": "ACTIVE",
                "resourceManagerVersion": "3.3.6",
                "hadoopVersion": "3.3.6",
            }
        }
        status = 200
    if positive and module == "jenkins":
        headers = {"X-Jenkins": "2.479.1"}
        if "/api/json?tree=" in url:
            body = {"_class": "jenkins.model.Jenkins", "jobs": []}
            status = 200
    if positive and module == "keycloak":
        issuer = "http://127.0.0.1:8080/realms/master"
        if url.endswith("/realms/master"):
            body = {
                "realm": "master",
                "public_key": "k" * 64,
                "token-service": issuer + "/protocol/openid-connect",
                "account-service": issuer + "/account",
                "tokens-not-before": 0,
            }
            status = 200
        if url.endswith("/.well-known/openid-configuration"):
            body = {
                "issuer": issuer,
                "jwks_uri": issuer + "/protocol/openid-connect/certs",
                "token_endpoint": issuer + "/protocol/openid-connect/token",
                "authorization_endpoint": issuer + "/protocol/openid-connect/auth",
            }
            status = 200
    return HttpResponse(status, json.dumps(body).encode(), headers, final_url=url)


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("positive", [True, False])
def test_same_records_and_requests(monkeypatch, module, positive):
    actions = importlib.import_module(f"redposture_core.modules.{module}.actions")
    ctx = SimpleNamespace(
        host="127.0.0.1", port=8080, target=None, args=SimpleNamespace(), credential=None, lifecycle_state=None
    )
    calls = []

    def get(*args):
        url = (
            args[0] + args[1] if module in ("spark", "yarn") else args[0] if module == "keycloak" else args[0] + args[1]
        )
        calls.append(url)
        return reply(module, url, positive)

    if module in ("jenkins", "keycloak"):
        monkeypatch.setattr(actions, "_client", lambda *a, **kw: object())
    monkeypatch.setattr(actions, "_get", lambda _client, *args: get(*args))
    expected = actions.detect_record(ctx)
    expected_calls = calls[:]
    calls.clear()

    async def send(base, path):
        return get(base, path) if module != "keycloak" else get(base + path)

    got = asyncio.run(run_async_requests(actions.detect_requests(ctx), send))
    assert got == expected
    assert calls == expected_calls
    assert got[f"is_{module}"] is positive


@pytest.mark.parametrize(
    "module", MODULES + ("portainer", "grafana", "qdrant", "gitlab", "docker_registry", "harbor", "nexus")
)
def test_stage_binds_adapter_to_current_sync_hook(module):
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    spec = getattr(stage, f"build_{module}_spec")(SimpleNamespace())
    assert spec.detect_async is not None
    assert spec.async_detect_sync_hook is spec.detect
