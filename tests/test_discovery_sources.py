from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.data_discovery import inspect_record
from redposture_core.modules.jenkins import actions as jenkins
from redposture_core.modules.kubeapi import actions as kubeapi
from redposture_core.modules.qdrant import actions as qdrant


def _response(data: Any, status: int = 200) -> HttpResponse:
    body = data.encode() if isinstance(data, str) else json.dumps(data).encode()
    return HttpResponse(status=status, body=body, headers={})


def test_kubeapi_configmap_read_uses_product_api_and_field_name(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []

    def list_items(
        _host: str, _port: int, path: str, _timeout: float, **_kwargs: Any
    ) -> tuple[list[dict[str, Any]], int, None]:
        paths.append(path)
        return (
            [
                {
                    "metadata": {"name": "settings", "namespace": "qa"},
                    "data": {"api_token": "glpat-abcdefghijklmnopqrst"},
                }
            ],
            200,
            None,
        )

    monkeypatch.setattr(kubeapi, "_invoke_kube_list_items", list_items)
    result = kubeapi._list_secrets(
        "qa", 6443, 1, use_https=True, insecure=True, ca_file=None, namespaces=[], resource="configmaps"
    )
    assert paths == ["/api/v1/configmaps"]
    assert result.items is not None and result.items[0]["data"]["api_token"] == "glpat-abcdefghijklmnopqrst"
    findings = inspect_record("kubeapi", {"status": "open_no_auth", "configmaps": result.items})["findings"]
    assert any("configmaps.qa.settings.api_token" in item["object_path"] for item in findings)


def test_qdrant_scroll_reads_payload_pages_and_stops_on_repeated_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    def request(
        _host: str, _port: int, method: str, path: str, _timeout: float, **kwargs: Any
    ) -> tuple[int, dict[str, Any], None]:
        assert method == "POST" and path == "/collections/qa/points/scroll"
        calls.append(kwargs["payload"])
        return (
            200,
            {
                "result": {
                    "points": [{"id": len(calls), "payload": {"password": "testsecret"}}],
                    "next_page_offset": "same",
                }
            },
            None,
        )

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    points, partial = qdrant._qdrant_scroll_payloads("qa", 6333, 1, "qa", headers=None)
    assert partial is True and len(points) == 2 and len(calls) == 2
    assert calls[0]["with_payload"] is True and calls[0]["with_vector"] is False
    findings = inspect_record(
        "qdrant", {"status": "open_no_auth", "payload_discovery_items": [{"collection": "qa", "points": points}]}
    )["findings"]
    assert any("password" in item["object_path"] for item in findings)


def test_jenkins_discover_reads_config_and_console_without_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []

    def get(_client: Any, _base: str, path: str, _basic: str | None = None) -> HttpResponse:
        paths.append(path)
        if path.startswith("/api/json"):
            return _response({"jobs": [{"name": "build", "color": "blue", "lastBuild": {"number": 2}}]})
        if path == "/job/build/config.xml":
            return _response("<config><api_token>glpat-abcdefghijklmnopqrst</api_token></config>")
        if path == "/job/build/2/consoleText":
            return _response("password=BuildSecret2026")
        if path == "/job/build/2/injectedEnvVars/api/json":
            return _response({"envMap": {"api_token": "glpat-abcdefghijklmnopqrst"}})
        if path.startswith("/job/build/api/json"):
            return _response({"builds": [{"number": 2, "result": "SUCCESS"}]})
        return _response({}, 404)

    monkeypatch.setattr(jenkins, "_client", lambda _ctx: object())
    monkeypatch.setattr(jenkins, "_get", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover=True, show_builds=1), credential=SimpleNamespace(username=None, password=None)
    )
    result = jenkins.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    assert all(path.startswith(("/api/json", "/job/")) for path in paths)
    assert result["build_logs"] and result["job_configs"] and result["build_envs"]
    findings = inspect_record("jenkins", result)["findings"]
    assert any(item["type"] == "password" for item in findings)
