"""HTTP capability failures preserve partial evidence and clean owned resources."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.modules.gitlab import actions as gitlab
from redposture_core.modules.grafana import actions as grafana


@pytest.mark.parametrize("fault", ["transport", "denied", "missing", "server", "shape"])
def test_gitlab_later_project_page_failure_retains_first_page(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    paths = []

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        paths.append(path)
        assert kwargs == {"use_https": True, "token": "verified"}
        if len(paths) == 1:
            return 200, [{"id": 7, "name": "kept"}], {"x-next-page": "9"}, None
        return {
            "transport": (0, None, {}, "reset"),
            "denied": (403, {}, {}, None),
            "missing": (404, {}, {}, None),
            "server": (503, {}, {}, None),
            "shape": (200, {}, {}, None),
        }[fault]

    monkeypatch.setattr(gitlab, "_api_get_json", request)
    rows, error = gitlab._paginate_projects("qa", 443, 1, use_https=True, token="verified", public_only=True)
    assert rows == [{"id": 7, "name": "kept"}] and error and error.startswith("partial:")
    assert [parse_qs(urlsplit(path).query)["page"] for path in paths] == [["1"], ["9"]]
    assert all(parse_qs(urlsplit(path).query)["visibility"] == ["public"] for path in paths)


def test_gitlab_project_page_limit_bounds_server_continuation(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = []

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        paths.append(path)
        return 200, [{"id": len(paths)}], {"x-next-page": str(len(paths) + 1)}, None

    monkeypatch.setattr(gitlab, "_api_get_json", request)
    rows, error = gitlab._paginate_projects("qa", 80, 1, use_https=False, token=None, public_only=False)
    assert rows and len(rows) == len(paths) == 100 and error == "partial: GitLab pagination limit exceeded"
    assert all("visibility=" not in path for path in paths)


@pytest.mark.parametrize("identity", [{"id": 12}, {"uid": "owned/a"}])
@pytest.mark.parametrize("failure", ["timeout", "denied", "cleanup"])
def test_grafana_owned_datasource_cleaned_after_failed_proxy(
    monkeypatch: pytest.MonkeyPatch, identity: dict[str, Any], failure: str
) -> None:
    calls = []

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        method = kwargs.get("method", "GET")
        calls.append((method, path, kwargs))
        assert kwargs["headers"]["Authorization"] == "Bearer verified"
        if method == "POST":
            data = json.loads(kwargs["data"])
            assert data["url"] == "https://upstream:9443" and data["isDefault"] is False
            return 201, json.dumps(identity), {}
        if method == "DELETE":
            return (403, "cleanup forbidden", {}) if failure == "cleanup" else (202, "", {})
        if failure == "timeout":
            raise TimeoutError("timed out")
        return 403, "proxy forbidden", {}

    monkeypatch.setattr(grafana, "_http_request", request)
    result = grafana._run_temp_prometheus_check("qa", 3000, 1, "Bearer verified", "https://upstream:9443/metrics?q=a")
    uid = "uid/owned%2Fa" if "uid" in identity else "12"
    assert [(method, path) for method, path, _ in calls] == [
        ("POST", "/api/datasources"),
        ("GET", f"/api/datasources/proxy/{uid}/metrics?q=a"),
        ("DELETE", f"/api/datasources/{uid}"),
    ]
    assert result["create_ok"] is True and result["probe_ok"] is False and result["probe_error"]
    assert result["cleanup_ok"] is (failure != "cleanup")
    assert bool(result["cleanup_error"]) is (failure == "cleanup")


@pytest.mark.parametrize("fault", ["denied", "missing_id", "transport"])
def test_grafana_unconfirmed_creation_never_probes_or_deletes(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    calls = []

    def request(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs.get("method", "GET"))
        if fault == "transport":
            raise OSError("reset")
        return (403, "forbidden", {}) if fault == "denied" else (201, "{}", {})

    monkeypatch.setattr(grafana, "_http_request", request)
    result = grafana._run_temp_prometheus_check("qa", 3000, 1, None, "http://upstream/metrics")
    assert calls == ["POST"]
    assert result["create_ok"] is False and result["create_error"]
    assert result["probe_ok"] is None and result["cleanup_ok"] is None
