"""Regressions derived from actual Harbor 1.8.x and 2.11.x responses."""

from __future__ import annotations

import json

import pytest

from redposture_core import stage_registry as registry


@pytest.mark.parametrize("version", ["v1.8.2-1c3a3d53", "v1.8.3", "1.10.17+build.1"])
def test_legacy_systeminfo_is_confirmed_only_after_v2_not_found(monkeypatch, version) -> None:
    calls = []
    payload = {"harbor_version": version, "auth_mode": "db_auth", "registry_url": "127.0.0.1:18280"}

    def response(_host, _port, method, path, _timeout, *, headers):
        calls.append((method, path, headers))
        return (404, b"", {}, None) if path == "/api/v2.0/systeminfo" else (200, json.dumps(payload).encode(), {}, None)

    monkeypatch.setattr(registry, "_http_request", response)
    assert registry._fetch_harbor_info("h", 18280, 1, headers={"Authorization": "Basic fixture"}) == (payload, None)
    assert [path for _, path, _ in calls] == ["/api/v2.0/systeminfo", "/api/systeminfo"]
    assert all(method == "GET" and headers == {"Authorization": "Basic fixture"} for method, _, headers in calls)


@pytest.mark.parametrize("status,error", [(401, None), (403, None), (500, None), (0, "timeout"), (404, "disconnect")])
def test_legacy_fallback_never_retries_auth_denials_or_transport_failures(monkeypatch, status, error) -> None:
    calls = []

    def response(*args, **kwargs):
        calls.append(args[3])
        return status, b"", {}, error

    monkeypatch.setattr(registry, "_http_request", response)
    assert registry._fetch_harbor_info("h", 18280, 1, headers={})[0] is None
    assert calls == ["/api/v2.0/systeminfo"]


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"harbor_version": "1.8.2"},
        {"harbor_version": "2.11.1", "auth_mode": "db_auth", "registry_url": "h"},
        {"harbor_version": "1.8.2", "auth_mode": "generic", "registry_url": "h"},
        {"harbor_version": "1.8.2", "auth_mode": [], "registry_url": "h"},
        {"harbor_version": "1.8.2", "auth_mode": {}, "registry_url": "h"},
        {"harbor_version": "1.8.2", "auth_mode": "db_auth", "registry_url": []},
        {"harbor_version": "1.8.2", "auth_mode": "db_auth", "registry_url": " "},
        {"harbor_version": "1.8.2 junk", "auth_mode": "db_auth", "registry_url": "h"},
    ],
)
def test_generic_and_malformed_legacy_responses_do_not_confirm_harbor(monkeypatch, payload) -> None:
    monkeypatch.setattr(
        registry,
        "_http_request",
        lambda *a, **k: (
            (404, b"", {}, None) if a[3] == "/api/v2.0/systeminfo" else (200, json.dumps(payload).encode(), {}, None)
        ),
    )
    assert registry._fetch_harbor_info("h", 18280, 1, headers={})[0] is None


@pytest.mark.parametrize("identifier", [0, -1, True, "3", None])
def test_legacy_repository_lookup_rejects_non_numeric_or_unrelated_project(monkeypatch, identifier) -> None:
    calls = []

    def pages(*args, **kwargs):
        calls.append(args[2])
        return [{"name": "core", "project_id": identifier}, {"name": "wrong", "project_id": 4}], None

    monkeypatch.setattr(registry, "_fetch_harbor_pages", pages)
    assert registry._fetch_harbor_repositories("h", 18280, "core", 1, headers={}, legacy=True)[0] is None
    assert calls == ["/api/projects?name=core"]


def test_legacy_repository_lookup_uses_project_id_without_dropping_pagination_query(monkeypatch) -> None:
    paths = []

    def response(*args, **kwargs):
        paths.append(args[3])
        payload = (
            [{"name": "wrong", "project_id": 99}, {"name": "core", "project_id": 3}]
            if "/projects?" in args[3]
            else [{"name": "core/controller"}]
        )
        return 200, json.dumps(payload).encode(), {}, None

    monkeypatch.setattr(registry, "_http_request", response)
    assert registry._fetch_harbor_repositories("h", 18280, "core", 1, headers={}, legacy=True) == (
        ["core/controller"],
        None,
    )
    assert paths == [
        "/api/projects?page=1&page_size=100&name=core",
        "/api/repositories?page=1&page_size=100&project_id=3",
    ]


@pytest.mark.parametrize(
    "legacy,repository,expected",
    [
        (False, "core/controller", "/api/v2.0/projects/core/repositories/controller/artifacts?with_tag=true"),
        (
            False,
            "core/nested/controller",
            "/api/v2.0/projects/core/repositories/nested%252Fcontroller/artifacts?with_tag=true",
        ),
        (True, "core/nested/controller", "/api/repositories/core%2Fnested%2Fcontroller/tags"),
    ],
)
def test_artifact_paths_match_real_vendor_api(monkeypatch, legacy, repository, expected) -> None:
    paths = []

    def pages(*args, **kwargs):
        paths.append(args[2])
        return (
            [{"name": "latest", "digest": "sha256:fixture"}]
            if legacy
            else [{"tags": [{"name": "latest"}], "digest": "sha256:fixture"}]
        ), None

    monkeypatch.setattr(registry, "_fetch_harbor_pages", pages)
    assert registry._fetch_harbor_artifacts("h", 18280, "core", repository, 1, headers={}, legacy=legacy) == (
        [repository + ":latest@sha256:fixture"],
        None,
    )
    assert paths == [expected]
