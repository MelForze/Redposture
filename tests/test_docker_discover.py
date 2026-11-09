"""Docker discovery reads existing objects, with bounded shared readers."""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.docker import discover as module


class Pool:
    routes: dict[str, tuple[int, object]] = {}
    calls: list[str] = []

    def __init__(self, **_kwargs):
        pass

    def close(self):
        pass

    def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
        assert method == "GET"
        assert kwargs["deadline"] and kwargs["allow_cross_origin_redirects"] is False
        path = urlsplit(url).path
        self.calls.append(path)
        status, value = self.routes[path]
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        headers = {"content-type": "application/json"}
        try:
            on_response(status, headers)
            for offset in range(0, len(raw), 17):
                on_chunk(raw[offset : offset + 17])
        except Exception as exc:
            return HttpResponse(status, b"", headers, error=str(exc))
        return HttpResponse(status, b"", headers)


@pytest.fixture
def context(monkeypatch):
    monkeypatch.setattr(module, "HttpSessionPool", Pool)
    Pool.calls = []
    Pool.routes = {
        "/containers/json": (200, [{"Id": "c1"}, {"Id": "c1"}]),
        "/containers/c1/json": (200, {"Id": "c1", "Image": "im1", "Config": {"Env": ["PASSWORD=inactive-env!42"]}}),
        "/images/json": (200, [{"Id": "im1"}, {"Id": "im1"}]),
        "/images/im1/json": (200, {"Id": "im1", "Config": {"Labels": {"application.password": "inactive-label!42"}}}),
    }
    return SimpleNamespace(
        host="qa.invalid", port=2375, args=SimpleNamespace(timeout=1, discover_time=30, container=None)
    )


def run(ctx):
    return module.discover(ctx, {"status": "open_no_auth", "transport_mode": "plaintext"})


def test_catalogs_and_configs_exact_secrets_and_no_duplicate_requests(context):
    report = run(context)
    assert report["status"] == "complete"
    assert sorted(str(f["value"]) for f in report["findings"]) == ["inactive-env!42", "inactive-label!42"]
    assert Pool.calls == ["/containers/json", "/containers/c1/json", "/images/json", "/images/im1/json"]
    assert all(s["requested"] and s["read"] and s["complete"] for s in report["sources"])


def test_container_selector_reads_only_selected_container_and_its_image(context):
    context.args.container = "c1"
    report = run(context)
    assert report["status"] == "complete"
    assert Pool.calls == ["/containers/c1/json", "/images/im1/json"]
    assert not next(s for s in report["sources"] if s["id"] == "docker.container_catalog")["requested"]


def test_denied_catalog_body_never_becomes_a_secret(context):
    Pool.routes = {"/containers/json": (403, {"password": "error-body-not-readable!42"}), "/images/json": (403, [])}
    report = run(context)
    assert report["status"] == "unavailable"
    assert not report["findings"]
    assert sum(s["denied"] for s in report["sources"]) == 2


def test_broken_response_keeps_closed_values_and_marks_partial(context):
    Pool.routes["/containers/c1/json"] = (
        200,
        b'{"Config":{"password":"closed-before-error!42"},"pending":"not-complete',
    )
    report = run(context)
    assert report["status"] == "partial"
    assert "closed-before-error!42" in {str(f["value"]) for f in report["findings"]}
    assert all("not-complete" not in str(f["value"]) for f in report["findings"])
    assert not next(s for s in report["sources"] if s["id"] == "docker.container_configs")["complete"]


def test_grouped_credentials_are_one_object_not_separate_fields(context):
    from redposture_core.discovery_values import CredentialObject

    context.args.container = "c1"
    Pool.routes["/containers/c1/json"] = (
        200,
        {"Config": {"oauth": {"client_id": "qa", "client_secret": "inactive-oauth!42"}}},
    )
    report = run(context)
    assert report["status"] == "complete"
    (finding,) = report["findings"]
    assert finding["type"] == "oauth_credentials" and isinstance(finding["value"], CredentialObject)


def test_unverified_access_does_not_start_content_requests(context):
    report = module.discover(context, {"status": "detected"})
    assert report["status"] == "partial" and not Pool.calls and not report["findings"]


def test_container_selector_is_valid_for_discovery_but_not_standalone():
    from redposture_core.cli_args import parse_args
    from redposture_core.modules.docker.policy import validate_args

    console = SimpleNamespace(error=lambda message: None)
    assert (
        validate_args(parse_args(["docker", "-t", "127.0.0.1", "--container", "selected", "--discover"]), console)
        is None
    )
    assert validate_args(parse_args(["docker", "-t", "127.0.0.1", "--container", "selected"]), console) == 2
