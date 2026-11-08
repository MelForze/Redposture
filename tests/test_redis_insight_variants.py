"""Redis Insight distribution metadata follows the official ServerService mapping.

The Electron/VS Code cases are contract fixtures, not desktop live evidence.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from redposture_core import web_panels
from redposture_core.clients.http_api import HttpResponse
from redposture_core.detection_steps import run_async_requests, run_requests

BUILDS = [
    ("DOCKER", "DOCKER_ON_PREMISE"),
    ("REDIS_STACK_WEB", "REDIS_STACK"),
    ("ELECTRON", "ELECTRON"),
    ("VS_CODE", "VS_CODE"),
]


def response(value: object) -> HttpResponse:
    body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
    return HttpResponse(200, body, {})


def detect(
    info: dict[str, object],
    body: str = "<title>Redis Insight</title>",
    *,
    expected_paths: tuple[str, ...] = ("/", "/api/info"),
):
    routes = {"/": response(body), "/api/info": response(info)}
    calls = []

    def send(base, path):
        calls.append((base, path))
        return routes[path]

    result = run_requests(web_panels.fingerprint_requests("redis", "http://qa/prefix"), send)
    expected_calls = calls[:]
    calls.clear()

    async def async_send(base, path):
        return send(base, path)

    native = asyncio.run(run_async_requests(web_panels.fingerprint_requests("redis", "http://qa/prefix"), async_send))
    assert native == result
    assert calls == expected_calls == [("http://qa/prefix", path) for path in expected_paths]
    return result


@pytest.mark.parametrize("app,build", BUILDS)
def test_official_distribution_metadata_keeps_version_and_parity(app, build):
    assert detect({"appVersion": "2.68.0", "appType": app, "buildType": build}) == (
        "redis_insight",
        "2.68.0",
        ["redis_insight_page", "redis_insight_info"],
    )


@pytest.mark.parametrize(
    "info",
    [
        {"appVersion": "2.68.0", "appType": "DOCKER", "buildType": "ELECTRON"},
        {"appVersion": "2.68.0", "appType": "UNKNOWN", "buildType": "UNKNOWN"},
        {"appVersion": "2.68.0", "appType": "other", "buildType": "other"},
        {"appVersion": "2.68.0", "appType": [], "buildType": {}},
        {"appType": "DOCKER", "buildType": "DOCKER_ON_PREMISE"},
        {"appVersion": "docs example 2.68.0", "appType": "DOCKER", "buildType": "DOCKER_ON_PREMISE"},
    ],
)
def test_missing_unknown_or_contradictory_metadata_is_not_product_evidence(info):
    assert detect(info) is None


@pytest.mark.parametrize("app,build", BUILDS)
@pytest.mark.parametrize(
    "body", ["<title>Other</title>", "<!-- <title>Redis Insight</title> -->", "<title>Redis Insight"]
)
def test_known_build_metadata_alone_cannot_confirm_generic_or_unfinished_page(app, build, body):
    assert detect({"appVersion": "2.68.0", "appType": app, "buildType": build}, body, expected_paths=("/",)) is None
