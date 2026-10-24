"""Pagination end conditions and bounded partial evidence for OCI products."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.modules.registry import actions as registry


def test_nexus_repeated_token_retains_two_pages_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = []

    def request(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        paths.append(args[3])
        return 200, json.dumps({"items": [{"id": str(len(paths))}], "continuationToken": "a/b +"}).encode(), {}, None

    monkeypatch.setattr(registry, "_http_request", request)
    rows, error = registry._fetch_nexus_components("qa", 8081, "docker repo", 1, headers={})
    assert rows == [{"id": "1"}, {"id": "2"}]
    assert error == "partial: nexus component pagination loop detected" and len(paths) == 2
    assert parse_qs(urlsplit(paths[1]).query) == {"repository": ["docker repo"], "continuationToken": ["a/b +"]}


@pytest.mark.parametrize("product", ["catalog", "tags", "nexus", "harbor"])
def test_registry_product_pagination_stops_at_thirty_pages(monkeypatch: pytest.MonkeyPatch, product: str) -> None:
    paths = []

    def request(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        paths.append(args[3])
        number = len(paths)
        headers = {"link": f'</next?page={number + 1}>; rel="next"'}
        payload: Any = {"repositories": [f"repo-{number:02}"], "tags": [f"v{number:02}"]}
        if product == "nexus":
            payload = {"items": [{"id": number}], "continuationToken": str(number)}
        elif product == "harbor":
            payload = [{"name": f"project-{number}"}]
        return 200, json.dumps(payload).encode(), headers, None

    monkeypatch.setattr(registry, "_http_request", request)
    rows: list[Any] | None
    if product == "catalog":
        rows, error = registry._fetch_registry_catalog("qa", 5000, 1, headers={})
    elif product == "tags":
        rows, error = registry._fetch_repository_tags("qa", 5000, "repo", 1, headers={})
    elif product == "nexus":
        rows, error = registry._fetch_nexus_components("qa", 8081, "repo", 1, headers={})
    else:
        rows, error = registry._fetch_harbor_pages(
            "qa", 443, "/api/v2.0/projects?public=true", 1, headers={}, page_size=1
        )
        assert all(parse_qs(urlsplit(path).query)["public"] == ["true"] for path in paths)
    assert rows is not None and len(rows) == 30 and len(paths) == 30
    assert error and error.startswith("partial:") and "pagination limit exceeded" in error


@pytest.mark.parametrize("fault", ["denied", "server", "invalid_json", "invalid_shape", "transport"])
def test_harbor_partial_page_failure_retains_first_page(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    paths = []
    faults = {
        "denied": (403, b"{}", {}, None),
        "server": (503, b"{}", {}, None),
        "invalid_json": (200, b"invalid", {}, None),
        "invalid_shape": (200, b"{}", {}, None),
        "transport": (0, b"", {}, "connection reset"),
    }

    def request(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        paths.append(args[3])
        return (200, b'[{"name":"retained"}]', {}, None) if len(paths) == 1 else faults[fault]

    monkeypatch.setattr(registry, "_http_request", request)
    rows, error = registry._fetch_harbor_pages("qa", 443, "/api/v2.0/projects", 1, headers={}, page_size=1)
    assert rows == [{"name": "retained"}] and error and error.startswith("partial:")
    assert [parse_qs(urlsplit(path).query)["page"] for path in paths] == [["1"], ["2"]]


@pytest.mark.parametrize(
    "product,payload",
    [("catalog", {"repositories": []}), ("tags", {"tags": None}), ("nexus", {"items": [], "continuationToken": None})],
)
def test_empty_product_inventory_completes_in_one_request(
    monkeypatch: pytest.MonkeyPatch, product: str, payload: Any
) -> None:
    calls = []
    monkeypatch.setattr(
        registry,
        "_http_request",
        lambda *args, **kwargs: calls.append(args) or (200, json.dumps(payload).encode(), {}, None),
    )
    result: tuple[list[Any] | None, str | None]
    if product == "catalog":
        result = registry._fetch_registry_catalog("qa", 5000, 1, headers={})
    elif product == "tags":
        result = registry._fetch_repository_tags("qa", 5000, "repo", 1, headers={})
    else:
        result = registry._fetch_nexus_components("qa", 8081, "repo", 1, headers={})
    assert result == ([], None) and len(calls) == 1


@pytest.mark.parametrize("product", ["catalog", "tags"])
def test_registry_pagination_loop_detected_before_reissuing_request(
    monkeypatch: pytest.MonkeyPatch, product: str
) -> None:
    paths = []

    def request(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        paths.append(args[3])
        return 200, b'{"repositories":["app"],"tags":["v1"]}', {"link": f'<{args[3]}>; rel="next"'}, None

    monkeypatch.setattr(registry, "_http_request", request)
    result = (
        registry._fetch_registry_catalog("qa", 5000, 1, headers={})
        if product == "catalog"
        else registry._fetch_repository_tags("qa", 5000, "repo", 1, headers={})
    )
    rows, error = result
    assert rows == (["app"] if product == "catalog" else ["v1"])
    assert len(paths) == 1 and error and "loop detected" in error


@pytest.mark.parametrize(
    "product,payload",
    [
        ("catalog", {"repositories": ["good", {}]}),
        ("tags", {"tags": ["good", " "]}),
        ("nexus", {"items": [{"id": "good"}, None]}),
    ],
)
def test_invalid_inventory_row_invalidates_page(monkeypatch: pytest.MonkeyPatch, product: str, payload: Any) -> None:
    monkeypatch.setattr(
        registry, "_http_request", lambda *args, **kwargs: (200, json.dumps(payload).encode(), {}, None)
    )
    rows: list[Any] | None
    if product == "catalog":
        rows, error = registry._fetch_registry_catalog("qa", 5000, 1, headers={})
    elif product == "tags":
        rows, error = registry._fetch_repository_tags("qa", 5000, "repo", 1, headers={})
    else:
        rows, error = registry._fetch_nexus_components("qa", 8081, "repo", 1, headers={})
    assert rows is None and error and "invalid" in error
