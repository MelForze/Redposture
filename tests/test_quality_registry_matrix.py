"""Cross-vendor registry identity and pagination regression corpus."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.modules.registry import actions


@given(st.lists(st.text(alphabet="abc123-_/", min_size=1, max_size=12), unique=True, max_size=80))
def test_oci_catalog_pagination_preserves_unique_sorted_repositories(names: list[str]) -> None:
    visited: list[str] = []

    def request(_host: str, _port: int, method: str, path: str, _timeout: float, **_kwargs: object):
        assert method == "GET"
        visited.append(path)
        query = parse_qs(urlsplit(path).query)
        offset = int(query.get("offset", ["0"])[0])
        page = names[offset : offset + 7]
        next_offset = offset + len(page)
        headers = (
            {"link": f'</v2/_catalog?n=1000&offset={next_offset}>; rel="next"'} if next_offset < len(names) else {}
        )
        return 200, json.dumps({"repositories": page}).encode(), headers, None

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(actions, "_http_request", request)
        repositories, error = actions._fetch_registry_catalog("registry.local", 5000, 1, headers={})
    assert error is None
    assert repositories == sorted(names)
    assert len(visited) <= (len(names) + 6) // 7 + 1


@pytest.mark.parametrize("product", ["harbor", "nexus", "docker-registry"])
@pytest.mark.parametrize("identity", ["valid", "invalid", "anonymous"])
def test_registry_credential_requires_product_specific_protected_identity(
    monkeypatch: pytest.MonkeyPatch, product: str, identity: str
) -> None:
    requested: list[tuple[str, bool]] = []

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **kwargs: object):
        authorized = bool(kwargs.get("headers", {}).get("Authorization"))
        requested.append((path, authorized))
        if product == "harbor":
            if identity == "invalid":
                return 401, b"", {}, None
            if identity == "anonymous":
                return 200, b"{}", {}, None
            return 200, b'{"username":"alice","user_id":7}', {}, None
        if product == "nexus":
            if not authorized:
                return (200 if identity == "anonymous" else 401), b"[]", {}, None
            if identity == "invalid":
                return 401, b"", {}, None
            return 200, b'[{"userId":"alice"}]', {}, None
        if identity == "invalid":
            return (
                401,
                b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                {"docker-distribution-api-version": "registry/2.0"},
                None,
            )
        return 200, b"", {"docker-distribution-api-version": "registry/2.0"}, None

    monkeypatch.setattr(actions, "_http_request", request)
    probe = (
        200 if identity == "anonymous" else 401,
        b"",
        {"docker-distribution-api-version": "registry/2.0"},
        None,
    )
    confirmed, reason = actions._verify_registry_credential(
        product, "127.0.0.1", 5000, 1, "alice", "secret", None, anonymous_probe=probe
    )
    assert confirmed is {"valid": True, "invalid": False, "anonymous": None}[identity]
    if product == "nexus" and identity == "anonymous":
        assert reason == "Nexus user listing is anonymously accessible"
    assert all(path.startswith(("/api/v2.0", "/service/rest", "/v2/")) for path, _authorized in requested)


@pytest.mark.parametrize("fault", ["denied", "malformed", "loop"])
def test_nexus_component_pagination_keeps_partial_evidence(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    calls: list[str] = []

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        calls.append(path)
        if len(calls) == 1:
            return 200, b'{"items":[{"id":"one"}],"continuationToken":"next"}', {}, None
        if fault == "denied":
            return 403, b"", {}, None
        if fault == "malformed":
            return 200, b"not-json", {}, None
        return 200, b'{"items":[{"id":"two"}],"continuationToken":"next"}', {}, None

    monkeypatch.setattr(actions, "_http_request", request)
    components, error = actions._fetch_nexus_components("127.0.0.1", 8081, "raw", 1, headers={})
    assert components is not None and components[0]["id"] == "one"
    assert error is not None and error.startswith("partial:")
    if fault == "loop":
        assert len(calls) == 2


def test_oci_catalog_repeated_next_link_stops_without_duplicating_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        calls.append(path)
        return 200, b'{"repositories":["app"]}', {"link": '</v2/_catalog?n=1000>; rel="next"'}, None

    monkeypatch.setattr(actions, "_http_request", request)
    repositories, error = actions._fetch_registry_catalog("127.0.0.1", 5000, 1, headers={})
    assert repositories == ["app"]
    assert error == "partial: registry catalog pagination loop detected"
    assert len(calls) == 1


def test_harbor_identity_requires_numeric_user_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        actions,
        "_http_request",
        lambda *_args, **_kwargs: (200, b'{"username":"alice","user_id":"7"}', {}, None),
    )
    decision, reason = actions._verify_registry_credential(
        "harbor", "127.0.0.1", 5000, 1, "alice", "secret", None, anonymous_probe=None
    )
    assert decision is None
    assert reason == "invalid Harbor identity response"


@given(st.lists(st.text(alphabet="ab-", min_size=1, max_size=8), max_size=40))
def test_harbor_pages_obey_count_and_do_not_repeat_page(names: list[str]) -> None:
    requested: list[int] = []

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        query = parse_qs(urlsplit(path).query)
        page_number = int(query["page"][0])
        page_size = int(query["page_size"][0])
        requested.append(page_number)
        offset = (page_number - 1) * page_size
        return (
            200,
            json.dumps([{"name": name} for name in names[offset : offset + page_size]]).encode(),
            {"x-total-count": str(len(names))},
            None,
        )

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(actions, "_http_request", request)
        items, error = actions._fetch_harbor_pages("127.0.0.1", 5000, "/api/v2.0/projects", 1, headers={}, page_size=7)
    assert error is None
    assert [item["name"] for item in items or []] == names
    assert requested == list(range(1, len(requested) + 1))
