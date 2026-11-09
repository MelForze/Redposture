"""Vault discovery routes complete mount/key identities beyond the old 4KiB cap."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote, urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.vault import actions
from redposture_core.modules.vault.policy import validate_args


class VaultPool:
    def __init__(self, routes, streams=None):
        self.routes = routes
        self.streams = streams or {}
        self.calls = []

    def request(self, method, url, **kwargs):
        parsed = urlsplit(url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        self.calls.append((method, path))
        assert path in self.routes, f"unexpected Vault route: {path}"
        value = self.routes[path]
        if isinstance(value, HttpResponse):
            return value
        return HttpResponse(200, json.dumps(value).encode(), {"Content-Type": "application/json"})

    def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
        parsed = urlsplit(url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        self.calls.append((method, path))
        assert path in self.streams, f"unexpected streamed Vault route: {path}"
        body = self.streams[path]
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        on_response(200, {"Content-Type": "application/json"})
        for offset in range(0, len(body), 127):
            on_chunk(body[offset : offset + 127])
        return HttpResponse(200, b"", {"Content-Type": "application/json"})


def _run(pool, **options):
    ctx = SimpleNamespace(
        host="qa",
        port=8200,
        args=SimpleNamespace(discover=True, discover_time=900, **options),
        credential=None,
        lifecycle_state=SimpleNamespace(http=pool),
    )
    return actions.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})


def _text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


def _findings(result):
    return [(_text(item["value"]), _text(item["object_path"])) for item in result["content_discovery"]["findings"]]


def test_long_mount_selector_is_accepted_and_normalized_by_vault_policy():
    mount = "catalog_" + "q" * 5000
    args = SimpleNamespace(discover=True, mount=mount, discover_time=900)
    errors = []
    assert validate_args(args, SimpleNamespace(error=errors.append)) is None
    assert args.mount == mount + "/"
    assert errors == []


def test_deep_mount_selector_is_valid_without_a_client_component_count_cap():
    mount = "m/" * 130
    args = SimpleNamespace(discover=True, mount=mount, discover_time=900)
    errors = []
    assert validate_args(args, SimpleNamespace(error=errors.append)) is None
    assert args.mount == mount
    assert errors == []


@pytest.mark.parametrize("deep_component", ["mount", "key"])
def test_deep_valid_mount_or_key_is_traversed_without_dropping_the_secret(deep_component):
    mount = "m/" * 130 if deep_component == "mount" else "secret/"
    directory = "k/" * 130 if deep_component == "key" else ""
    routes: dict[str, Any] = {"/v1/sys/mounts": {"data": {mount: {"type": "kv"}}}}
    if deep_component == "key":
        for depth in range(130):
            routes["/v1/" + mount + "k/" * depth] = {"data": {"keys": ["k/"]}}
    routes["/v1/" + mount + directory] = {"data": {"keys": ["entry"]}}
    routes["/v1/" + mount + directory + "entry"] = {"data": {"password": "known-deep-secret"}}
    pool = VaultPool(routes)
    result = _run(pool)
    assert result["kv_secrets_read"] == 1
    assert result["content_discovery"]["status"] == result["inventory_status"] == "complete"
    assert _findings(result) == [("known-deep-secret", f"$.kv_dump_items.{mount}{directory}entry.entry.password")]
    assert ("GET", "/v1/" + mount + directory + "entry") in pool.calls


@pytest.mark.parametrize("stream_catalog", [False, True])
@pytest.mark.parametrize("selection", ["all", "long", "short"])
def test_long_neutral_kv_mount_routes_exactly_and_respects_selection(stream_catalog, selection):
    mount = "catalog_" + "q" * 5000 + "/"
    catalog = {"data": {mount: {"type": "kv"}, "short/": {"type": "kv"}}}
    routes: dict[str, Any] = {"/v1/sys/mounts": catalog}
    streams = {}
    if stream_catalog:
        routes["/v1/sys/mounts"] = HttpResponse(200, b'{"data":{', {}, truncated=True)
        streams["/v1/sys/mounts"] = catalog
    wanted = [mount, "short/"] if selection == "all" else [mount if selection == "long" else "short/"]
    for name in wanted:
        routes["/v1/" + quote(name, safe="/")] = {"data": {"keys": ["entry"]}}
        routes["/v1/" + quote(name, safe="/") + "entry"] = {
            "data": {
                "password": "known-long-secret" if name == mount else "known-short-secret",
                "note": "ordinary text",
            }
        }
    pool = VaultPool(routes, streams)
    selected = {} if selection == "all" else {"mount": wanted[0]}
    result = _run(pool, **selected)
    assert result["kv_secrets_read"] == len(wanted)
    assert result["inventory_status"] == "complete"
    assert result["content_discovery"]["status"] == "complete"
    expected = {
        ("known-long-secret" if name == mount else "known-short-secret", f"$.kv_dump_items.{name}entry.entry.password")
        for name in wanted
    }
    assert set(_findings(result)) == expected
    encoded = json.loads("".join(iter_json_chunks(result["content_discovery"])))
    assert {(item["value"], item["object_path"]) for item in encoded["findings"]} == expected
    if selection == "short":
        assert not any(mount in path for _method, path in pool.calls)


@pytest.mark.parametrize("stream_keys", [False, True])
@pytest.mark.parametrize("version", ["1", "2"])
def test_long_kv_directory_and_leaf_are_both_followed_without_truncation(stream_keys, version):
    directory = "folder_" + "q" * 5000 + "/"
    key = "entry_" + "r" * 5000
    listing = "/v1/secret/" + ("metadata/" if version == "2" else "")
    reading = "/v1/secret/" + ("data/" if version == "2" else "")
    routes = {
        "/v1/sys/mounts": {"data": {"secret/": {"type": "kv", "options": {"version": version}}}},
        listing: {"data": {"keys": [directory]}},
        listing + directory: {"data": {"keys": [key]}},
        reading + directory + key: {
            "data": {"data": {"password": "known-vault-secret"}}
            if version == "2"
            else {"password": "known-vault-secret"}
        },
    }
    streams: dict[str, Any] = {}
    if version == "2":
        streams[listing + directory + key] = {
            "data": {"current_version": 1, "versions": {"1": {"destroyed": False, "deletion_time": ""}}}
        }
    if stream_keys:
        for path in (listing, listing + directory):
            streams[path + "?list=true"] = routes[path]
            routes[path] = HttpResponse(200, b'{"data":{"keys":[', {}, truncated=True)
    pool = VaultPool(routes, streams)
    result = _run(pool)
    assert result["kv_secrets_read"] == 1
    assert result["content_discovery"]["status"] == result["inventory_status"] == "complete"
    assert _findings(result) == [("known-vault-secret", f"$.kv_dump_items.secret/{directory}{key}.{key}.password")]
    assert ("GET", reading + directory + key) in pool.calls


@pytest.mark.parametrize("stream_keys", [False, True])
def test_invalid_key_routes_are_partial_and_keep_valid_completed_prefix(stream_keys):
    key = "entry_" + "q" * 5000
    listing = {"data": {"keys": ["good", "../escape", "/outside", "a//b", "a?query", "a#fragment", "a\ncontrol", key]}}
    routes = {
        "/v1/sys/mounts": {"data": {"secret/": {"type": "kv"}}},
        "/v1/secret/": listing,
        "/v1/secret/good": {"data": {"password": "prefix-secret"}},
        "/v1/secret/" + key: {"data": {"password": "tail-secret"}},
    }
    streams = {}
    if stream_keys:
        routes["/v1/secret/"] = HttpResponse(200, b'{"data":{"keys":[', {}, truncated=True)
        streams["/v1/secret/?list=true"] = listing
    result = _run(VaultPool(routes, streams))
    assert result["kv_secrets_read"] == 2
    assert result["kv_discovery_partial"] is True
    assert result["content_discovery"]["status"] == result["inventory_status"] == "partial"
    assert set(_findings(result)) == {
        ("prefix-secret", "$.kv_dump_items.secret/good.good.password"),
        ("tail-secret", f"$.kv_dump_items.secret/{key}.{key}.password"),
    }


def test_malformed_streamed_listing_keeps_closed_key_prefix_as_partial():
    key = "entry_" + "q" * 5000
    prefix = (json.dumps({"data": {"keys": ["good", key]}})[:-3] + ",").encode()
    pool = VaultPool(
        {
            "/v1/sys/mounts": {"data": {"secret/": {"type": "kv"}}},
            "/v1/secret/": HttpResponse(200, b'{"data":{"keys":[', {}, truncated=True),
            "/v1/secret/good": {"data": {"password": "prefix-secret"}},
            "/v1/secret/" + key: {"data": {"password": "tail-secret"}},
        },
        {"/v1/secret/?list=true": prefix},
    )
    result = _run(pool)
    assert result["kv_secrets_read"] == 2
    assert result["content_discovery"]["status"] == result["inventory_status"] == "partial"
    assert {value for value, _place in _findings(result)} == {"prefix-secret", "tail-secret"}
