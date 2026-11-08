"""Extra Vault sources use only allowlisted GET/LIST operations."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.vault import actions

KEYS = [base64.b64encode(bytes(range(start, start + 32))).decode() for start in (0, 32, 64)]


class Pool:
    def __init__(self, mounts, routes, *, interrupt=None, emitted=None):
        self.mounts, self.routes = mounts, routes
        self.calls = []
        self.interrupt = interrupt
        self.emitted = emitted

    def request(self, method, url, **kwargs):
        assert method in {"GET", "LIST"}
        assert kwargs["headers"].get("X-Vault-Token") == "local-vault-token"
        path = url.removeprefix("http://qa")
        self.calls.append((method, path))
        if path == "/v1/sys/mounts":
            return HttpResponse(200, json.dumps({"data": self.mounts}).encode(), {})
        status, body = self.routes[(method, path)]
        return HttpResponse(status, json.dumps(body).encode(), {})

    def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
        assert method in {"GET", "HEAD", "POST"}, "native HTTP streaming transport rejects LIST"
        assert kwargs["headers"].get("X-Vault-Token") == "local-vault-token"
        assert kwargs["allow_cross_origin_redirects"] is False
        path = url.removeprefix("http://qa")
        self.calls.append((method, path))
        status, body = self.routes[(method, path)]
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        on_response(status, {"Content-Type": "application/json"})
        for offset in range(0, len(raw), 7):
            on_chunk(raw[offset : offset + 7])
        error = "read timeout" if path == self.interrupt else None
        return HttpResponse(status, b"", {}, error=error, truncated=bool(error))


def run(pool, *, mount=None, cancel_after_finding=False):
    emitted = []
    ctx = SimpleNamespace(
        host="qa",
        port=8200,
        args=SimpleNamespace(discover=True, discover_time=30, mount=mount),
        credential=SimpleNamespace(token="local-vault-token"),
        lifecycle_state=SimpleNamespace(http=pool),
        live_emit=emitted.extend,
        cancelled=lambda: cancel_after_finding and bool(emitted),
    )
    result = actions.data_record(
        ctx,
        {
            "status": "valid_credentials",
            "token_valid": True,
            "provided_credentials_ok": True,
            "api_endpoint": "http://qa",
        },
    )
    return result["content_discovery"], emitted


@pytest.mark.parametrize("engine", ["cubbyhole", "transit"])
def test_cancel_preserves_completed_values_and_repeat_rereads_sources(monkeypatch, engine):
    from redposture_core.scheduler import NestedSchedulerCancelled
    from redposture_core.storage_discovery import DiscoveryCollector

    collectors = []

    def capture(*args, **kwargs):
        c = DiscoveryCollector(*args, **kwargs)
        collectors.append(c)
        return c

    monkeypatch.setattr(actions, "DiscoveryCollector", capture)
    routes = (
        transit_routes()
        if engine == "transit"
        else {
            ("LIST", "/v1/cubbyhole/"): (200, {"data": {"keys": ["a", "b"]}}),
            ("GET", "/v1/cubbyhole/a"): (200, {"data": {"password": "inactive-first!42"}}),
            ("GET", "/v1/cubbyhole/b"): (200, {"data": {"password": "inactive-second!42"}}),
        }
    )
    pool = Pool({engine + "/": {"type": engine}}, routes)
    with pytest.raises(NestedSchedulerCancelled):
        run(pool, cancel_after_finding=True)
    result = collectors[-1].result()
    source = next(
        r
        for r in result["sources"]
        if r["id"] == ("vault.transit_exports" if engine == "transit" else "vault.cubbyhole")
    )
    assert result["status"] == "partial" and not source["complete"]
    expected_prefix = {KEYS[0]} if engine == "transit" else {"inactive-first!42"}
    assert {f["value"] for f in result["findings"]} == expected_prefix
    expected = set(KEYS) if engine == "transit" else {"inactive-first!42", "inactive-second!42"}
    for _ in range(2):
        report, emitted = run(Pool({engine + "/": {"type": engine}}, routes))
        assert report["status"] == "complete" and len(emitted) == len(expected)
        assert {f["value"] for f in report["findings"]} == expected
        source = next(
            r
            for r in report["sources"]
            if r["id"] == ("vault.transit_exports" if engine == "transit" else "vault.cubbyhole")
        )
        assert source["complete"]


def transit_routes(*, exportable=True):
    return {
        ("GET", "/v1/transit/keys?list=true"): (200, {"data": {"keys": ["app", "app"]}}),
        ("GET", "/v1/transit/keys/app"): (
            200,
            {"data": {"type": "aes256-gcm96", "exportable": exportable, "keys": {"1": {"public_key": "not-private"}}}},
        ),
        ("GET", "/v1/transit/export/encryption-key/app"): (200, {"data": {"keys": {"1": KEYS[0], "2": KEYS[1]}}}),
        ("GET", "/v1/transit/export/hmac-key/app"): (200, {"data": {"keys": {"1": KEYS[2]}}}),
    }


def test_cubbyhole_walk_reads_token_private_values_and_repeated_keys_once():
    pool = Pool(
        {"cubbyhole/": {"type": "cubbyhole"}},
        {
            ("LIST", "/v1/cubbyhole/"): (200, {"data": {"keys": ["app", "nested/", "app"]}}),
            ("GET", "/v1/cubbyhole/app"): (200, {"data": {"password": "inactive-cubbyhole!42"}}),
            ("LIST", "/v1/cubbyhole/nested/"): (200, {"data": {"keys": ["other"]}}),
            ("GET", "/v1/cubbyhole/nested/other"): (200, {"data": {"password": "inactive-nested!42"}}),
        },
    )
    report, emitted = run(pool)
    assert report["status"] == "complete", report["partial_reasons"]
    assert {r["value"] for r in report["findings"]} == {"inactive-cubbyhole!42", "inactive-nested!42"}
    assert pool.calls.count(("GET", "/v1/cubbyhole/app")) == 1
    source = next(s for s in report["sources"] if s["id"] == "vault.cubbyhole")
    assert source["read"] == 2 and source["complete"] and len(emitted) == 2


def test_transit_exports_each_existing_private_version_but_never_public_keys_or_generates_material():
    pool = Pool({"transit/": {"type": "transit"}}, transit_routes())
    report, emitted = run(pool)
    assert report["status"] == "complete", report["partial_reasons"]
    assert {r["value"] for r in report["findings"]} == set(KEYS)
    assert {r["type"] for r in report["findings"]} == {"generic_secret"}
    assert pool.calls.count(("GET", "/v1/transit/keys/app")) == 1
    assert all(
        "public-key" not in p and "encrypt/" not in p and "creds/" not in p and "rotate" not in p for m, p in pool.calls
    )
    source = next(s for s in report["sources"] if s["id"] == "vault.transit_exports")
    assert source["read"] == 2 and source["complete"]
    assert len(emitted) == 3
    places = [loc for finding in report["findings"] for loc in finding["locations"]]
    assert {p["version"] for p in places} == {"1", "2"}
    assert all(p["source_kind"] == "vault_transit_export" and p["object"] == "app" for p in places)


def test_mount_selector_does_not_touch_other_engines():
    pool = Pool(
        {"cubbyhole/": {"type": "cubbyhole"}, "transit/": {"type": "transit"}, "database/": {"type": "database"}},
        {("LIST", "/v1/cubbyhole/"): (404, {"errors": []})},
    )
    report, _ = run(pool, mount="cubbyhole/")
    assert report["status"] == "complete" and not report["findings"]
    assert all("transit" not in p and "database" not in p for _, p in pool.calls)


def test_transit_nonexportable_material_is_partial_and_not_read_as_metadata():
    pool = Pool({"transit/": {"type": "transit"}}, transit_routes(exportable=False))
    report, _ = run(pool)
    assert report["status"] == "partial" and not report["findings"]
    assert not any("/export/" in path for _, path in pool.calls)
    source = next(s for s in report["sources"] if s["id"] == "vault.transit_exports")
    assert source["unsupported"] and not source["complete"]


@pytest.mark.parametrize("engine", ["kv", "cubbyhole"])
def test_all_denied_stored_values_are_unavailable_not_complete_or_generic_partial(engine):
    pool = Pool({"chosen/": {"type": engine}}, {("LIST", "/v1/chosen/"): (403, {"errors": ["permission denied"]})})
    report, _ = run(pool)
    assert report["status"] == "unavailable", report
    assert not report["findings"]
    source = next(
        s for s in report["sources"] if s["id"] == ("vault.cubbyhole" if engine == "cubbyhole" else "vault.kv")
    )
    assert source["denied"] == 1 and not source["complete"]


@pytest.mark.parametrize("failure", ["http403", "cut-json", "timeout", "invalid-value"])
def test_completed_export_value_survives_later_failure(failure):
    routes = transit_routes()
    path = "/v1/transit/export/encryption-key/app"
    prefix = ('{"data":{"keys":{"1":"' + KEYS[0] + '",').encode()
    if failure == "http403":
        routes[("GET", "/v1/transit/export/hmac-key/app")] = (403, {"errors": ["forbidden"]})
    elif failure == "invalid-value":
        routes[("GET", path)] = (200, {"data": {"keys": {"1": KEYS[0], "2": 42}}})
    else:
        routes[("GET", path)] = (200, prefix + b'"2":"unfinished')
    pool = Pool({"transit/": {"type": "transit"}}, routes, interrupt=path if failure == "timeout" else None)
    report, _ = run(pool)
    assert report["status"] == "partial" and report["partial_reasons"]
    assert KEYS[0] in {row["value"] for row in report["findings"]}
    assert not any(str(row["value"]).startswith("unfinished") for row in report["findings"])
    source = next(s for s in report["sources"] if s["id"] == "vault.transit_exports")
    assert not source["complete"]


def test_unknown_engine_has_explicit_manifest_and_never_dynamic_credential_request():
    pool = Pool({"database/": {"type": "database"}}, {})
    report, _ = run(pool)
    assert report["status"] == "partial" and not report["findings"]
    source = next(s for s in report["sources"] if s["id"] == "vault.unsupported_engines")
    assert source["implemented"] is False and source["unsupported"] and not source["read"]
    assert pool.calls == [("GET", "/v1/sys/mounts")]


def test_large_export_value_keeps_full_disk_text_without_masking():
    routes = transit_routes()
    value = base64.b64encode(bytes(range(256)) * 1000).decode()
    routes[("GET", "/v1/transit/export/encryption-key/app")] = (200, {"data": {"keys": {"1": value}}})
    pool = Pool({"transit/": {"type": "transit"}}, routes)
    report, _ = run(pool)
    assert report["status"] == "complete", report["partial_reasons"]
    found = [row["value"] for row in report["findings"]]
    assert any(isinstance(v, DiskBackedText) and "".join(v.iter_text_chunks()) == value for v in found)


@pytest.mark.parametrize("value", ["not-a-key", "password=not-exported", "AA==", "!!!!"])
def test_malformed_export_text_is_not_promoted_to_a_secret(value):
    routes = transit_routes()
    routes[("GET", "/v1/transit/export/encryption-key/app")] = (200, {"data": {"keys": {"1": value}}})
    report, _ = run(Pool({"transit/": {"type": "transit"}}, routes))
    assert report["status"] == "partial"
    assert value not in {row["value"] for row in report["findings"]}
    assert any("invalid_private_export_encoding" in r for r in report["partial_reasons"])


def test_uniform_but_well_formed_exported_material_is_not_lost_to_entropy_filters():
    routes = transit_routes()
    value = base64.b64encode(bytes(32)).decode()
    routes[("GET", "/v1/transit/export/encryption-key/app")] = (200, {"data": {"keys": {"1": value}}})
    report, _ = run(Pool({"transit/": {"type": "transit"}}, routes))
    assert report["status"] == "complete"
    finding = next(row for row in report["findings"] if row["value"] == value)
    assert finding["confidence"] == "high" and "vault_private_export" in finding["detectors"]
