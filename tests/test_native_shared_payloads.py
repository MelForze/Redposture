"""Raw native values retain their encoding until the shared format reader."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
from types import SimpleNamespace

import pytest

from redposture_core.clients.mongodb import _discovery_document
from redposture_core.discovery_bytes import SpoolBytes
from redposture_core.discovery_engine import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.redis.discovery import RedisBulk, _DiscoverySession
from redposture_core.modules.zookeeper.discovery import discover_znodes
from redposture_core.storage_discovery import DiscoveryCollector

PASSWORD = "qa-native-format-password-2026"
BODY = f'password="{PASSWORD}"\n'


def full(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


def context():
    return SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=1)


@pytest.mark.parametrize("kind", ["utf8", "utf16", "gzip", "binary", "corrupt-gzip"])
@pytest.mark.parametrize("module", ["redis", "mongodb", "zookeeper", "keeper"])
@pytest.mark.parametrize("spooled", [False, True])
def test_native_value_dispatch_preserves_full_value_and_coverage(kind, module, spooled):
    raw = {
        "utf8": BODY.encode(),
        "utf16": BODY.encode("utf-16"),
        "gzip": gzip.compress(BODY.encode()),
        "binary": b"\xff\x00unreadable",
        "corrupt-gzip": gzip.compress(BODY.encode())[:-6],
    }[kind]
    if module == "mongodb":
        # Exercise the actual PyMongo -> Extended JSON adapter, including its
        # disk-backed base64 branch without making the test allocate a BSON max.
        if spooled:
            raw = raw + (b" " * 50_000 if kind in {"utf8", "binary"} else b"")
        value = _discovery_document({"config": raw}, None)
        if spooled and isinstance(value["config"]["$binary"]["base64"], str):
            encoded = DiskBackedText()
            encoded.append_text(value["config"]["$binary"]["base64"])
            encoded.finish()
            value["config"]["$binary"]["base64"] = encoded
        matches, _, complete = _scan_portioned_value(value, "$.document", 64)
        values = {full(row.value) for row in matches}
        places = [full(row.object_path) for row in matches]
        reasons = [getattr(matches, "incomplete_reason", None)]
    elif module == "redis":
        session = _DiscoverySession.__new__(_DiscoverySession)
        session.collector = DiscoveryCollector(module, context(), {"status": "open_no_auth"})
        source = io.BytesIO(raw)
        shown = session.scalar(
            "config",
            RedisBulk(source, len(raw), hashlib.sha256(raw).hexdigest()) if spooled else raw,
            "key_value_entries.config",
        )
        expected_display = raw.decode() if kind == "utf8" else "base64:" + base64.b64encode(raw).decode()
        assert full(shown) == expected_display
        if spooled:
            assert source.closed
        result = session.collector.result()
        complete = result["status"] == "complete"
        values = {full(row["value"]) for row in result["findings"]}
        places = [full(row["object_path"]) for row in result["findings"]]
        reasons = result["partial_reasons"]
    else:

        class Client:
            def get_data_discovery(self, path, **kwargs):
                assert path == "/config"
                if spooled:
                    data = SpoolBytes()
                    data.write(raw)
                    return data, 0, None
                return raw, 0, None

            def read_children_discovery(self, *args, **kwargs):
                raise AssertionError("a selected znode must not traverse children")

        result = discover_znodes(
            context(), {"module": module, "status": "open_no_auth"}, Client(), {"query_znode": "/config"}
        )["content_discovery"]
        complete = result["status"] == "complete"
        values = {full(row["value"]) for row in result["findings"]}
        places = [full(row["object_path"]) for row in result["findings"]]
        reasons = result["partial_reasons"]
    if kind in {"binary", "corrupt-gzip"}:
        assert not complete, reasons
        assert reasons and any(reasons)
        # A completed quoted value survives a missing gzip trailer. Unknown
        # binary never becomes a secret just because its content was readable.
        assert values == ({PASSWORD} if kind == "corrupt-gzip" else set())
    else:
        assert complete, reasons
        assert values == {PASSWORD}
        assert len(places) == 1
        assert "config" in places[0]
        assert hashlib.sha256(next(iter(values)).encode()).digest() == hashlib.sha256(PASSWORD.encode()).digest()


@pytest.mark.parametrize("subtype", ["06", "80"])
def test_bson_non_generic_binary_requires_its_own_schema(subtype):
    value = {"$binary": {"base64": base64.b64encode(BODY.encode()).decode(), "subType": subtype}}
    matches, _, complete = _scan_portioned_value(value, "$.source", 64)
    assert not complete
    assert not matches
    assert matches.incomplete_reason == "unsupported_binary_subtype"


@pytest.mark.parametrize("encoded", ["!!!!", "YQ", "YQ==tail", "YQ==="])
def test_bson_invalid_base64_is_partial_without_prefix_findings(encoded):
    matches, _, complete = _scan_portioned_value({"$binary": {"base64": encoded, "subType": "00"}}, "$", 64)
    assert not complete
    assert not matches
    assert matches.incomplete_reason == "invalid_binary_encoding"


def test_literal_base64_display_prefix_is_not_a_wire_encoding_contract():
    value = "base64:" + base64.b64encode(BODY.encode("utf-16")).decode()
    matches, _, complete = _scan_portioned_value({"ordinary": value}, "$", 64)
    assert complete
    assert PASSWORD not in {full(row.value) for row in matches}
