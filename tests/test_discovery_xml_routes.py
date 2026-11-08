"""XML secret elements/attributes have no size-dependent shortcut grammar."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from redposture_core.discovery_engine import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.storage_discovery import DiscoveryCollector


def text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize("size", [80, 6000, 100_000])
@pytest.mark.parametrize("kind", ["element", "attribute", "neutral"])
def test_xml_values_and_places_match_scalar_disk_and_chunked_json(size, kind):
    secret = ("inactive-Ab3_" * (size // 13 + 2))[:size] + "&tail"
    escaped = secret.replace("&", "&amp;")
    source = {
        "element": f"<api_token>{escaped}</api_token>",
        "attribute": f'<input name="api_token" value="{escaped}"/>',
        "neutral": f"<description>{escaped}</description>",
    }[kind]
    stored = DiskBackedText()
    stored.append_text(source)
    stored.finish()
    observations = []
    for value in [source, stored]:
        matches, _, complete = _scan_portioned_value({"body": value}, "$.source", 65536)
        assert complete, getattr(matches, "incomplete_reason", None)
        observations.append([(text(m.value), text(m.object_path)) for m in matches])
    collector = DiscoveryCollector(
        "gitlab",
        SimpleNamespace(
            args=SimpleNamespace(discover_time=30),
            host="qa",
            port=1,
        ),
        {"status": "open_no_auth"},
    )
    raw = json.dumps({"body": source}).encode()
    assert collector.scan_json_chunks("source", (raw[i : i + 37] for i in range(0, len(raw), 37)))
    report = collector.result()
    assert report["status"] == "complete", report["partial_reasons"]
    observations.append([(text(m["value"]), text(m["object_path"])) for m in report["findings"]])
    assert observations[0] == observations[1] == observations[2]
    if kind == "neutral":
        assert not observations[0]
    else:
        assert len(observations[0]) == 1
        assert observations[0][0][0] == secret
        assert hashlib.sha256(observations[0][0][0].encode()).digest() == hashlib.sha256(secret.encode()).digest()
