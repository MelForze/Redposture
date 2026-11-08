"""Closed quoted values may contain markup without a second partial finding."""

from __future__ import annotations

import json
from io import BytesIO
from types import SimpleNamespace

import pytest

from redposture_core.discovery_values import iter_json_chunks
from redposture_core.secret_detection import scan_value
from redposture_core.storage_discovery import DiscoveryCollector


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("field,detector", [("password", "password"), ("client_secret", "client_secret")])
@pytest.mark.parametrize("value", ["qa-before-<tag>-secret", "qa-<inner>λ</inner>-secret"])
def test_closed_quoted_assignment_has_one_full_match_without_partial_copy(quote, field, detector, value):
    source = f"{field}={quote}{value}{quote}"
    matches = scan_value(source, enabled=["password", "client_secret"])
    assert [(match.detector, match.value, match.object_path) for match in matches] == [(detector, value, "$")]


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_markup_in_log_keeps_full_value_once_and_stable_place(quote):
    value = "qa-before-<tag>-password"
    source = f"password={quote}{value}{quote}\n"
    lines = []
    collector = DiscoveryCollector(
        "jenkins",
        SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80, live_emit=lines.extend),
        {"status": "open_no_auth"},
    )
    collector._scan_member_stream("config", "runtime/app.log", BytesIO(source.encode()), prefer_specific=True)
    result = collector.result()
    assert result["status"] == "complete"
    assert [(row["type"], row["value"], row["object_path"]) for row in result["findings"]] == [
        ("password", value, "$.config/file/runtime/app.log")
    ]
    assert len(lines) == 1 and f'Value="{value}"' in lines[0]
    encoded = "".join(iter_json_chunks(result))
    assert [row["value"] for row in json.loads(encoded)["findings"]] == [value]
    assert "\x1b" not in encoded and "\x1b" not in lines[0]
