"""Existing detector selectors retain canonical values through disk spools."""

from __future__ import annotations

import base64

import pytest

from redposture_core.discovery_engine import _scan_portioned_value, _scan_text_chunks
from redposture_core.discovery_matches import SpoolingSecretMatches
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.clickhouse.discover.engine import _scan_rows
from redposture_core.modules.clickhouse.discover.models import ScanChunk
from redposture_core.secret_detection import detector_matches


def test_valid_bearer_jwt_preserves_bearer_selector_and_all_evidence():
    from redposture_core.secret_detection import scan_value

    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJxYSJ9.c2lnbmF0dXJl"
    matches = scan_value("Authorization: Bearer " + token, enabled=("bearer_token",))
    assert len(matches) == 1 and matches[0].value == token
    assert matches[0].detector == "jwt"
    assert detector_matches(matches[0], ("bearer_token",))
    assert {"jwt_structure", "bearer_auth"} <= set(matches[0].rule_ids)


@pytest.mark.parametrize(
    "alias,body",
    [
        ("connection_string", "postgres://qa:inactive-password@db.invalid/app"),
        ("url_credentials", "postgres://qa:inactive-password@db.invalid/app"),
        ("basic_auth", "Basic " + base64.b64encode(b"qa:inactive-password").decode()),
    ],
)
def test_legacy_selector_keeps_complete_carrier_in_clickhouse(alias, body):
    findings = {}
    coverage = {"qa.items.message": {"rows_scanned": 0, "bytes_scanned": 0}}
    assert _scan_rows(
        [[body]], ScanChunk("qa", "items", ("message",), None, 0, 1), findings, coverage, enabled=(alias,), redact=False
    )
    assert len(findings) == 1
    assert next(iter(findings.values()))["value"] == body


@pytest.mark.parametrize("route", ["inline", "stream", "disk-path"])
def test_alias_and_rule_ids_survive_spilling_and_path_remapping(route):
    body = "Basic " + base64.b64encode(b"qa:inactive-password").decode()
    if route == "stream":
        matches, complete = _scan_text_chunks((body[n : n + 3] for n in range(0, len(body), 3)), "$.body", 64)
    elif route == "disk-path":
        with DiskBackedText() as path:
            path.append_text("$." + "long-key-" * 10000)
            path.finish()
            matches, _size, complete = _scan_portioned_value(body, path, 64)
            # Adopt source-owned paths before closing the original input.
            matches = SpoolingSecretMatches(matches, inline_limit=0)
    else:
        matches, _size, complete = _scan_portioned_value(body, "$.body", 65536)
    assert complete
    spilled = SpoolingSecretMatches(matches, inline_limit=0)
    match = spilled[0]
    assert detector_matches(match, ("basic_auth",))
    assert "basic_auth" in match.rule_ids
    assert match.detector == "basic_auth"
    value = "".join(match.value.iter_text_chunks()) if isinstance(match.value, DiskBackedText) else match.value
    assert value == body
