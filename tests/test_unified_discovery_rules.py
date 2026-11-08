"""Independently specified values must agree through every scalar entry point."""

from __future__ import annotations

import base64

import pytest

from redposture_core.discovery_engine import _scan_portioned_value, _scan_text_chunks
from redposture_core.discovery_rules import analyze_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.elastic.discover import scan_value_tree


def plain(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize("entry", ["scalar", "common", "elastic", "disk", "stream"])
@pytest.mark.parametrize(
    "body,expected",
    [
        ("postgres://qa:p%40ss@db.invalid/db", {"postgres://qa:p%40ss@db.invalid/db"}),
        ("connect failed: postgres://qa:p%40ss@db.invalid/db", {"postgres://qa:p%40ss@db.invalid/db"}),
        (
            "Authorization: Basic " + base64.b64encode(b"qa:inactive-basic-password").decode(),
            {"Basic " + base64.b64encode(b"qa:inactive-basic-password").decode()},
        ),
        ("ALTER USER qa IDENTIFIED BY 'inactive-sql-password';", {"inactive-sql-password"}),
        ("username,password\nqa,inactive-csv-password\n", {"inactive-csv-password"}),
        ("hvs." + "InactiveOnly0123456789abcdefghijklmnop", {"hvs." + "InactiveOnly0123456789abcdefghijklmnop"}),
        ("eyJnotjsonheader.abcdefghijk.0123456789", set()),
        ("-----BEGIN CERTIFICATE-----\nINACTIVEPUBLICCERTIFICATE\n-----END CERTIFICATE-----", set()),
        ("postgres://db.invalid:5432/app", set()),
        ("http://[broken", set()),
    ],
    ids=[
        "uri-password",
        "embedded-uri",
        "basic-password",
        "sql-identified-by",
        "csv",
        "vault-token",
        "invalid-jwt",
        "public-certificate",
        "uri-without-credentials",
        "malformed-uri",
    ],
)
def test_scalar_entry_points_extract_the_same_full_secrets(entry, body, expected):
    if entry == "scalar":
        actual = {plain(item.value) for item in analyze_value(body) if item.available}
    elif entry == "common":
        matches, _size, complete = _scan_portioned_value({"body": body}, "$", 65536)
        assert complete, getattr(matches, "incomplete_reason", None)
        actual = {plain(item.value) for item in matches}
    elif entry == "elastic":
        result = scan_value_tree({"body": body}, source_kind="document", object_name="qa/one")
        assert not result.truncated_reasons
        actual = {plain(item.value) for item, _location in result.detections if item.available}
    elif entry == "disk":
        with DiskBackedText() as disk:
            disk.append_text(body)
            disk.finish()
            matches, _size, complete = _scan_portioned_value(disk, "$.body", 64)
            actual = {plain(item.value) for item in matches}
            assert complete, getattr(matches, "incomplete_reason", None)
    else:
        matches, complete = _scan_text_chunks((body[i : i + 3] for i in range(0, len(body), 3)), "$.body", 64, 0)
        actual = {plain(item.value) for item in matches}
        assert complete, getattr(matches, "incomplete_reason", None)
    assert actual == expected


def test_elastic_default_retains_all_unique_locations_beyond_the_old_cap():
    import json

    from redposture_core.discovery_values import iter_json_chunks
    from redposture_core.modules.elastic.discover import DetectedSecret, FindingAccumulator, FindingLocation

    accumulator = FindingAccumulator(spill_threshold=1)
    for n in list(range(150)) + [149, 0]:
        assert accumulator.add(
            DetectedSecret("inactive-location-password", "password", 85, ("sensitive_field",)),
            FindingLocation("document", f"qa/{n}", "/password", index="qa", id=str(n)),
        )
    finding = accumulator.findings()[0]
    assert finding.occurrence_count == len(finding.locations) == 150
    assert accumulator.locations_dropped == 0
    output = json.loads("".join(iter_json_chunks(finding.to_dict())))
    assert {p["id"] for p in output["locations"]} == {str(n) for n in range(150)}
    assert output["value"] == "inactive-location-password"
    assert finding.locations.copy() == [item for item in finding.locations]
    assert not (finding.locations != finding.locations.copy())
    assert next(reversed(finding.locations)).id == "149"


def test_elastic_equal_value_different_field_roles_is_one_finding():
    from redposture_core.modules.elastic.discover import DetectedSecret, FindingAccumulator, FindingLocation

    accumulator = FindingAccumulator()
    accumulator.add(
        DetectedSecret("inactive-equal-secret", "secret", 68, ("sensitive_field",)),
        FindingLocation("document", "qa/one", "/api_key"),
    )
    accumulator.add(
        DetectedSecret("inactive-equal-secret", "password", 90, ("credential_pair",)),
        FindingLocation("document", "qa/two", "/password"),
    )
    findings = accumulator.findings()
    assert len(findings) == 1
    assert findings[0].secret_type == "password"
    assert findings[0].occurrence_count == 2
