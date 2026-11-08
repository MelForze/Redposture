"""Heuristic candidates remain ordinary findings with explicitly low confidence."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.discovery_engine import _scan_portioned_value, _scan_text_chunks
from redposture_core.discovery_rules import _confidence, analyze_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.elastic.discover import FindingAccumulator, scan_value_tree
from redposture_core.storage_discovery import DiscoveryCollector

TOKEN = "qR7xN2pV5tC8fK3sM9zD6aL4bE1"


def plain(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize("entry", ["scalar", "common", "disk", "stream", "elastic", "elastic-disk", "storage"])
def test_neutral_entropy_candidate_is_a_full_low_confidence_finding(entry):
    body = f"service message {TOKEN} completed\n"
    if entry == "scalar":
        rows = [(r.secret_type, _confidence(r.score), plain(r.value)) for r in analyze_value(body) if r.available]
    elif entry in {"common", "disk", "stream"}:
        if entry == "stream":
            matches, complete = _scan_text_chunks((body[i : i + 3] for i in range(0, len(body), 3)), "$.body", 64, 0)
        elif entry == "disk":
            with DiskBackedText() as disk:
                disk.append_text(body)
                disk.finish()
                matches, _, complete = _scan_portioned_value(disk, "$.body", 64)
        else:
            matches, _, complete = _scan_portioned_value({"body": body}, "$", 64)
        assert complete
        rows = [(r.detector, r.confidence, plain(r.value)) for r in matches]
    elif entry.startswith("elastic"):
        with DiskBackedText() as disk:
            disk.append_text(body)
            disk.finish()
            result = scan_value_tree(
                {"body": disk if entry.endswith("disk") else body}, source_kind="document", object_name="qa/one"
            )
            assert not result.truncated_reasons
            findings = FindingAccumulator()
            for detection, location in result.detections:
                findings.add(detection, location)
            rows = [(r.secret_type, r.confidence, plain(r.value)) for r in findings.findings()]
    else:
        collector = DiscoveryCollector(
            "gitlab",
            SimpleNamespace(host="qa", port=443, args=SimpleNamespace(discover_time=900)),
            {"status": "open_no_auth"},
        )
        collector.add("log", {"body": body})
        report = collector.result()
        assert report["status"] == "complete"
        rows = [(r["type"], r["confidence"], plain(r["value"])) for r in report["findings"]]
    assert rows == [("high_entropy", "low", TOKEN)]


@pytest.mark.parametrize("field", ["checksum", "public_key", "token_count"])
def test_entropy_policy_keeps_metadata_exclusions(field):
    result = scan_value_tree({field: TOKEN}, source_kind="document", object_name="qa/one")
    assert not [(r, p) for r, p in result.detections if r.available]


def test_explicit_provider_stays_high_confidence_without_an_entropy_duplicate():
    token = "glpat-InactiveOnly0123456789abcdef"
    rows = [r for r in analyze_value(token) if r.available]
    assert len(rows) == 1
    assert rows[0].secret_type == "gitlab_token" and rows[0].score >= 90


@pytest.mark.parametrize("reverse", [False, True])
def test_explicit_evidence_promotes_candidate_without_losing_places(reverse):
    values = [{"body": TOKEN}, {"password": TOKEN}]
    result = scan_value_tree(values[::-1] if reverse else values, source_kind="document", object_name="qa/one")
    findings = FindingAccumulator()
    for detection, location in result.detections:
        findings.add(detection, location)
    rows = findings.findings()
    assert len(rows) == 1
    row = rows[0]
    assert plain(row.value) == TOKEN and row.secret_type == "password"
    assert (row.score, row.confidence) == (90, "very_high") and row.occurrence_count == 2
    assert set(row.detectors) >= {"entropy_candidate", "sensitive_field"}


def test_repeated_heuristic_stays_low_and_keeps_all_places():
    result = scan_value_tree([{"body": TOKEN} for _ in range(150)], source_kind="document", object_name="qa/one")
    findings = FindingAccumulator()
    for detection, location in result.detections:
        findings.add(detection, location)
    rows = findings.findings()
    assert len(rows) == 1
    assert (rows[0].score, rows[0].confidence) == (55, "low")
    assert rows[0].occurrence_count == len(rows[0].locations) == 150


@pytest.mark.parametrize("entry", ["scalar", "common", "disk", "stream", "elastic", "elastic-disk"])
def test_entropy_token_above_grammar_limit_is_not_reported_as_a_cut_prefix(entry):
    body = TOKEN * 20
    rows: object
    with DiskBackedText() as disk:
        disk.append_text(body)
        disk.finish()
        if entry == "scalar":
            rows = [row for row in analyze_value(body) if row.available]
        elif entry.startswith("elastic"):
            result = scan_value_tree(
                {"body": disk if entry.endswith("disk") else body}, source_kind="document", object_name="qa/one"
            )
            assert not result.truncated_reasons
            rows = result.detections
        elif entry == "stream":
            rows, complete = _scan_text_chunks((body[i : i + 3] for i in range(0, len(body), 3)), "$.body", 64, 0)
            assert complete
        else:
            rows, _, complete = _scan_portioned_value(disk if entry == "disk" else body, "$.body", 64)
            assert complete
        assert not rows


def test_full_low_candidate_survives_plain_txt_and_json_projection():
    import json

    from redposture_core.discovery_rendering import discovery_color_spans, format_discovery_finding_line
    from redposture_core.discovery_values import iter_json_chunks

    row = next(row for row in analyze_value(TOKEN) if row.available)
    payload = {"type": row.secret_type, "confidence": _confidence(row.score), "value": row.value}
    saved = "".join(iter_json_chunks(payload))
    assert json.loads(saved) == {"type": "high_entropy", "confidence": "low", "value": TOKEN}
    line = format_discovery_finding_line(
        "ELASTIC", "qa", 9200, finding_type=row.secret_type, severity="low", value=row.value, place="$.body"
    )
    assert TOKEN in line and "\x1b" not in saved + line
    content = line.split("[!] ", 1)[1]
    assert discovery_color_spans("[!]", content) == [(0, len(content), "orange")]
