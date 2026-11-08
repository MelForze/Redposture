"""Locked HTTP-boundary UI inputs and labels are independent of detector results."""

from __future__ import annotations

import json

import pytest

from redposture_core import web_panels
from redposture_core.modules.kafka import http_surfaces
from scripts.discovery_ui_accuracy import CORPUS, HTTP_SURFACES, SUPPORTED, UNSUPPORTED, compare, load, run_case


@pytest.mark.parametrize("case", load()["cases"], ids=lambda case: case["id"])
def test_locked_ui_reader_case_has_exact_value_type_location_and_coverage(case):
    result = run_case(case)
    score = compare(case, result)
    assert score["status_ok"], (case["id"], result)
    assert score["fn"] == score["fp"] == score["duplicates"] == 0, (case["id"], result, score)
    assert result["sources"], (case["id"], "source manifest missing at actual UI dispatch")
    for source in result["sources"]:
        assert {"id", "implemented", "requested", "read", "denied", "unsupported", "complete"} <= source.keys()
    if case["mode"] == "unsupported":
        assert all(source["read"] == 0 and not source["complete"] for source in result["sources"])
        assert any(source["unsupported"] and not source["implemented"] for source in result["sources"])
    serialized = json.dumps(result, ensure_ascii=False)
    assert "\x1b" not in serialized and "DiskBackedText(" not in serialized
    if case["mode"] == "denied":
        assert not result["early_output_lines"], "error response emitted a finding before status verification"


def test_ui_gate_covers_each_declared_companion_ui_and_kafka_http_surface():
    products = {case["product"] for case in load()["cases"]}
    assert products == set(web_panels.UI_PRODUCTS) | {"provectus", "kafbat"} | set(http_surfaces._PRODUCTS)
    assert products == set(SUPPORTED) | set(UNSUPPORTED) | set(HTTP_SURFACES)


def test_ui_holdout_rejects_changed_input_or_label(tmp_path):
    copied = tmp_path / "modified.json"
    corpus = json.loads(CORPUS.read_text())
    corpus["cases"][0]["expected"] = []
    copied.write_text(json.dumps(corpus))
    with pytest.raises(ValueError, match="UI holdout changed"):
        load(copied)


def test_ui_metric_rejects_wrong_type_value_place_and_duplicate():
    case = next(case for case in load()["cases"] if case["expected"])
    row = case["expected"][0]
    for field, value in [
        ("value", "prefix"),
        ("type", "high_entropy"),
        ("path", "/unrelated"),
        ("place", {"index": "other"}),
    ]:
        result = compare(case, {"status": "complete", "findings": [{**row, field: value}]})
        assert result["fn"] == result["fp"] == 1
    assert compare(case, {"status": "complete", "findings": [row, row]})["duplicates"] == 1


@pytest.mark.parametrize("product", HTTP_SURFACES)
def test_http_surface_cases_reach_kafka_reader_not_generic_panel_fallback(monkeypatch, product):
    from redposture_core.modules.kafka import ui

    original = ui.collect_ui
    observed = []

    def checked(ctx, record, state, options):
        observed.append(record.get("ui_vendor"))
        return original(ctx, record, state, options)

    monkeypatch.setattr(ui, "collect_ui", checked)
    result = run_case(next(case for case in load()["cases"] if case["product"] == product))
    assert observed == [product]
    assert result["status"] == "unsupported_by_ui" and result["requests"] == 0
